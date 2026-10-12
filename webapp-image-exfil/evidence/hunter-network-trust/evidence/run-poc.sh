#!/usr/bin/env bash
# Reproduces the model-controlled remote image exfiltration PoC end to end.
# 1) vitest: the real webapp renderer turns attacker image URLs into <img src=...>
#    (writes rendered HTML + production CSP into this directory)
# 2) Chromium: the rendered HTML, served under the production CSP, makes the
#    browser send the "leaked" data to the attacker origin via image fetches,
#    while fetch() to that origin is blocked by connect-src.
set -euo pipefail
source /root/tinfoil-review/env.sh
WORK=/root/tinfoil-review/work/webapp-network-trust
cd "$WORK/tinfoil-webapp"
npx vitest run tests/poc/model-controlled-remote-images.test.tsx 2>&1 | tee "$WORK/evidence/vitest-remote-images.log"
cd "$WORK/browser-poc"
node img-exfil.mjs 2>&1 | tee "$WORK/evidence/chromium-img-exfil.log" | tail -8
