#!/usr/bin/env bash
# Finding 6 PoC. Local only: no Tinfoil host is contacted (npm registry downloads only).
# Builds in $WORK (default /root/tinfoil-review/work/disclosures/06), outside this directory.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PRISTINE="${PRISTINE:-/root/tinfoil-review/repos/tinfoil-webapp}"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/06}"
COMMIT=c061681
mkdir -p "$WORK"

# 1. Checkout of tinfoil-webapp at the pinned commit, deps from the lockfile.
if [ ! -d "$WORK/tinfoil-webapp/.git" ]; then
  git clone -q "$PRISTINE" "$WORK/tinfoil-webapp"
fi
git -C "$WORK/tinfoil-webapp" checkout -q "$COMMIT"
git -C "$WORK/tinfoil-webapp" status --porcelain --untracked-files=no | grep -q . && { echo "work copy modified"; exit 1; }
[ -d "$WORK/tinfoil-webapp/node_modules" ] || (cd "$WORK/tinfoil-webapp" && npm ci --ignore-scripts --no-audit --no-fund)

# 2. Playwright (Chromium from the local Playwright cache; installs it if missing).
PW="$WORK/pw"
if [ ! -d "$PW/node_modules/playwright" ]; then
  mkdir -p "$PW" && (cd "$PW" && npm init -y >/dev/null && npm i --no-audit --no-fund playwright@1.63.0)
  (cd "$PW" && npx playwright install chromium-headless-shell)
fi

# 3. Self-signed loopback certificate for the app and attacker servers.
[ -f "$WORK/tls/cert.pem" ] || { mkdir -p "$WORK/tls"; openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj /CN=127.0.0.1 -keyout "$WORK/tls/key.pem" -out "$WORK/tls/cert.pem" 2>/dev/null; }

# 4. Part 1: render through the shipped markdown pipeline (only file added: tests/poc/image-exfil.test.tsx).
mkdir -p "$WORK/tinfoil-webapp/tests/poc"
cp "$HERE/image-exfil.test.tsx" "$WORK/tinfoil-webapp/tests/poc/"
(cd "$WORK/tinfoil-webapp" && POC_OUT="$WORK/out" POC_ATTACKER_ORIGIN=https://127.0.0.1:48443 \
  npx vitest run tests/poc/image-exfil.test.tsx --reporter=verbose 2>&1 | grep -vE '^ *(RUN|Start at|Duration)' )

# 5. Part 2: Chromium under the exact vercel.json CSP, loopback attacker; then the fixed-CSP control.
PLAYWRIGHT_DIR="$PW" node "$HERE/browser.mjs" "$WORK/out/rendered-message.html" \
  "$WORK/tinfoil-webapp/vercel.json" "$WORK/tls"
