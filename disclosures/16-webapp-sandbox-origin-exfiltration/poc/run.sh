#!/usr/bin/env bash
# Finding 16 PoC. Local only. Every request from Chromium is answered by Playwright
# route interception (fake chat.tinfoil.sh / webapp-sandbox.tinfoil.sh / attacker.example
# origins served from the local checkout), and Chromium runs with
# --host-resolver-rules="MAP * ~NOTFOUND" so no hostname can resolve. No socket is
# opened to any Tinfoil host. Builds in $WORK, outside this directory.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PRISTINE_SANDBOX="${PRISTINE_SANDBOX:-/root/tinfoil-review/repos/tinfoil-webapp-sandbox}"
PRISTINE_WEBAPP="${PRISTINE_WEBAPP:-/root/tinfoil-review/repos/tinfoil-webapp}"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/16}"
mkdir -p "$WORK"

# 1. tinfoil-webapp-sandbox @ 54ed549, deps from its lockfile (playwright 1.63.0), dist/ via its own build.mjs.
[ -d "$WORK/tinfoil-webapp-sandbox/.git" ] || git clone -q "$PRISTINE_SANDBOX" "$WORK/tinfoil-webapp-sandbox"
git -C "$WORK/tinfoil-webapp-sandbox" checkout -q 54ed549
[ -d "$WORK/tinfoil-webapp-sandbox/node_modules/playwright" ] || (cd "$WORK/tinfoil-webapp-sandbox" && npm ci --no-audit --no-fund)
(cd "$WORK/tinfoil-webapp-sandbox" && npx playwright install chromium-headless-shell >/dev/null && node build.mjs)

# 2. The chat-side CSP is read from tinfoil-webapp @ c061681 (vercel.json only, read-only).
git -C "$PRISTINE_WEBAPP" show c061681:vercel.json > "$WORK/webapp-vercel.json"

export SANDBOX_REPO="$WORK/tinfoil-webapp-sandbox" WEBAPP_VERCEL="$WORK/webapp-vercel.json" OUT="$WORK/out"

echo "##### Run 1: shipped headers (vercel.json @ 54ed549, host webapp-sandbox.tinfoil.sh)"
node "$HERE/sandbox-exfil.mjs" | tee "$WORK/out-shipped.log"

echo
echo "##### Run 2 (negative control / fix validation): proposed hardened CSP"
SANDBOX_CSP_OVERRIDE="default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src data: blob:; media-src data: blob:; font-src data:; base-uri 'none'; form-action 'none'; sandbox allow-scripts; frame-ancestors https://*.tinfoil.sh" \
  node "$HERE/sandbox-exfil.mjs" | tee "$WORK/out-hardened.log"
