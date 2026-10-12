#!/usr/bin/env bash
# Finding 10 PoC runner. Installs the published @tinfoilsh/verifier 1.2.2 twice from npm:
#   (a) with @freedomofpress/sigstore-browser 0.1.14 (what tinfoil-js's lockfile resolves) -> vulnerable
#   (b) with 0.1.15 (upstream fix)                                                        -> control
# then runs poc.mjs against the genuine production fixture from tinfoil-js.
# No network access other than registry.npmjs.org; verifyBundle() itself is offline.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/10}"
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh   # node >= 20
for v in 0.1.14 0.1.15; do
  d="$WORK/node-$v"; mkdir -p "$d"
  cat > "$d/package.json" <<JSON
{"name":"poc10-$v","private":true,"type":"module",
 "dependencies":{"@tinfoilsh/verifier":"1.2.2"},
 "overrides":{"@freedomofpress/sigstore-browser":"$v"}}
JSON
  (cd "$d" && npm install --ignore-scripts --no-audit --no-fund --silent)
  node "$HERE/poc.mjs" "$d" "$HERE/attestation-bundle.json"
  echo
done
