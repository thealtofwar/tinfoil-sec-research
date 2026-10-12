#!/usr/bin/env bash
# Finding 14 PoC: anonymous HTTP/2 CONNECT through the shipped cvmimage shim reaches
# every port that confidential-agent-sandbox publishes. Local only (loopback).
# Needs: Go toolchain (source /root/tinfoil-review/env.sh), pristine clones of cvmimage and
# confidential-agent-sandbox, and permission to bind 127.0.0.1:22 (run as root, or the
# port-22 stub fails to bind).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPOS="${REPOS:-/root/tinfoil-review/repos}"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/14}"
CVMIMAGE_COMMIT=58b08deab239257ca10e078bc78906f8cdf8dd62
SANDBOX_COMMIT=d78ec387fd23fbd46723727913c6c78920341deb
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh

rm -rf "$WORK"; mkdir -p "$WORK"
git clone -q "$REPOS/cvmimage" "$WORK/cvmimage"
git -C "$WORK/cvmimage" checkout -q "$CVMIMAGE_COMMIT"
git -C "$REPOS/confidential-agent-sandbox" show "$SANDBOX_COMMIT:tinfoil-config.yml" > "$WORK/tinfoil-config.yml"

cp "$HERE/poc_sandbox_tunnel_test.go" "$WORK/cvmimage/tinfoil/cmd/shim/"
cd "$WORK/cvmimage/tinfoil"
echo "cvmimage @ $(git rev-parse --short HEAD); sandbox config @ ${SANDBOX_COMMIT:0:7}"
SANDBOX_CONFIG="$WORK/tinfoil-config.yml" go test ./cmd/shim/ -run 'TestPoC_' -v -count=1 2>&1 \
  | grep -Ev '^[0-9]{4}/[0-9]{2}/[0-9]{2} ' # drop the shim's own log lines
