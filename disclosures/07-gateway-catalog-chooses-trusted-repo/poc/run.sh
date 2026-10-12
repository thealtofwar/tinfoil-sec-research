#!/usr/bin/env bash
# Finding 7 PoC: copies pristine tinfoil-go at ef79d8e (v0.17.0-rc.1), drops in
# three test files, runs them. Local only: no network except the Go module cache.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${TINFOIL_GO_SRC:-/root/tinfoil-review/repos/tinfoil-go}"   # local pristine clone
COMMIT="ef79d8ed92a4b5e669c71328caa2b4a9f7931d25"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/07}"
# The dev-box witness was logged 2026-10-07T18:03:26Z and is valid for 7 days
# (until 2026-10-14T18:03:26Z). Pin the appraisal clock inside that window so
# the PoC is reproducible after expiry. Set POC_NOW=$(date -u +%FT%TZ) to use
# the real clock (fails with "freshness witness is stale" after 2026-10-14).
export POC_NOW="${POC_NOW:-2026-10-11T12:00:00Z}"
export POC_DATA="$HERE/data"
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh

rm -rf "$WORK/tinfoil-go"; mkdir -p "$WORK"
git clone -q "$SRC" "$WORK/tinfoil-go"
git -C "$WORK/tinfoil-go" checkout -q "$COMMIT"
cp "$HERE/poc_a_devbox_provenance_test.go" "$WORK/tinfoil-go/verify/internal/provenance/"
cp "$HERE/poc_b_catalog_test.go"           "$WORK/tinfoil-go/"
cp "$HERE/poc_c_verifyv3_layers_test.go"   "$WORK/tinfoil-go/verify/"
cd "$WORK/tinfoil-go"
echo "tinfoil-go $(git rev-parse --short HEAD) ($(git describe --tags)); POC_NOW=$POC_NOW; $(go version)"
go test ./verify/internal/provenance/ -run TestPoC07_A -v -count=1
go test .                             -run TestPoC07_B -v -count=1
go test ./verify/                     -run TestPoC07_C -v -count=1
