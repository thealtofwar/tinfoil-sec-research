#!/bin/sh
# Reproduction commands for the go-verifier-quotes finding (TDX collateral case-fold differential).
# All local; Intel PCS collateral was fetched once (see intel-collateral/) and is replayed from disk.
set -e
. /root/tinfoil-review/env.sh
W=/root/tinfoil-review/work/go-verifier-quotes

echo "== PoC 1: go-tdx-guest v0.3.1 library level, real Intel quote + real Intel collateral, current clock"
cd $W/poc1-gotdx-casefold && go test -count=1 -v . 2>&1 | grep -v '^WARN\|^I[0-9]'

echo "== PoC 2: tinfoil-go HEAD (ef79d8e), PRODUCTION build (no tags), verify/internal/quote/tdx.Authenticate"
cd $W/tinfoil-go && go test -count=1 -run 'TestPoC_' -v ./verify/internal/quote/tdx/ 2>&1 | grep -v '^WARN\|^I[0-9]'

echo "== PoC 2b: tinfoil-go v0.16.1 (pinned by tinfoil-proxy), production build"
cd $W/poc2b-tinfoil-go-v0.16.1 && go test -count=1 -run 'TestPoC_v0161' -v ./verifier/internal/quote/tdx/ 2>&1 | grep -v '^WARN\|^I[0-9]'

echo "== PoC 3: full Verifier.VerifyV3 (conformance adapter = VerifyV3WithLayer) on a fake-QE document"
cd $W/tinfoil-go && go build -tags tinfoil_conformance -o bin/tinfoil-conformance ./cmd/tinfoil-conformance
cd $W/poc3-verifyv3-fakeqe
for f in fakeqe-control fakeqe-casefold-derived; do
  echo "-- $f"; python3 -I -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['input']))" $f.json | $W/tinfoil-go/bin/tinfoil-conformance verify-attestation-v3 2>/dev/null | head -4; echo "exit=$?"
done
