#!/bin/sh
# Reproduces: confidential-model-router sends METRICS_API_KEY over WebPKI-only
# TLS to enclave hostnames (manager/metrics.go scrape()), unlike every other
# enclave hop which is pinned to the attested key.
set -e
POC=$(cd "$(dirname "$0")" && pwd)
ROUTER=$POC/../confidential-model-router
. /root/tinfoil-review/env.sh
cd "$POC/gencerts" && go run . "$POC/certs" gpu-1.inf6.example
cp "$POC/poc_metrics_unpinned_test.go" "$ROUTER/manager/"
cd "$ROUTER" && SSL_CERT_FILE="$POC/certs/ca.pem" POC_CERT_DIR="$POC/certs" \
  go test -tags poc -run TestPoC_MetricsPollLeaksAdminKeyToUnpinnedPeer ./manager/ -v -count=1 2>&1 | tee "$POC/evidence/run.log"
