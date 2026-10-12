#!/usr/bin/env bash
# Router lower-severity item (local only): the /metrics poller sends METRICS_API_KEY over
# WebPKI-only TLS to a peer that is not the attested enclave.
#   ./run.sh         # shipped code @ 6494b7d: key delivered to the attacker; pinned proxy hop fails closed
#   FIX=1 ./run.sh   # with fix-pin-metrics.patch: nothing delivered; full manager test suite also run
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPOS="${REPOS:-/root/tinfoil-review/repos}"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/19}"
COMMIT=6494b7d
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh

rm -rf "$WORK/router" "$WORK/certs"; mkdir -p "$WORK/certs"
git clone -q --no-checkout "$REPOS/confidential-model-router" "$WORK/router"
git -C "$WORK/router" -c advice.detachedHead=false checkout -q "$COMMIT"
echo "confidential-model-router @ $(git -C "$WORK/router" rev-parse --short HEAD)"

# Stand-in "WebPKI" CA and an attacker leaf for the enclave hostname (ECDSA P-256).
C="$WORK/certs"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=PoC stand-in public CA" \
  -keyout "$C/ca-key.pem" -out "$C/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=gpu-1.inf6.example" \
  -keyout "$C/leaf-key.pem" -out "$C/leaf.csr" 2>/dev/null
printf 'subjectAltName=DNS:gpu-1.inf6.example\nextendedKeyUsage=serverAuth\n' > "$C/ext.cnf"
openssl x509 -req -in "$C/leaf.csr" -CA "$C/ca.pem" -CAkey "$C/ca-key.pem" -CAcreateserial -days 1 \
  -extfile "$C/ext.cnf" -out "$C/leaf.pem" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$C/leaf-key.pem" -out "$C/leaf-key.p8" && mv "$C/leaf-key.p8" "$C/leaf-key.pem"

cp "$HERE/poc_metrics_unpinned_test.go" "$HERE/poc_helper_unfixed.go" "$HERE/poc_helper_fixed.go" "$WORK/router/manager/"
cd "$WORK/router"
TAGS=poc
if [ "${FIX:-0}" = 1 ]; then git apply "$HERE/fix-pin-metrics.patch"; TAGS=poc,pocfix; echo "applied fix-pin-metrics.patch"; fi
SSL_CERT_FILE="$C/ca.pem" POC_CERT_DIR="$C" POC_FIX_APPLIED="${FIX:-0}" \
  go test -tags "$TAGS" -run TestPoC_MetricsPollLeaksAdminKeyToUnpinnedPeer ./manager/ -v -count=1 2>&1 \
  | grep -E 'poc_metrics_unpinned_test.go|level=error|^(--- |PASS|FAIL|ok)'
if [ "${FIX:-0}" = 1 ]; then echo "full manager suite with the fix:"; go test ./manager/ -count=1 2>&1 | tail -1; fi
