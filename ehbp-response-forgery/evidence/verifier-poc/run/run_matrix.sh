#!/usr/bin/env bash
# Usage: run_matrix.sh <victim-test-binary> <test-name-regex> [topologies...]
# Runs every attacker mode against the victim binary. Loopback only.
set -u
W=/root/.claude/jobs/632f70ea/tmp/work/verify3-L3-ehbp-response-forgery-poc
VICTIM=$1
TESTRE=$2
shift 2
TOPOLOGIES=${*:-direct proxy}
MODES=${POC_MODES:-honest forge-200 forge-404 forge-300 forge-300-toolcall forge-302-noloc forge-305 redirect-301 redirect-302 redirect-303}
RUN=$(mktemp -d "$W/run/r.XXXX")

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY ALL_PROXY all_proxy

"$W/bin/enclave" -pubkey-out "$RUN/pub.hex" -addr-out "$RUN/enclave.addr" >"$RUN/enclave.log" 2>&1 &
EPID=$!
for _ in $(seq 50); do [ -s "$RUN/enclave.addr" ] && break; sleep 0.1; done
echo "enclave pid=$EPID addr=$(cat "$RUN/enclave.addr") pubkey=$(cat "$RUN/pub.hex")"

for topo in $TOPOLOGIES; do
  for mode in $MODES; do
    rm -f "$RUN/attacker.addr"
    "$W/bin/attacker" -mode "$mode" -upstream "$(cat "$RUN/enclave.addr")" \
      -cert "$W/pki/leaf.pem" -key "$W/pki/leaf-key.pem" -addr-out "$RUN/attacker.addr" >"$RUN/attacker.log" 2>&1 &
    APID=$!
    for _ in $(seq 50); do [ -s "$RUN/attacker.addr" ] && break; sleep 0.1; done
    echo "=================== topology=$topo mode=$mode"
    env -i PATH=/usr/bin:/bin HOME="$W/home" SSL_CERT_FILE="$W/pki/ca.pem" \
      HTTPS_PROXY="http://$(cat "$RUN/attacker.addr")" \
      POC_MODE="$mode" POC_TOPOLOGY="$topo" POC_PUBKEY_FILE="$RUN/pub.hex" \
      "$VICTIM" -test.run "$TESTRE" -test.v -test.count=1 2>&1 | grep -E "RESULT|VERDICT|client transport|^--- |^(ok|FAIL|PASS)|panic|Error" | sed 's/^/  victim   | /'
    kill $APID 2>/dev/null; wait $APID 2>/dev/null
    grep -E "\[attacker\]" "$RUN/attacker.log" | sed -E 's/^[0-9\/]+ [0-9:]+ //' | grep -v "CONNECT proxy on" | sed 's/^/  attacker | /'
  done
done
echo "=================== enclave log (only process with the HPKE private key)"
sed -E 's/^[0-9\/]+ [0-9:]+ //' "$RUN/enclave.log" | sed 's/^/  enclave  | /'
kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
echo "run dir: $RUN"
