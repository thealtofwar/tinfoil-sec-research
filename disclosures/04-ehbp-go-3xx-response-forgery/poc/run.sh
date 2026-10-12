#!/usr/bin/env bash
# Finding 04 PoC: tinfoil-go / EHBP Go accept forged responses (nonce-less 3xx,
# and a 303 POST->GET downgrade). Loopback only. Sources come from the public
# Go module proxy: tinfoil-go v0.17.0-rc.1 (= HEAD ef79d8e), EHBP v0.3.2 (what
# tinfoil-go pins) and v0.4.0 (= HEAD 7ee9288), openai-go v3.42.0.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh
export GOFLAGS=-mod=mod
WORK="${WORK:-/root/tinfoil-review/work/disclosures/04}"
mkdir -p "$WORK"

fetch() { # fetch <module@version> <dest>
  local dir; dir="$(cd /tmp && go mod download -json "$1" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p')"
  rm -rf "$2"; cp -r "$dir" "$2"; chmod -R u+w "$2"
}

# Candidate fix in the EHBP Go client: a sealed exchange whose response has no
# nonce may pass through only as an error (status >= 400). 1xx/3xx without a
# nonce become errors, so http.Client never follows a redirect off a sealed
# request and openai-go never sees an unauthenticated "success".
apply_fix() {
  python3 - "$1/client/client.go" <<'EOF'
import sys
p = sys.argv[1]; s = open(p).read()
old = "\t\tif resp.Header.Get(protocol.ResponseNonceHeader) == \"\" &&\n\t\t\t(resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) {\n"
new = ("\t\tif resp.Header.Get(protocol.ResponseNonceHeader) == \"\" && resp.StatusCode < http.StatusBadRequest &&\n"
       "\t\t\t(resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) {\n"
       "\t\t\tresp.Body.Close()\n"
       "\t\t\treturn nil, fmt.Errorf(\"FIX: unauthenticated %d response to a sealed request\", resp.StatusCode)\n"
       "\t\t}\n" + old)
assert s.count(old) == 1, "fix anchor not found"
open(p, "w").write(s.replace(old, new))
EOF
}

run() { # run <label> <expect> [ehbp-replacement-dir]
  local D="$WORK/tinfoil-go-$1"
  fetch github.com/tinfoilsh/tinfoil-go@v0.17.0-rc.1 "$D"
  cp "$HERE/forgery_poc_test.go" "$D/"
  cp "$HERE/enclave_zz_poc_hook.go" "$D/enclave/zz_poc_hook.go"
  [ -n "${3:-}" ] && (cd "$D" && go mod edit -replace "github.com/tinfoilsh/encrypted-http-body-protocol=$3")
  echo "=== tinfoil-go v0.17.0-rc.1, $1, expect=$2"
  (cd "$D" && POC_EXPECT=$2 go test -run 'TestPoC_ResponseForgery' -v -count=1 . 2>&1 \
    | grep -E 'peer saw|VULNERABLE|STILL|NOT REPRODUCED|want |^(ok|FAIL|--- (PASS|FAIL): TestPoC_[A-Za-z0-9_]+ )')
}

run ehbp-v0.3.2 vulnerable
fetch github.com/tinfoilsh/encrypted-http-body-protocol@v0.4.0 "$WORK/ehbp-v0.4.0"
run ehbp-v0.4.0 vulnerable "$WORK/ehbp-v0.4.0"
fetch github.com/tinfoilsh/encrypted-http-body-protocol@v0.3.2 "$WORK/ehbp-v0.3.2-fixed"
apply_fix "$WORK/ehbp-v0.3.2-fixed"
run ehbp-v0.3.2-fixed fixed "$WORK/ehbp-v0.3.2-fixed"
