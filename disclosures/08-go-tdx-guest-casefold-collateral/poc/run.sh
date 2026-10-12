#!/bin/sh
# Finding 8 PoC: go-tdx-guest case-fold collateral differential. Local only.
# Builds happen in $WORK (default /root/tinfoil-review/work/disclosures/08).
# Needs Go >= 1.25 (tested with 1.27.1) and network access to proxy.golang.org for
# public modules on first run. Optional env: TINFOIL_GO_SRC (a tinfoil-go git clone;
# default the local pristine clone), GOTDX_MAIN=1 to also test go-tdx-guest main b0a2dd8.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-/root/tinfoil-review/work/disclosures/08}
TINFOIL_GO_SRC=${TINFOIL_GO_SRC:-/root/tinfoil-review/repos/tinfoil-go}
[ -f /root/tinfoil-review/env.sh ] && . /root/tinfoil-review/env.sh
mkdir -p "$WORK"
filt() { grep -v '^WARN\|^I[0-9]\|^=== RUN'; }

echo "== Stage 1: encoding/json v1 case-insensitive merge vs exact-key raw extraction (stdlib only)"
rm -rf "$WORK/1" && cp -r "$HERE/1-json-semantics" "$WORK/1"
(cd "$WORK/1" && go test -count=1 -v . 2>&1 | filt)

echo; echo "== Stage 2: google/go-tdx-guest v0.3.1 verify.TdxQuote, real Intel quote + real Intel-signed collateral, time.Now()"
rm -rf "$WORK/2" && cp -r "$HERE/2-go-tdx-guest" "$WORK/2"
(cd "$WORK/2" && go test -count=1 -v . 2>&1 | filt)
if [ "${GOTDX_MAIN:-1}" = 1 ]; then
  echo; echo "== Stage 2 (main): same test against go-tdx-guest main v0.3.2-0.20261003001058-b0a2dd8100a0"
  rm -rf "$WORK/2main" && cp -r "$HERE/2-go-tdx-guest" "$WORK/2main"
  (cd "$WORK/2main" && go mod edit -require=github.com/google/go-tdx-guest@v0.3.2-0.20261003001058-b0a2dd8100a0 \
     && go mod tidy >/dev/null 2>&1 && go test -tags gotdx_main -count=1 -v . 2>&1 | filt)
fi

echo; echo "== Stage 3: tinfoil-go ef79d8e (v0.17.0-rc.1), PRODUCTION build, verify/internal/quote/tdx.Authenticate"
if [ ! -d "$WORK/tinfoil-go/.git" ]; then git clone -q --no-hardlinks "$TINFOIL_GO_SRC" "$WORK/tinfoil-go"; fi
(cd "$WORK/tinfoil-go" && git checkout -q -f ef79d8e && git clean -qfd && git log -1 --format='tinfoil-go %h %s')
T="$WORK/tinfoil-go/verify/internal/quote/tdx"
mkdir -p "$T/testdata/poc-casefold" && cp "$HERE"/2-go-tdx-guest/testdata/* "$T/testdata/poc-casefold/"
cp "$HERE/3-tinfoil-go/poc_casefold_test.go" "$T/"
(cd "$WORK/tinfoil-go" && go test -count=1 -run 'TestPoC_' -v ./verify/internal/quote/tdx/ 2>&1 | filt)

echo; echo "== Stage 4: full Verifier.VerifyV3 via tinfoil-go's conformance adapter on a fake-QE v3 document"
echo "   (synthetic Intel root/PCK chain + fixed clock via the repo's tinfoil_conformance build tag)"
mkdir -p "$WORK/4"
(cd "$WORK/tinfoil-go" && go build -tags tinfoil_conformance -o "$WORK/4/tinfoil-conformance" ./cmd/tinfoil-conformance)
python3 -I "$HERE/4-verifyv3-fakeqe/derive_casefold.py" "$HERE/4-verifyv3-fakeqe/fakeqe-control.json" "$WORK/4/fakeqe-casefold-derived.json"
for f in "$HERE/4-verifyv3-fakeqe/fakeqe-control.json" "$WORK/4/fakeqe-casefold-derived.json"; do
  printf -- '-- %s: ' "$(basename "$f" .json)"
  python3 -I -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['input']))" "$f" \
    | "$WORK/4/tinfoil-conformance" verify-attestation-v3 2>/dev/null \
    | python3 -I -c "import json,sys; d=json.load(sys.stdin); o=d.get('outputs',{}); print(json.dumps({'accepted':d['accepted'],'rejection':d.get('rejection'),'tls_public_key_fp':o.get('tls_public_key_fp'),'hpke_public_key':o.get('hpke_public_key')}))" || true
done
