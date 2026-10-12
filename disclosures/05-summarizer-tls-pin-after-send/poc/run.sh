#!/usr/bin/env bash
# Finding 5 PoC. Local only: the attacker listens on 127.11.22.33:443 (needs root
# or CAP_NET_BIND_SERVICE) and an in-process resolver blocks all other names.
# Public Go modules are fetched from the Go module proxy if not cached.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/05}"
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY NO_PROXY
export GOFLAGS=-mod=mod

rm -rf "$WORK/summarizer" "$WORK/control"
mkdir -p "$WORK"

# 1) Unmodified confidential-summarizer v0.1.15 from the Go module proxy.
SRC=$(go mod download -json github.com/tinfoilsh/confidential-summarizer@v0.1.15 | sed -n 's/.*"Dir": "\(.*\)".*/\1/p')
cp -r "$SRC" "$WORK/summarizer"; chmod -R u+w "$WORK/summarizer"
cp "$HERE/shared/harness_test.go" "$HERE/vulnerable/poc_test.go" "$WORK/summarizer/"
( cd "$WORK/summarizer"
  echo "== summarizer v0.1.15 deps =="; go list -m github.com/tinfoilsh/tinfoil-go github.com/tinfoilsh/verifier github.com/openai/openai-go/v3
  echo "== vulnerable (HTTP/1.1) =="; go test -count=1 -v -run 'TestVulnerable|TestControl' .
  echo "== vulnerable (HTTP/2) ==";   POC_H2=1 go test -count=1 -v -run 'TestVulnerable' . )

# 2) Negative control: same attacker, pinning transport from current tinfoil-go.
mkdir -p "$WORK/control"
cp "$HERE/control/go.mod" "$HERE/control/control_test.go" "$HERE/shared/harness_test.go" "$WORK/control/"
( cd "$WORK/control"
  go mod tidy >/dev/null 2>&1
  echo "== control: tinfoil-go v0.16.1 =="; go test -count=1 -v . )
