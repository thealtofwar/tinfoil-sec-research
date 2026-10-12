#!/usr/bin/env bash
# Finding 01 PoC: EHBP Go client replays the plaintext body on HTTP/2 retries.
# Loopback only. Sources come from the public Go module proxy (the exact bytes
# consumers build): EHBP v0.3.2 and v0.4.0, tinfoil-go v0.17.0-rc.1 (= ef79d8e).
# Usage: ./run.sh            (all steps)
#        WORK=/tmp/x ./run.sh (choose the scratch directory)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh
export GOFLAGS=-mod=mod
WORK="${WORK:-/root/tinfoil-review/work/disclosures/01}"
XNET=golang.org/x/net@v0.57.0   # test-only dependency (raw HTTP/2 framer)
mkdir -p "$WORK"; cd "$WORK"

fetch() { # fetch <module@version> <dest>: fresh writable copy from the module cache/proxy
  local dir; dir="$(cd /tmp && go mod download -json "$1" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p')"
  rm -rf "$2"; cp -r "$dir" "$2"; chmod -R u+w "$2"
}

# One-line fix, inserted after the body is replaced by the encrypting reader.
apply_fix() {
  python3 - "$1/identity/crypt.go" <<'EOF'
import sys
p = sys.argv[1]; s = open(p).read()
old = "\t\teof:    false,\n\t}\n\treq.Body = streamingReader\n\treq.ContentLength = -1\n\n\treturn &RequestContext{"
assert s.count(old) == 1, "fix anchor not found"
open(p, "w").write(s.replace(old, old.replace("req.ContentLength = -1\n", "req.ContentLength = -1\n\treq.GetBody = nil // FIX\n")))
EOF
}

for V in v0.3.2 v0.4.0; do
  for MODE in vulnerable fixed; do
    D="$WORK/ehbp-$V-$MODE"
    fetch "github.com/tinfoilsh/encrypted-http-body-protocol@$V" "$D"
    [ "$MODE" = fixed ] && apply_fix "$D"
    cp "$HERE/poc_h2_retry_test.go" "$D/client/"
    (cd "$D" && go get "$XNET" >/dev/null 2>&1)
    echo "=== EHBP $V, expect=$MODE"
    (cd "$D" && POC_EXPECT=$MODE go test ./client/ -run TestPoC_H2RetryPlaintext -v -count=1 2>&1 \
      | grep -E 'client:|intermediary observed|VULNERABLE|FIXED|NOT REPRODUCED|STILL|^(ok|FAIL|---)')
  done
done

# SDK level: tinfoil-go default EHBP stack + real openai-go v3.42.0.
for MODE in vulnerable fixed; do
  D="$WORK/tinfoil-go-$MODE"
  fetch github.com/tinfoilsh/tinfoil-go@v0.17.0-rc.1 "$D"
  cp "$HERE/sdk_poc_test.go" "$D/"
  (cd "$D" && go get "$XNET" >/dev/null 2>&1)
  if [ "$MODE" = fixed ]; then
    fetch github.com/tinfoilsh/encrypted-http-body-protocol@v0.3.2 "$WORK/ehbp-v0.3.2-for-sdk-fixed"
    apply_fix "$WORK/ehbp-v0.3.2-for-sdk-fixed"
    (cd "$D" && go mod edit -replace "github.com/tinfoilsh/encrypted-http-body-protocol=$WORK/ehbp-v0.3.2-for-sdk-fixed")
  fi
  echo "=== tinfoil-go v0.17.0-rc.1 (EHBP v0.3.2), expect=$MODE"
  (cd "$D" && POC_EXPECT=$MODE go test -run 'TestPoC_' -v -count=1 . 2>&1 \
    | grep -E 'SDK call|capture|VULNERABLE|FIXED|STILL|^(ok|FAIL|---)')
done
