#!/usr/bin/env bash
# Finding 12 PoC. Local only: loopback listeners, no network calls except Go module downloads.
# Usage: ./run.sh   (env: PRISTINE=<confidential-sync git clone>, WORK=<scratch dir>)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PRISTINE="${PRISTINE:-/root/tinfoil-review/repos/confidential-sync}"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/12}"
COMMIT=4acbf16e07c099bb5a030e7fc5e9b0b2db64c5b4
[ -f /root/tinfoil-review/env.sh ] && source /root/tinfoil-review/env.sh

rm -rf "$WORK/confidential-sync" && mkdir -p "$WORK/confidential-sync"
git -C "$PRISTINE" archive "$COMMIT" | tar -x -C "$WORK/confidential-sync"   # unmodified source at the pinned commit
cp "$HERE/poc_attachment_key_test.go" "$WORK/confidential-sync/internal/localstack/smoke/"
cd "$WORK/confidential-sync"
go version
go test -tags=smoke -run TestDisclosure12 -v -count=1 ./internal/localstack/smoke 2>&1 | tee "$WORK/output.txt"
