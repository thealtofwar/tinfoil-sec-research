#!/usr/bin/env bash
# Finding 18 PoC (local only): tinfoil-swift 0.8.2 + EHBP Swift 0.3.2 + openai-swift-fork 0.0.15
# return a nonce-less 300 (streaming) / 500 (non-streaming) body from the TLS peer as the
# model's completion. Runs on Linux with Swift 6.2.1; see README for the Linux-only shims.
#   ./run.sh          # shipped code: forgeries accepted, controls rejected
#   FIX=1 ./run.sh    # with fix-tinfoil-swift-0.8.2.patch: forgeries rejected
# Sources: git clones of the public repos at the exact tags the iOS app pins
# (tinfoil-ios cd5824e Package.resolved). By default they come from the review's local clones;
# set SRC to a directory holding clones of tinfoil-swift, encrypted-http-body-protocol and
# openai-swift-fork (github.com/tinfoilsh/<name>) to use others.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-/root/tinfoil-review/work/disclosures/18}"
SW=/root/tinfoil-review/work/ios-swift
TINFOIL_SWIFT="${SRC:+$SRC/tinfoil-swift}"; TINFOIL_SWIFT="${TINFOIL_SWIFT:-$SW/tinfoil-swift-0.8.2}"
EHBP="${SRC:+$SRC/encrypted-http-body-protocol}"; EHBP="${EHBP:-$SW/ehbp-0.3.2}"
OPENAI="${SRC:+$SRC/openai-swift-fork}"; OPENAI="${OPENAI:-$SW/openai-swift-fork}"
source "$SW/swiftenv.sh"   # Swift 6.2.1 toolchain + C++ headers for swift-crypto on this host

B="$WORK/build"; mkdir -p "$B"
fresh() { rm -rf "$B/$2"; git clone -q --no-checkout "$1" "$B/$2"; git -C "$B/$2" -c advice.detachedHead=false checkout -q "$3"; echo "$2 @ $3 = $(git -C "$B/$2" rev-parse --short HEAD)"; }
fresh "$TINFOIL_SWIFT" tinfoil-swift v0.8.2          # 4988b05 (iOS app pin)
fresh "$EHBP" ehbp-0.3.2 v0.3.2                      # 8528a8d (iOS app pin)
fresh "$OPENAI" openai-swift-fork v0.0.15            # c8f8383 (iOS app pin)

# Linux-only shims (no effect on response handling; see README).
git -C "$B/ehbp-0.3.2" apply "$HERE/linux-shims/ehbp-0.3.2-linux.patch"
P="$B/poc"; rm -rf "$P"; mkdir -p "$P/Sources" "$P/Tests/PoCTests"
cp -r "$B/tinfoil-swift/Sources/TinfoilAI" "$P/Sources/"
rm "$P/Sources/TinfoilAI/Verification.swift" "$P/Sources/TinfoilAI/VerificationDocument.swift"
(cd "$P" && git apply -p1 "$HERE/linux-shims/tinfoil-swift-0.8.2-linux.patch")
if [ "${FIX:-0}" = 1 ]; then (cd "$P" && git apply -p1 "$HERE/fix-tinfoil-swift-0.8.2.patch"); echo "applied fix-tinfoil-swift-0.8.2.patch"; fi
cp "$HERE/Package.swift" "$HERE/Package.resolved" "$P/"
cp "$HERE/ForgedResponseTests.swift" "$P/Tests/PoCTests/"
# Package.swift refers to ../openai-swift-fork and ../ehbp-0.3.2

cd "$P"
swift build --build-tests $SWIFT_BUILD_FLAGS -Xlinker -L"$SW/toolchain/shimlibs" 2>&1 | grep -v "no version information" | tail -1
POC_FIX_APPLIED="${FIX:-0}" swift test --skip-build $SWIFT_BUILD_FLAGS -Xlinker -L"$SW/toolchain/shimlibs" 2>&1 \
  | grep -v "no version information" | grep -E '^\[poc\]|Test Case .*(passed|failed)|error:|Executed .* tests' | sed -E "s/ \(0\.[0-9]+ seconds\)//"
