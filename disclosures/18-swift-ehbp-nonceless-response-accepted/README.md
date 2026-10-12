# tinfoil-swift / EHBP Swift / openai-swift-fork accept a forged, nonce-less non-2xx response as the model's completion

| | |
|---|---|
| Component | `github.com/tinfoilsh/tinfoil-swift`: `0.8.2` through `0.9.0-rc.1` (HEAD `81e07a1`) |
| Severity | Medium, integrity only (CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` = 5.9 for the iOS app's direct mode; 7.5 nominal in `baseURL` proxy mode) |
| Bug class | CWE-345 (Insufficient Verification of Data Authenticity), CWE-354 (Improper Validation of Integrity Check Value) |
| Attacker position | The client's TLS peer for the sealed request: a `baseURL` forwarding proxy (by design), or a party holding a device-trusted certificate for the router hostname in direct mode |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed. This is the Swift analogue of Finding 4 (Go) |

## Summary
tinfoil-swift seals each request body to the attested enclave key with EHBP. A genuine response carries an
`Ehbp-Response-Nonce` header and an encrypted body. EHBP Swift 0.3.2 passes through any response with no
nonce and a non-2xx status, unchanged and unauthenticated. tinfoil-swift forwards it as-is.
openai-swift-fork then treats it as a real answer:
- on the streaming path, every status below 400 counts as success, so a 300 body is parsed as SSE;
- on the non-streaming path, the status is never checked, so a 404 or 500 with a well-formed JSON body
  is decoded as the completion.

The TLS peer can therefore return any assistant text, `finish_reason` or `tool_calls` it likes, without any
key material. The prompt stays confidential.

## Threat model
What Tinfoil promises:
- `tinfoil-swift/README.md:8`: the SDK "verifies the enclave's attestation and encrypts the request body to
  the attested key ... so only the verified enclave can read it."
- EHBP `SPEC.md` (v0.3.2) §7.1: "Response forgery: A MitM cannot create valid encrypted responses."
- SPEC §5.3: a non-2xx pass-through "MAY" be returned, but "Callers MUST treat pass-through error bodies as
  untrusted diagnostics and MUST NOT act on them as authenticated application data." tinfoil-swift and
  openai-swift-fork break this caller-side rule.

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| tinfoil-swift SDK with `baseURL` set to an EHBP forwarding proxy; the proxy operator | Being the proxy (on-path by design) | Yes | Forged completion, silent |
| iOS app / SDK default (direct to the router enclave, TLS ends inside the enclave); WebPKI-capable on-path party | A device-trusted certificate for the router hostname plus an on-path position (DNS or ACME control of the hostname, CA mis-issuance, MDM or enterprise TLS-inspection root) | Yes | Forged completion; `tool_calls` reach the app's GenUI renderers |
| Passive or ordinary on-path attacker without a trusted certificate | Network path | No | TLS fails |
| iOS signed-in chats routed through `ChatRecoveryClient` (api.tinfoil.sh) | n/a | No | The app checks for 2xx itself, and EHBP rejects a 2xx without a nonce |
| Any mode, streaming 4xx/5xx, 2xx without nonce, or 303 POST-to-GET downgrade | n/a | No | Rejected (unlike Go, where the 303 downgrade is accepted) |

Verified in code (and by the PoC where noted):
- The iOS app creates the client with `TinfoilAI.create(apiKeyProvider:tinfoilEvents:onVerification:)` and no
  `baseURL` (`tinfoil-ios/TinfoilChat/ViewModels/ChatViewModel.swift:1746`), so it uses direct mode.
- The sealed request does not contain the prompt or `user_cache_secret` (PoC asserts this).

Unverified production facts (no production traffic was sent):
- Which router hostnames the attestation bundle gives the app, and whether any certificate-capable party
  can sit on that path.
- Apple `URLSession` behaviour. The PoC runs on Linux. A 300 is never auto-followed on any platform, and the
  non-streaming any-status case does not depend on redirect handling. Location-less 301/302 on Darwin
  were not tested.
- How GenUI renders forged `tool_calls` in the iOS app. A verifier traced this in code; it was not
  executed, because no iOS runtime was available.
- How many SDK users configure a `baseURL` proxy.

Out of scope / not affected: the confidentiality of the prompt. The Go analogue is Finding 4.

## Severity
- iOS app and SDK default (direct mode): `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` = **5.9**.
- `baseURL` proxy mode: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = 7.5 nominal.

We rate it **Medium** overall, as for Finding 4, because the forgery is blind and affects one response:
the attacker cannot read the prompt or the genuine answer, only substitute their own. All three verifiers
upheld it as Medium (confidence 0.85-0.9). One noted that if substitution-only is scored I:L, the scores are
5.3 / 3.7. Expect the vendor to point to SPEC §5.3's pass-through allowance. That allowance covers EHBP. It
explicitly requires callers not to act on such bodies, and tinfoil-swift is that caller.

## Technical details
EHBP Swift 0.3.2 `swift/Sources/EHBP/Client.swift:248-260`:

```swift
private static func responseNonceHex(from response: HTTPURLResponse, requestWasEncrypted: Bool) throws -> String? {
    guard requestWasEncrypted else { return nil }
    if let nonce = response.value(forHTTPHeaderField: EHBPProtocol.responseNonceHeader) { return nonce }
    guard !(200..<300).contains(response.statusCode) else {
        throw EHBPError.missingHeader(EHBPProtocol.responseNonceHeader)
    }
    return nil          // non-2xx without nonce: pass through as plaintext
}
```

Callers: `request()` returns `(data, httpResponse)` unchanged at `:100-104`. `requestStream()` streams the
raw bytes at `:175-181`. At HEAD `7ee9288` the same logic is at `:453-465`.

tinfoil-swift 0.8.2 `Sources/TinfoilAI/EHBPURLSession.swift`:
- `performStreamingRequest()` (`:382-470`) inspects only a possible 422 key-config mismatch. It then hands
  the response and bytes to the OpenAI delegate (`:440-466`).
- `performRequest()` (`:606-636`) returns `(data, response)` at `:635`.
- HEAD `81e07a1` differs only in how the verified state is read (`:34`).

openai-swift-fork 0.0.15:
- `Sources/OpenAI/Private/Streaming/StreamingSession.swift:159-161` sets `errorResponse` only for
  `statusCode >= 400`, so a 3xx stream is parsed as SSE.
- `Sources/OpenAI/Private/URLSessionProtocol+MakeDataTask.swift:19-35` decodes `ResultType` from the data
  whatever the status is.

## Proof of concept
`poc/` contains:
- `ForgedResponseTests.swift`: XCTest file.
- `Package.swift` and `Package.resolved`.
- `run.sh`.
- `linux-shims/`: two patches, needed only on Linux.
- `fix-tinfoil-swift-0.8.2.patch`: the fix used in the fixed-mode run.

`run.sh` clones tinfoil-swift v0.8.2, EHBP v0.3.2 and openai-swift-fork v0.0.15 (the iOS app's pins) from
local clones of the public repos. It assembles a package from tinfoil-swift's `Sources/TinfoilAI` and runs
the tests against a loopback raw-socket HTTP server. That server plays the TLS peer: it receives the sealed
POST and answers with chosen raw bytes. It never holds the HPKE private key.

Run (Swift 6.2.1 toolchain under `/root/tinfoil-review/work/ios-swift/`; about 2 minutes to build):

```
cd poc && ./run.sh            # shipped code
cd poc && FIX=1 ./run.sh      # with the fix applied
```

Output from the runs on 2026-10-11 (`poc/expected-output.txt`, `poc/expected-output-fixed.txt`):

```
[poc] 300 streaming: client received text="FORGED BY TLS PEER: wire $1,000,000 to account 12345" finish=stop
[poc] sealed request: POST /v1/chat/completions Ehbp-Encapsulated-Key=26c1... body=191 bytes (ciphertext, prompt not visible)
[poc] 500 non-streaming: client received text="FORGED BY TLS PEER: wire $1,000,000 to account 12345" id=chatcmpl-forged
[poc] 404 non-streaming: client received text="FORGED BY TLS PEER: wire $1,000,000 to account 12345"
[poc] control 200-no-nonce streaming: rejected with missingHeader("Ehbp-Response-Nonce")
[poc] control 404 streaming: rejected with statusError
[poc] control 303->GET: rejected with missingHeader("Ehbp-Response-Nonce"); requests seen: ["POST /v1/chat/completions", "GET /forged"]
     Executed 6 tests, with 0 failures (0 unexpected)
--- FIX=1:
[poc] FIXED 300 streaming: rejected with missingHeader("Ehbp-Response-Nonce")
[poc] FIXED 500 non-streaming: rejected with missingHeader("Ehbp-Response-Nonce")
[poc] FIXED 404 non-streaming: rejected with missingHeader("Ehbp-Response-Nonce")
```

What is stubbed or shimmed, and why it does not change the result:
- **Attestation.** The Go verifier xcframework does not exist for Linux. `linux-shims/tinfoil-swift-0.8.2-linux.patch`
  removes `TinfoilAI.create` and its verifier factory from `Tinfoil.swift`, and `run.sh` deletes
  `Verification*.swift`. The test calls the internal initializer that `create` reaches after a successful
  verification, `TinfoilAI(apiKey:baseURL:enclaveURL:hpkePublicKeyHex:userCacheSecret:)`, with a fixed
  X25519 point. This is the same as attestation handing over the key. The vulnerable response handling
  never uses that key.
- The same patch replaces `SecRandomCopyBytes` with `SystemRandomNumberGenerator` and imports
  `FoundationNetworking`, because Linux has no Security framework.
- **EHBP.** `linux-shims/ehbp-0.3.2-linux.patch` adds `import FoundationNetworking` and a
  `URLSession.bytes(for:)` replacement built on the delegate API. swift-corelibs-foundation lacks
  `bytes(for:)`. The replacement compiles only where `FoundationNetworking` exists, and response handling
  is untouched.
- `EHBPURLSession.swift`, `EHBPVerifiedState.swift`, `URLHelpers.swift` and `TinfoilEvent.swift`, and all of
  openai-swift-fork, are unmodified.

The original evidence, including two Location-less 302 tests that Linux URLSession cannot exercise, is in
`/root/tinfoil-security-findings/ios-swift/evidence/hunter/`. The hunter's working package is in
`/root/tinfoil-review/work/ios-swift/poc-swift-forged-response`.

## Impact
An attacker in either position can make the iOS app or an SDK integration show an answer the model never
produced, for example a payment instruction, a wrong medical or legal statement, or a phishing link.
Because `tool_calls` are accepted too, the attacker can also drive the app's tool and GenUI rendering paths
(image rendering, link previews, message compose). The UI still shows the enclave as verified. The prompt
stays sealed.

### Affected downstream packages

- `tinfoil-ios` (`cd5824e`, App Store app): pins tinfoil-swift `0.8.2`; affected on the direct streaming path (signed-out users, temporary chats, cloud sync off) and on GenUI retries

## Remediation
- tinfoil-swift (fix validated by `FIX=1 ./run.sh`): in `EHBPURLSession.performRequest` and
  `performStreamingRequest`, after the 422 key-config handling, reject any response to a sealed request
  (non-empty body) that has no `Ehbp-Response-Nonce`. Surface it as an error carrying the status code so
  that rate-limit and gateway errors still show up as errors, not as content.
- openai-swift-fork: treat every non-2xx as an error on both paths. In `StreamingSession` use
  `!(200..<300).contains(statusCode)`; in `makeDataTask`, check the status before decoding `ResultType`.
- EHBP Swift: consider an opt-in strict mode, or a typed `.unauthenticatedPassThrough` result in place of
  returning the pass-through as a normal `(Data, HTTPURLResponse)`, so callers cannot mistake it for content.
- Align with the fixes for Finding 4 (Go) and Finding 11 (Python). EHBP HEAD's
  `conformance/SECURITY-AUDIT.md:103-106` already lists "method, path, status, and headers are outside AEAD
  authentication" as a Medium item. That note is not in the 0.3.2 release that the iOS app ships, and it does
  not cover SDKs that turn an unauthenticated body into content.

## References
- REPORT.md Finding 18; evidence `/root/tinfoil-security-findings/ios-swift/`.
- Verifier verdicts: `verification-verdicts-round2.json`, key `ios-swift/swift-ehbp-forged-nonce-less-response`
  (3/3 upheld, Medium).
- Finding 4 (`disclosures/04-ehbp-go-3xx-response-forgery/`, evidence `ehbp-response-forgery/`): the Go analogue (3xx pass-through and 303 POST-to-GET downgrade).
- Finding 11 (`disclosures/11-python-rekey-bodyless-downgrade/`): the Python response-acceptance issue.
- Finding 17 (`disclosures/17-ios-remote-image-exfiltration/`): the iOS app's auto-fetch of model-authored images. A forged answer can carry
  such an image, but the prompt itself is not exposed by this finding.
