# EHBP Go client resends request bodies in plaintext on HTTP/2 retries

| | |
|---|---|
| Component | `github.com/tinfoilsh/encrypted-http-body-protocol` (Go client): `v0.3.2` through `v0.4.0` (latest); same root cause back to `v0.1.7` |
| Severity | High (CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5 for the gateway / proxy topology) |
| Bug class | CWE-319 (cleartext transmission of sensitive information), CWE-311; root cause is a stale `http.Request.GetBody` after the body is replaced (CWE-672-like reuse of a superseded resource) |
| Attacker position | The client's TLS peer: Tinfoil's gateway or a configured proxy (by design), or in direct mode an on-path party holding a WebPKI certificate for the enclave hostname |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary

The EHBP Go client encrypts the request body but leaves `req.GetBody` pointing at the caller's
plaintext body. Go's HTTP/2 client replays a request on a new stream when the peer sends
`RST_STREAM(REFUSED_STREAM)` or `GOAWAY`, and it rebuilds the body by calling `GetBody()`. The replay
therefore carries the plaintext body, still labelled with the `Ehbp-Encapsulated-Key` header. The party
that terminates TLS can trigger this with one frame, read the plaintext, forward the original
ciphertext to the real enclave and relay the sealed reply. The client decrypts a genuine answer and
reports success. `tinfoil-go` uses this transport by default, and several shipped Tinfoil components
send EHBP through Tinfoil's own unattested gateway, which is exactly the party EHBP is meant to keep
out.

## Threat model

What is promised:

- `tinfoil-go/enclave_transport.go:21-24`: "TransportEHBP encrypts request bodies end-to-end with HPKE
  via the Encrypted HTTP Body Protocol. Only the verified enclave can decrypt them, so it works through
  proxies. This is the default."
- `tinfoil-proxy/README.md:3`: bodies are encrypted with EHBP "so neither the gateway nor any other
  intermediary can read them."
- `encrypted-http-body-protocol/README.md`: "Proxies can inspect and route upon request metadata without
  seeing the body."
- `tinfoil-go/AGENTS.md:11`: in EHBP mode the enclave certificate "is not expected to be chain-trusted
  or to prove the attested TLS public key". EHBP is the only body protection in that mode.

Who can exploit it:

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| `tinfoil.NewGateway(...)`, `tinfoil-proxy`, `confidential-openai-adapter`, Tinfoil Chat harness model turns (`WithBaseURL(gateway)`) | Be, or compromise, Tinfoil's gateway (`inference-gateway.tinfoil.sh`). It terminates TLS by design and clients do not attest it. | Yes, no extra capability | Every request body: prompts, history, files, `cache_salt` / `user_cache_secret` |
| `WithBaseURL(proxy)` (any SDK user) | Operate the configured proxy | Yes, by design | Same |
| Any EHBP mode behind enterprise TLS inspection | A root the client trusts | Yes | Same |
| Default `NewClient()` direct to the router enclave | A WebPKI certificate for the router hostname plus an on-path position (DNS owner, a host passing ACME HTTP-01/TLS-ALPN-01 for the enclave IP, a compromised DNS API token, CA mis-issuance) | Yes, high complexity | Same; CT records the certificate afterwards |
| Passive network attacker / active attacker without a trusted certificate | - | No | TLS prevents frame injection |
| `TransportTLS` (pinned) mode | - | No | The pin is checked in `VerifyConnection` during the handshake, so a non-enclave peer never receives a request |

Preconditions verified in code:

- tinfoil-go defaults to EHBP (`options.go:9`, `defaultTransportMode = TransportEHBP`) and builds the EHBP
  transport on `http.DefaultTransport` (`enclave_transport.go:137-148`), which has
  `ForceAttemptHTTP2: true` and offers `h2` in ALPN, so the TLS peer chooses HTTP/2.
- Every common caller sets a plaintext `GetBody`: openai-go for its JSON body, `http.NewRequest` for
  `bytes`/`strings` readers, `tinfoil-go/user_cache_secret.go:269` (body with `user_cache_secret`
  injected) and `tinfoil-go/seal_transport.go:248-253` (`setGatewayBody`, body with `cache_salt`).
- The harness defaults to the gateway (`confidential-tinfoil-harness/main.go:73`), builds a default EHBP
  client with `WithBaseURL(gateway)` (`main.go:131-142`) and sends each turn with
  `http.NewRequestWithContext(..., bytes.NewReader(payload))` (`agent.go:291`).

Unverified production facts (no production traffic was sent):

- Whether `inference-gateway.tinfoil.sh` currently negotiates HTTP/2. A malicious or compromised gateway
  chooses ALPN itself, so this does not change the conclusion for an adversarial gateway; it matters only
  for the accidental-leak case below.
- Whether honest gateway behaviour (graceful `GOAWAY` on deploy/drain, `REFUSED_STREAM` under stream
  limits) already sends plaintext to the gateway today. Locally, an unmodified Go `net/http` HTTP/2 server
  with `MaxConcurrentStreams` 1 or 32 received 1140/1280 and 375/1280 plaintext bodies during bursts
  (evidence directory, `evidence/variants`).

Not affected (checked): the JS, Python, Rust and Swift EHBP clients and SDKs (Python tested against a
refusing HTTP/2 peer: no replay; others by code review); `TransportTLS`; the model router's upstream
calls (TLS-pinned); HTTP/1.1 in practice (openai-go sends no `Idempotency-Key`, so POSTs are not
replayed). On Go 1.27.1 a peer `RST_STREAM(PROTOCOL_ERROR)` is not a retry trigger; on Go <= 1.26 it is.

## Severity

- Gateway / proxy topologies (harness, `tinfoil-proxy`, adapter, `NewGateway`, `WithBaseURL`):
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5**. The attacker is the gateway or proxy operator (or
  whoever compromises it), which needs nothing beyond its normal position.
- Default direct-to-enclave mode: `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = **5.9**. A trusted
  certificate for the enclave hostname plus an on-path position is required.

All five independent reviewers upheld the finding as High (confidence 0.93-0.97). They agreed on the
attacker-position split above. Two of them corrected the original hunter text: peer `PROTOCOL_ERROR` is
not retried on Go 1.27.1. The rating is High because the primary affected products (Tinfoil Chat
harness, `tinfoil-proxy`, the adapter) route through Tinfoil's gateway, which is precisely the party
EHBP is documented to exclude.

## Technical details

`encrypted-http-body-protocol/client/client.go` (HEAD `7ee9288`; `v0.3.2` lines 240/253/270):

```go
323	newReq := req.Clone(req.Context())                       // Clone copies req.GetBody (plaintext)
343	reqCtx, err := t.serverIdentity.EncryptRequestWithContext(newReq)
363	resp, err := t.roundTripper().RoundTrip(newReq)          // http.DefaultTransport (ForceAttemptHTTP2)
```

`encrypted-http-body-protocol/identity/crypt.go` (HEAD; `v0.3.2` lines 394-424):

```go
435	func (i *Identity) EncryptRequestWithContext(req *http.Request) (*RequestContext, error) {
	...
458		req.Body = streamingReader   // ciphertext, used for the first attempt only
459		req.ContentLength = -1
		// req.GetBody is never cleared or replaced
```

Go 1.27.1 `src/net/http/internal/http2/transport.go`:

```go
507	func shouldRetryRequest(req *ClientRequest, err error) (*ClientRequest, error) {
518		if req.GetBody != nil {
519			body, err := req.GetBody()   // the caller's plaintext body
	...
537	func canRetryError(err error) bool {
538		if err == errClientConnUnusable || err == errClientConnGotGoAway { return true }
542			return se.Code == ErrCodeRefusedStream   // inside: if se, ok := err.(StreamError)
```

The tinfoil-go wrappers set `GetBody` on purpose (`user_cache_secret.go:267-271`: "Retries below this
layer (EHBP key rotation, redirects) must replay the injected body"). They assume every replay goes back
through the EHBP `RoundTrip`. The net/http/HTTP2 retry runs below EHBP, so it does not.

## Proof of concept

Files in `poc/`:

- `poc_h2_retry_test.go`: one test file dropped into `client/` of an unmodified EHBP checkout. A loopback
  TLS "intermediary" that speaks raw HTTP/2 frames and never holds the HPKE private key. Two subtests:
  `REFUSED_STREAM` and `GOAWAY_NO_ERROR`. The intermediary refuses the first (sealed) stream, records the
  retried body, forwards the original ciphertext to a genuine EHBP enclave (`identity.Middleware()`) and
  relays the sealed reply.
- `sdk_poc_test.go`: optional SDK-level variant, an in-package test for tinfoil-go `v0.17.0-rc.1`. It
  builds the default EHBP stack (`ehbpHTTPClient` + `recoveryTransport` + `boundHTTPClient`, the same
  composition as `secureHTTPClient`) and the `NewGateway` seal transport, then drives them with the real
  openai-go `v3.42.0` client.
- `run.sh`: fetches EHBP `v0.3.2` and `v0.4.0` and tinfoil-go `v0.17.0-rc.1` from the Go module proxy
  (the bytes consumers build; `v0.4.0` origin hash `7ee9288`, `v0.17.0-rc.1` origin hash `ef79d8e`),
  copies each to a scratch directory (`$WORK`, default `/root/tinfoil-review/work/disclosures/01`),
  adds `golang.org/x/net v0.57.0` for the test's frame writer, and runs each test twice: unmodified
  (`POC_EXPECT=vulnerable`) and with the one-line fix applied (`POC_EXPECT=fixed`).

Prerequisites: Go 1.27.1 (tested), Python 3 (only to apply the fix), network access to
proxy.golang.org or a warm module cache. Run: `cd poc && ./run.sh`.

Key output (full run in `poc/expected-output.txt`):

```
=== EHBP v0.3.2, expect=vulnerable
    client: status=200 proto=HTTP/2.0 decrypted answer="genuine enclave answer"
    intermediary observed body #0 (120 bytes): "\x00\x00\x00t\xd0\x0f..."   (ciphertext, refused)
    intermediary observed body #1 (100 bytes): "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"CANARY-PROMPT acquisition target is ACME Corp\"}]}"
    VULNERABLE [REFUSED_STREAM]: intermediary read the plaintext body; client got the genuine decrypted answer
    VULNERABLE [GOAWAY_NO_ERROR]: intermediary read the plaintext body; client got the genuine decrypted answer
=== EHBP v0.4.0, expect=vulnerable
    VULNERABLE [REFUSED_STREAM]: ...      VULNERABLE [GOAWAY_NO_ERROR]: ...
=== tinfoil-go v0.17.0-rc.1 (EHBP v0.3.2), expect=vulnerable
    SDK call succeeded; assistant said "hello from the enclave"
    proxy capture 1: POST /v1/chat/completions ... body="{\"messages\":[{\"content\":\"CANARY-SDK-PROMPT patient record 0000\",\"role\":\"user\"}],\"model\":\"m\",\"user_cache_secret\":\"CANARY-user-cache-secret-5f3a\"}"
    gateway capture 1: POST /v1/chat/completions x-tinfoil-seal=replica.example ... body="{\"cache_salt\":\"DJY6...\",\"messages\":[{\"content\":\"CANARY-GATEWAY-PROMPT merger target\",\"role\":\"user\"}],\"model\":\"m\"}"
```

Negative control (same tests, `req.GetBody = nil` added after `req.ContentLength = -1` in
`EncryptRequestWithContext`):

```
=== EHBP v0.3.2, expect=fixed
    client: error: ... http2: Transport: cannot retry err [stream error: stream ID 1; REFUSED_STREAM; received from peer] after Request.Body was written; define Request.GetBody to avoid this error
    FIXED [REFUSED_STREAM]: no plaintext reached the intermediary
    FIXED [GOAWAY_NO_ERROR]: no plaintext reached the intermediary
=== tinfoil-go v0.17.0-rc.1 (EHBP v0.3.2), expect=fixed
    FIXED: no plaintext reached the proxy
    FIXED: no plaintext reached the gateway
```

In the SDK fixed run, openai-go's own retry re-enters EHBP and sends a freshly sealed body (capture 1 is
ciphertext). The call then fails only because this PoC proxy always forwards the first ciphertext; a real
proxy would forward the new one.

What is stubbed: attestation. The EHBP test hands the client the enclave's HPKE public key; the SDK test
replaces the verifier with a function that returns the HPKE key a successful verification yields. The
attack never touches attestation (a real attacker forwards it unchanged). The client trusts the
intermediary's self-signed certificate; this stands in for the gateway's or proxy's own certificate (or a
WebPKI certificate in direct mode). Nothing in the request or retry path is modified.

Full original evidence (end-to-end `tinfoil-proxy` and harness tests, Go 1.26 `PROTOCOL_ERROR`, EHBP
`v0.2.5` 307 redirect variant, streaming and multipart audio, benign-server burst test, HTTP/1.1
control): `/root/tinfoil-security-findings/ehbp-h2-retry-plaintext/`.

## Impact

A Tinfoil gateway operator, an attacker who compromises the gateway, or any proxy a user configures can
read request bodies that EHBP promises only the attested enclave can read. For Tinfoil Chat this is every
model turn the harness sends through the gateway: system prompt, conversation history, project documents,
memory and attachments. For `tinfoil-proxy` and the OpenAI adapter it is every API request, including
`cache_salt`. The user sees a normal, successful, genuinely decrypted response, and nothing is logged.
Responses stay encrypted, but earlier answers reappear in later requests as history.

### Affected downstream packages

- `github.com/tinfoilsh/tinfoil-go` `v0.17.0-rc.1`, `v0.16.1` and earlier releases using `NewTransportWithIdentity` (default EHBP transport)
- `tinfoil-proxy` (CLI, desktop app, container; tinfoil-go `v0.16.1`)
- `confidential-tinfoil-harness`, the Tinfoil Chat backend (tinfoil-go `v0.15.4-0.20260828072713-251feb041ce8`)
- `confidential-openai-adapter` (tinfoil-go `v0.15.8-0.20260924012310-ff60af7e9ea6`)
- `confidential-safeguards`, `confidential-websearch`, `confidential-doc-upload` (default EHBP, inspection only)
- `confidential-sync` and `demo-safeguard` pin EHBP <= `v0.2.5`, which has the older 307/308 redirect variant of the same root cause

## Remediation

1. In `identity/crypt.go` `EncryptRequestWithContext`, after replacing the body:
   ```go
   req.Body = streamingReader
   req.ContentLength = -1
   req.GetBody = nil // transport-level retries must never re-read the caller's plaintext
   ```
   Alternatively install a `GetBody` that replays the already-produced ciphertext byte-for-byte. Validated
   locally: with the one-line change both triggers fail closed on `v0.3.2` and `v0.4.0`, the tinfoil-go
   default and gateway paths stop leaking, and (per the original evidence) the full EHBP Go test suite
   passes. Retries above EHBP (openai-go's retry loop, `http.Client` redirects, tinfoil-go key-rotation
   recovery) still work because each one goes back through `RoundTrip` and is re-encrypted.
2. Add a raw-frame HTTP/2 regression test (REFUSED_STREAM and GOAWAY) to the EHBP Go client.
3. Release a fixed EHBP version and bump `tinfoil-go`, `tinfoil-proxy`, the harness, the adapter and the
   other Go services (`confidential-safeguards`, `confidential-websearch`, `confidential-doc-upload`).
4. Move `confidential-sync` and `demo-safeguard` off EHBP <= `v0.2.5` (same root cause, also leaks to an
   attacker-chosen `Location` on 307/308).
5. Defence in depth: consider pinning or attesting the gateway's TLS key for gateway-mode clients.

## References

- Finding 4 (`04-ehbp-go-3xx-response-forgery`): same Go EHBP client, response-integrity side.
- Finding 11 (`11-python-rekey-bodyless-downgrade`): Python retry path; different mechanism.
- Finding 7 (`gateway-catalog-any-repo`): the same unattested gateway chooses which code a `NewGateway`
  client trusts.
- RFC 9113 section 8.7 (REFUSED_STREAM / GOAWAY retry semantics); EHBP `SPEC.md` section 7.
- REPORT.md section "Finding 1"; verifier verdicts `verification-verdicts.json` key
  `L1-ehbp-h2-retry-plaintext`.
