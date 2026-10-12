# confidential-summarizer sends each upstream request before it checks the TLS pin

| | |
|---|---|
| Component | `github.com/tinfoilsh/verifier`: `v0.11.2` and `v0.11.3` (latest standalone release); the same code in `github.com/tinfoilsh/tinfoil-go` `v0.12.0` through `v0.12.5` (fixed in `v0.12.6`) |
| Severity | Medium (CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = 5.9 for the primary scenario) |
| Bug class | CWE-295 (Improper Certificate Validation: check performed after use), CWE-1104 (unmaintained third-party component) |
| Attacker position | Controls the summarizer CVM's network path to the router **and** holds a publicly trusted certificate for the router hostname (Tinfoil host/control plane, DNS owner) |
| Status | Unfixed at upstream HEAD as of 2026-10-08 (re-checked 2026-10-11 from the module proxy: `@latest` is still v0.1.15); not disclosed |

## Summary

The summarizer enclave forwards user text to the model router over a TLS connection that is supposed
to be pinned to the router's attested key. The pinned SDK it ships (verifier v0.11.2 via tinfoil-go
v0.11.3) checks the peer key only after `http.DefaultTransport.RoundTrip` has returned. By then the full
request, including `Authorization: Bearer <TINFOIL_API_KEY>` and the user text, has been written to the
peer. Anyone who can route the summarizer's outbound connection to themselves and present a WebPKI-valid
certificate for the router name receives every summarize request in plaintext. The summarizer then
returns 503, which all clients swallow silently. Upstream fixed the SDK in tinfoil-go v0.12.6
(2026-03-27), but the summarizer was never rebuilt on it.

## Threat model

What Tinfoil promises here:
- `tinfoil-go/AGENTS.md:6`: "A real TLS pinning bypass is an HTTPS request that can complete without the
  peer certificate public key matching the attested TLS public-key fingerprint."
- `tinfoil-go@v0.12.6/verifier/client/roundtrip.go:40-41` (the fix): "dialTLSContext performs the TLS
  handshake and verifies the certificate fingerprint BEFORE any HTTP request data is sent over the
  connection."
- `confidential-summarizer/README.md:3,98`: the service "runs inside a Tinfoil secure enclave" and "Uses
  the Tinfoil Go SDK for attested communication with Tinfoil enclaves."

The pin exists precisely so that the host, Tinfoil's control plane, or a certificate holder cannot read
traffic between enclaves. The summarizer->router hop has no EHBP layer (no EHBP package is in the
v0.1.15 build graph), so the pin is its only protection.

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Tinfoil infrastructure (CVM host, DNS owner for `tinfoil.sh`, cert-proxy DNS-01) | Route the summarizer CVM's egress (`egress: open`, `tinfoil-config.yml:17`) and obtain a public cert for `inference.tinfoil.sh` or an ATC-listed `router.infN.tinfoil.sh` | Yes, easy | Reads summarize inputs for every request in the attack window. Each intercepted request returns 503 |
| Malicious operator of the machine hosting the router or summarizer | Network path plus a cert via HTTP-01/TLS-ALPN-01 for a hostname that resolves to a machine they run | Plausible | Same |
| External network attacker (no Tinfoil access) | BGP/DNS hijack plus CA mis-issuance or ACME validation | Hard | Same, plus the summarizer's `TINFOIL_API_KEY` (only meaningful against non-Tinfoil attackers) |
| Passive observer | Nothing active | No | TLS still encrypts the hop |
| End users calling summarizer.tinfoil.sh directly | n/a | Not the attacker; they are the victims | Their title/summary inputs leak |

Preconditions verified in code:
- v0.1.15 `go.mod:11` pins `tinfoil-go v0.11.3`; `go.mod:72` pins `verifier v0.11.2`. The release zip is
  byte-identical to `main` @ af60fd1 except the image digest in `tinfoil-config.yml`.
- `upstream.go:45-47` builds the client with `tinfoil.NewClient`, which uses verifier's
  `TLSBoundRoundTripper`.
- Data sent to the summarizer: webapp titles (first <=100 words of the first user message,
  `tinfoil-webapp/src/services/inference/title.ts:41-53` @ c061681) and reasoning tails (<=200 words,
  `ThoughtProcess.tsx:114`); harness titles (`confidential-tinfoil-harness/derived.go:63-86` @ 4c170c6);
  iOS titles (first <=100 words of the first assistant reply) and thinking summaries
  (`tinfoil-ios` `SummarizerService.swift`, `ThinkingSummaryService.swift`).

Unverified production facts (no production contact allowed):
- That `summarizer.tinfoil.sh` runs v0.1.15. Inferred: clients verify it against `releases/latest` of
  `tinfoilsh/confidential-summarizer`, and every tag pins the vulnerable SDK.
- That verifier v0.11.2 still verifies today's router at startup. Inferred from code: the shim still
  serves the legacy v2 attestation document and the `snp-tdx-multiplatform/v1` predicate.

Not affected: other Tinfoil Go services checked by reviewers are on tinfoil-go >= v0.13 (pin enforced in
`VerifyConnection`); integrity is not affected, because the forged response is rejected; the main chat
completion traffic does not go through the summarizer.

## Severity

- Tinfoil/host as attacker (primary): `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = **5.9**. AC:H because the
  attacker needs both a network position and a trusted certificate for the router name.
- External attacker: same vector, but in practice much harder (CA mis-issuance or BGP hijack). Score
  unchanged; likelihood far lower.

All three round-1 reviewers upheld the finding as Medium (confidence 0.8-0.9). Two noted it could be argued
High under Tinfoil's "the operator cannot read your data" promise. We keep Medium because only a slice of
each chat is exposed (title source text and reasoning tails), each interception produces a visible 503,
and the fix already exists upstream.

## Technical details

`verifier@v0.11.2/client/roundtrip.go:22-44` (v0.11.3 is identical):

```go
func (t *TLSBoundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	...
	resp, err := http.DefaultTransport.RoundTrip(r)   // :27 request written to any WebPKI-valid peer
	...
	certFP, err := attestation.ConnectionCertFP(*resp.TLS) // :36 checked after the response arrives
	...
	if certFP != t.ExpectedPublicKey {                  // :40
		return nil, ErrCertMismatch
	}
```

- `verifier@v0.11.2/client/client.go:299-310`: `HTTPClient()` returns
  `&http.Client{Transport: &TLSBoundRoundTripper{s.groundTruth.TLSPublicKey}}`.
- `tinfoil-go@v0.11.3/tinfoil_client.go:91-118`: `createClientFromSecureClient` wraps that transport in
  `reVerifyingTransport` (`:25-52`) and passes it to openai-go with base URL `https://<enclave>/v1/`.
  `reVerifyingTransport` only acts after `RoundTrip` returns, so it cannot stop the leak. On mismatch it
  re-runs attestation (the PoC blocks that fetch); a successful re-verification would retry the request.
- `confidential-summarizer` v0.1.15: `main.go:34-42` wires the client into `summaryService`;
  `upstream.go:49-54` sets `WithAPIKey(apiKey)`; `upstream.go:60-80` sends the user content.
- Fixed in `tinfoil-go@v0.12.6` (`verifier/client/roundtrip.go`, pin checked in `DialTLSContext`) and, at
  HEAD ef79d8e / v0.17.0-rc.1, in `tls.Config.VerifyConnection` (`enclave/roundtrip.go:49-63`; same code at
  `tinfoil-go@v0.16.1/verifier/client/roundtrip.go:49-63`).

## Proof of concept

Files (`poc/`):
- `shared/harness_test.go`: test CA installed as the system trust store (`SSL_CERT_FILE`), an attacker TLS
  server on `127.11.22.33:443` with a CA-valid certificate for `inference.tinfoil.sh` but a non-attested
  key, and an in-process resolver that maps `inference.tinfoil.sh` to it and returns NXDOMAIN for all
  other names (no egress).
- `vulnerable/poc_test.go`: dropped into an unmodified copy of `confidential-summarizer@v0.1.15` from the
  Go module proxy. Drives `POST /summarize` through the real handler, openai-go v3.16.0, tinfoil-go
  v0.11.3 `reVerifyingTransport`, verifier v0.11.2 `TLSBoundRoundTripper`, unmodified
  `http.DefaultTransport`. The attacker withholds its response, so the capture provably happens while the
  client is still inside `RoundTrip`, before any pin check.
- `control/`: same attacker, same request, transport from tinfoil-go v0.16.1 (latest stable).
- `run.sh`, `expected-output.txt` (full run of 2026-10-11).

Run (needs Go >= 1.25, root or `CAP_NET_BIND_SERVICE` for port 443 on 127.11.22.33; fetches public modules
from proxy.golang.org if not cached; build tree goes to `$WORK`, default
`/root/tinfoil-review/work/disclosures/05`):

```
cd poc && ./run.sh
```

Key output (Go 1.27.1):

```
github.com/tinfoilsh/tinfoil-go v0.11.3
github.com/tinfoilsh/verifier v0.11.2
== vulnerable (HTTP/1.1) ==
poc_test.go:108: pinned (attested) key FP : ad22c95d...
poc_test.go:109: attacker cert key FP     : 51b286fc...
poc_test.go:110: [attacker, response withheld] POST inference.tinfoil.sh/v1/chat/completions HTTP/1.1
poc_test.go:111: [attacker, response withheld] Authorization: Bearer tk_CANARY_SUMMARIZER_API_KEY
poc_test.go:112: [attacker, response withheld] body: {"messages":[...,{"content":"CANARY-USER-SECRET: I was diagnosed with HIV yesterday, how do I tell my employer","role":"user"}],"model":"llama3-3-70b",...}
poc_test.go:113: summarizer upstream call still pending: pin check has not run
poc_test.go:117: end user got: 503 {"error":"upstream service is temporarily unavailable","code":"upstream_unavailable",...}
poc_test.go:119: resolver: api-github-proxy.tinfoil.sh -> NXDOMAIN (egress blocked)
poc_test.go:127: VULNERABLE: full plaintext request (user text + API key) reached a non-attested TLS peer; pin mismatch detected only afterwards (503)
--- PASS: TestVulnerable_PinCheckedAfterSend
poc_test.go:139: pinned key == peer key: end user got 200 {"summary":"Peer chosen title"}
--- PASS: TestControl_HonestPeerAccepted
== vulnerable (HTTP/2) ==   (same result, HTTP/2.0)
== control: tinfoil-go v0.16.1 ==
control_test.go:38: current SDK error: Post "https://inference.tinfoil.sh/v1/chat/completions": attestation error: enclave certificate does not match the attested key; re-verify the enclave
control_test.go:39: attacker: 1 TCP connection(s), 0 HTTP request(s)
--- PASS: TestControl_CurrentSDKPinsBeforeSend
--- PASS: TestControl_CurrentSDKHonestPeer
```

Negative controls: (1) with the pin equal to the peer key the same harness returns 200, so the 503 is
caused by the late pin check; (2) the current SDK reaches the same attacker (1 TCP connection) but aborts in
the handshake and sends 0 HTTP requests.

Stubbed or simulated:
- Startup attestation: the `SecureClient`'s `groundTruth` is set by reflection to
  `{EnclaveHost: inference.tinfoil.sh, TLSPublicKey: <genuine key FP>}`, which is what a successful
  `Verify()` stores (`verifier@v0.11.2/client/client.go:220-230`). The client is then built by tinfoil-go's
  own `createClientFromSecureClient` (via `go:linkname`), as `NewClient` does. This skips only the network
  attestation fetch; the pin value and transport chain are real.
- WebPKI: a test CA replaces the public roots. Network control: the in-process resolver.
- The re-verification fetch the SDK attempts after the mismatch is blocked (NXDOMAIN). A second leak when
  the attacker lets re-verification succeed was not demonstrated.

Original evidence (hunter and three reviewer PoCs, including a run against tinfoil-go v0.12.5/v0.12.6):
`/root/tinfoil-security-findings/summarizer-postsend-pin/evidence/`.

## Impact

During an interception window the attacker reads, for every user of Tinfoil Chat (web, iOS) and the
harness: the first <=100 words of each new chat's first user message (iOS: first assistant reply), and
<=200-word tails of model reasoning sent for thought summaries. These are exactly the inputs Tinfoil says
the operator cannot see. The summarizer's `TINFOIL_API_KEY` also leaks. Users see only a default "New Chat"
title or a missing thought summary; the summarizer logs `upstream_unavailable` and nothing else.

### Affected downstream packages

- `github.com/tinfoilsh/tinfoil-go` <= `v0.11.x` (depends on `verifier`)
- `github.com/tinfoilsh/confidential-summarizer`, every tag `v0.1.0` through `v0.1.15` (latest; pins tinfoil-go `v0.11.3` and verifier `v0.11.2`), deployed as `summarizer.tinfoil.sh`; its callers are the web app, the harness and the iOS app

## Remediation

- Rebuild the summarizer on current tinfoil-go (>= v0.12.6; preferably latest, which pins in
  `VerifyConnection` and offers EHBP), and cut a release so clients' `releases/latest` check moves to it.
- Deprecate or patch the standalone `github.com/tinfoilsh/verifier` module (v0.11.3 still has the
  post-send check) so other consumers cannot pick it up.
- Defence in depth: add a CI check that fails enclave service builds whose module graph contains
  `tinfoilsh/verifier` <= v0.11.3 or `tinfoil-go` < v0.12.6; use EHBP for enclave-to-enclave hops so the
  body is encrypted to the attested key even if TLS pinning regresses (after Finding 1 is fixed).

Fix validated locally: the control test shows the v0.16.1 transport sends zero request bytes to the same
attacker.

## References

- Finding 1 (`ehbp-h2-retry-plaintext`): EHBP Go plaintext resend; relevant if EHBP is used as the fix.
- Finding 4 (`ehbp-go-forged-responses`): other tinfoil-go transport-layer integrity issues.
- Upstream fix: tinfoil-go v0.12.6 (`afca1f7`, 2026-03-27), `verifier/client/roundtrip.go`.
