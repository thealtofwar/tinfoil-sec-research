# go-tdx-guest enforces Intel TDX collateral from an unsigned case-variant JSON member (tinfoil-go accepts unsigned TCB Info and QE Identity)

| | |
|---|---|
| Component | `github.com/google/go-tdx-guest`: `v0.3.1` (latest tag) and upstream `main` `b0a2dd8` (2026-10-03) |
| Severity | **Critical impact / High CVSS.** Full TDX attestation bypass: CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4**, scoring the host-root precondition as AC:H; 9.1 if that position is taken as the adversary (AC:L). TCB-status forgery only: 4.8-5.9. See [Severity](#severity). |
| Bug class | CWE-347 (Improper Verification of Cryptographic Signature); CWE-436 (Interpretation Conflict); CWE-178 (Improper Handling of Case Sensitivity) |
| Attacker position | Whoever supplies the Intel PCS responses to the verifier. In tinfoil-go ≥ v0.16.1 that is whoever serves the attestation document. In v0.15.x it is whoever controls `tdx-proxy.tinfoil.sh`. The full bypass also needs root on the host OS of an endorsed TDX machine. |
| Status | Unfixed in go-tdx-guest v0.3.1 and main `b0a2dd8`, and in tinfoil-go HEAD `ef79d8e`, as of 2026-10-08 (go-tdx-guest re-checked 2026-10-11 via proxy.golang.org: v0.3.1 is still the latest tag). Not disclosed. |

## Summary

go-tdx-guest parses each Intel PCS TCB Info and QE Identity response twice, with different rules:

- **Enforced copy.** `json.Unmarshal(body, &collateral.TdxTcbInfo)` uses `encoding/json` v1. It matches member names **case-insensitively** and decodes a later matching member **into the same struct**, overriding the fields that member contains.
- **Signed copy.** The bytes whose ECDSA signature is checked come from `map[string]json.RawMessage` with the **exact** key `"tcbInfo"` / `"enclaveIdentity"`.

The attacker takes a genuine Intel-signed body and inserts an extra `"tcbinfo"` or `"enclaveidentity"` member. The signature still verifies over the untouched genuine member. The checks for TCB status, TDX module identity, QE MRSIGNER/ISVPRODID/attributes and collateral expiry all read the attacker's values.

tinfoil-go replays document-carried PCS responses into go-tdx-guest unchanged. Two consequences follow:
- Whoever serves the attestation document can make any genuine but out-of-date TDX platform pass as `UpToDate`.
- Combined with root on an endorsed TDX host, that party can endorse its own Quoting Enclave. tinfoil-go then accepts a forged attestation that binds the attacker's TLS and HPKE keys.

**For go-tdx-guest maintainers.** The bug is in `verify/verify.go` (`getTcbInfo` / `getQeIdentity` against `bodyToRawMessage`). Any verifier that receives PCS responses from a party it does not fully trust is affected: replayed or embedded collateral, a caching PCCS or proxy, or a custom `trust.HTTPSGetter`. Fetching directly from Intel PCS over TLS limits the attacker to someone who can impersonate `api.trustedservices.intel.com`.

## Threat model

**What is promised.**
- `tinfoil-go/README.md:7`: "before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key ... so only the verified enclave can read it."
- `tinfoil-go/collaterals/collaterals.go:8-9`: "Collateral is untrusted transport: the verifier re-checks every signature, so a malformed or substituted entry can only cause verification to fail."
- `tinfoil-go/verify/internal/quote/tdx/authenticate.go:217-219`: "these bytes are authenticated and interpreted by the verification library".

TDX exists to exclude the host and cloud operator. Tinfoil's model also excludes Tinfoil itself and network intermediaries.

**Who can exploit it.**

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| **A. Document-carried collateral** (tinfoil-go ≥ v0.16.1, HEAD/v0.17.0-rc.1, tinfoil-proxy, tinfoil-swift HEAD xcframework, cvmimage): TCB-status forgery | The `intel-pcs` entries of the v3 document. Possible holders: Tinfoil's unattested gateway/relay in gateway mode; a configured proxy; a party holding a WebPKI certificate for the enclave name in direct mode; the host of the TD; or the attestation-collaterals (ATC) service, whose entries the cvmimage shim embeds verbatim (`cvmimage/tinfoil/cmd/shim/collaterals.go`, `tinfoil/internal/attestationmaterial/client.go`). `REPORT_DATA` does not bind the collateral array. | Yes (real Intel quote and collateral, production build) | A genuine TDX platform below Intel's current TCB (microcode, TDX module or QE SVNs) is accepted as `UpToDate`, and the TCB/SVN policy is void. Exploiting that platform weakness is a separate step. |
| **A. Document-carried collateral**: full bypass | The above **plus** root on the host OS of a TDX machine whose PPID is in Tinfoil's platform endorsements: the bare-metal or cloud provider, a datacenter or ops insider, or anyone who has compromised that host. Under FLC the host owner decides which enclaves receive PROVISIONKEY, so the platform's PCE certifies an attacker QE with the genuine PCK key. The forged QE Identity (`mrsigner` = attacker) is then what gets enforced. | Yes (fake-QE step simulated; see below) | A forged v3 document with any MRTD/RTMRs (set to match the endorsed code) and a `REPORT_DATA` binding attacker TLS/HPKE keys passes `VerifyV3`, `mobile.Verifier.Verify` and `enclave.Handle`. The client pins the attacker's TLS key or seals EHBP bodies to the attacker's HPKE key. Prompts, responses and `user_cache_secret` are readable by the host. |
| **B. Live-fetch collateral** (tinfoil-go v0.15.x: shipped iOS app via xcframework v0.15.4, tinfoil-cli, Go enclave services) | Responses of `tdx-proxy.tinfoil.sh`: a Tinfoil insider, a compromise of that proxy, or a WebPKI-certificate holder for it. Full bypass needs the fake-QE step as well. | Yes (same parser, same code path) | Same results as mode A, but the attacker must control a Tinfoil-operated service. This is the same position as Finding 2. |
| **C. Other go-tdx-guest users** | Whatever sits between the verifier and Intel PCS: a PCCS or caching proxy, replayed evidence, or a custom getter | Depends on deployment | TCB/QE policy forgery; full bypass with a host-root fake QE. |
| Passive network attacker; SEV-SNP-only enclaves | - | No | The AMD path has no JSON collateral. |

**Preconditions and assumptions.**

*Verified in code and by the PoCs below:*
- tinfoil-go HEAD consumes document-carried collateral only and never fetches. `document/collateral/tdx.go:66-76` decodes `body_base64` as opaque bytes. `verify/internal/quote/quote.go:127` passes them to `tdx.Authenticate`. `authenticate.go:93-109` hands them to `tdxverify.TdxQuote`, and the replay getter (`:170-201`) returns the body unchanged.
- tinfoil-go's `tcbEvaluationRecorder` (`authenticate.go:211-246`) decodes with `encoding/json/v2`, which is case-sensitive. It therefore records the genuine evaluation number (20, above the floor of 19) and ignores the variant member.
- Exact duplicate keys are **not** exploitable in Go, because last-wins applies to both decodes.
- v0.15.x live fetch: `tinfoil-go@v0.15.3/verifier/attestation/tdx.go:240-254` sets `Getter = NewTDXGetter(WithProxyServer("tdx-proxy.tinfoil.sh"))`, `GetCollateral = true`, then calls `verify.TdxQuote`.

*Assumed, not exercised on hardware:*
- That the PCE certifies the report of an attacker enclave holding PROVISIONKEY on an FLC platform where the attacker has host root. This is documented DCAP behaviour, and Finding 2 relies on the same assumption.
- PoC stage 4 therefore uses the synthetic Intel root and PCK chain from tinfoil-conformance. tinfoil-go's `tinfoil_conformance` build tag replaces **only** the root and the clock (`overrides_conformance.go`). Stages 2 and 3 use a real Intel quote, real Intel-signed collateral, the real embedded Intel root and the real clock.

*Unverified production facts:*
- Which Tinfoil enclaves run on TDX, and who holds root on the endorsed TDX hosts.
- Whether deployed images serve v3 documents with verbatim ATC entries.
- Whether `tdx-proxy.tinfoil.sh` is a pure pass-through.
- How many users run the document-carried versions. tinfoil-go v0.16.x/v0.17.0-rc.1 and tinfoil-swift v0.9.0-rc.1 are pre-releases. The shipped iOS app and the Go enclave services are on mode B.

**Not affected.**
- SEV-SNP verification.
- tinfoil-python, which has a different bug of the same class (Finding 2).
- tinfoil-js and tinfoil-rs, which use separate implementations and were not examined for this bug.
- Go clients using exact duplicate `tcbInfo` keys (fails the signature, PoC stage 2 test D).

## Severity

| Scenario | Vector | Score |
|---|---|---|
| Full bypass, mode A, host root scored as attack complexity | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | **7.4** |
| Full bypass, mode A, host-root operator taken as the adversary | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| Full bypass, scored as scope change (the TEE boundary) | `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N` | 8.7 |
| TCB-status forgery only, no fake QE | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | 4.8 (5.9 with `C:H` if a usable platform-TCB exploit exists) |
| Mode B (v0.15.x live fetch) | Same vectors; the attacker must also control `tdx-proxy.tinfoil.sh` | 7.4 / 4.8 |

**Rating: Critical impact, High CVSS (7.4-9.1).** The impact is a complete break of TDX attestation for every Go-based Tinfoil verifier. The attacker is the host operator TDX is meant to exclude, and no client interaction is needed. CVSS is lower than the impact suggests because the full bypass needs a privileged position: host root on an endorsed machine plus control of the document path. It also rests on a DCAP property that was not exercised on hardware.

The two valid reviewers disagreed on the label. One rated it Critical (8.7 with S:C, 10.0 at AC:L). The other rated it High (7.4, 9.1 at AC:L), for consistency with Finding 2. A third reviewer was blocked by an API safeguard and gave no verdict.

**Correction to REPORT.md.** Its Finding 8 severity paragraph gives "8.5-9.0" for the full bypass and "6.5-7.5" for TCB-only. The reviewers' vectors give 7.4 / 8.7 / 9.1 and 4.8-5.9, which this disclosure uses.

## Technical details

go-tdx-guest v0.3.1, `verify/verify.go`.

The signed bytes come from the exact-key member:

```go
333 func bodyToRawMessage(name string, body []byte) ([]byte, error) {
337     var rawbody map[string]json.RawMessage
338     if err := json.Unmarshal(body, &rawbody); err != nil {
341     val, ok := rawbody[name]                  // exact key "tcbInfo" / "enclaveIdentity"
```

The enforced copy is decoded case-insensitively and merged:

```go
391     if err := json.Unmarshal(body, &collateral.TdxTcbInfo); err != nil {   // encoding/json v1
397     tcbInfoRawBody, err := bodyToRawMessage(tcbInfoPhrase, body)
426     if err := json.Unmarshal(body, &collateral.QeIdentity); err != nil {
432     qeIdentityRawBody, err := bodyToRawMessage(enclaveIdentityPhrase, body)
```

The signature check runs over the raw member (`verifyResponse`, L1136-1168):

```go
1165    if err := signingCertificate.CheckSignature(x509.ECDSAWithSHA256, rawBody, derSignature); err != nil {
```

Everything that is enforced reads the merged structs:
- `checkCollateralExpiration` (L500);
- `checkTcbInfoTcbStatus` (L940);
- `verifyTdQuoteBody` (L966: FMSPC, PCEID, MRSIGNERSEAM, module identity);
- `verifyQeReport` (L998: MRSIGNER, ISVPRODID, MISCSELECT, attributes, ISVSVN).

On main `b0a2dd8` the same construct sits at L28 (`encoding/json`), L365-373, L423/L429, L458/L464 and L1401.

Example of an accepted body. `<genuine>` and `<sig>` are Intel's bytes, unchanged:

```
{"tcbInfo":<genuine>,"tcbinfo":{"tcbLevels":[{"tcb":{...all 0...},"tcbStatus":"UpToDate",...}],"tdxModuleIdentities":[...]},"signature":"<sig>"}
{"enclaveIdentity":<genuine>,"enclaveidentity":{"mrsigner":"<attacker QE signer>","tcbLevels":[...]},"signature":"<sig>"}
```

Two defences that do not help:
- A v1 decoder with `DisallowUnknownFields` does not reject the variant (PoC stage 1), because the variant is not "unknown" to v1.
- Comparing `tcbEvaluationDataNumber` does not help either: it is read from the signed member.

## Proof of concept

`poc/` contains four stages, a `run.sh` that runs them all, and `expected-output.txt` from a run on 2026-10-11. Builds happen under `/root/tinfoil-review/work/disclosures/08/`. Requirements: Go ≥ 1.25 (tested with 1.27.1) and `python3`. The first run needs proxy.golang.org for public modules. No Tinfoil or Intel host is contacted.

```
cd poc && ./run.sh            # GOTDX_MAIN=0 skips the go-tdx-guest main run; TINFOIL_GO_SRC=<clone> overrides the tinfoil-go source
```

| Stage | Files | What it shows | Key output |
|---|---|---|---|
| 1 | `1-json-semantics/` (stdlib only) | encoding/json v1 merges `"tcbinfo"` into the `tcbInfo` field, while the exact-key raw map returns the genuine bytes. v1 `DisallowUnknownFields` accepts it. json/v2 ignores it, and v2 `RejectUnknownMembers` rejects it. | `enforced (v1 struct): ... nextUpdate="2099-01-01" levels=[{Status:UpToDate}]` / `signed (exact-key raw): {... "OutOfDate"}` |
| 2 | `2-go-tdx-guest/` (go-tdx-guest v0.3.1, then main `b0a2dd8` via `-tags gotdx_main`) | `verify.TdxQuote` on Intel's production SPR quote (go-tdx-guest testdata) with genuine Intel PCS collateral for FMSPC 50806f000000, fetched 2026-10-08 and valid to 2026-11-06. Embedded Intel root, `time.Now()`, `CheckRevocations: true`. | A (control): `no matching TCB level found`. B: `+ unsigned "tcbinfo"/"enclaveidentity" members: err=<nil>`. C: `MRSIGNER value("dc9e…") in QE Report is not equal to MRSIGNER value(…\xab\xab…)`, so the unsigned mrsigner is enforced. D (control): exact duplicate → `x509: ECDSA verification failure`. Identical results on main. |
| 3 | `3-tinfoil-go/poc_casefold_test.go`, dropped into tinfoil-go `ef79d8e` `verify/internal/quote/tdx/` (production build, no tags) | `tdx.Authenticate`, the function `VerifyV3` calls for TDX, with the same quote and collateral as stage 2 | A: `verifying TDX quote: ... no matching TCB level found`. B: `ACCEPTED: identity(PPID)=089ddfdb9c0359c82a3bc7719239574e tcbEvaluationDataNumber(recorded from the signed member)=20`, with MRTD/RTMRs returned. C: unsigned MRSIGNER enforced. |
| 4 | `4-verifyv3-fakeqe/` (fixture made with tinfoil-conformance's own generators; `derive_casefold.py` adds one unsigned member) | Full `Verifier.VerifyV3` through tinfoil-go's conformance adapter (`-tags tinfoil_conformance`: synthetic Intel root and fixed clock only). The quote is signed by a "QE" with MRSIGNER `EE..EE`; the signed QE Identity says `DC..DC`. | `fakeqe-control: {"accepted": false, "rejection": {"code": "QUOTE_REJECTED"}}`; `fakeqe-casefold-derived: {"accepted": true, "tls_public_key_fp": "d1a37889…", "hpke_public_key": "58c9b375…"}`. The signed member and the signature are byte-identical between the two fixtures. |

**Negative controls.**
- Genuine collateral is rejected (stages 2, 3, 4).
- Exact duplicates are rejected (stage 2 test D).
- With the fix in `poc/fix/` applied, every forged body is rejected while genuine collateral still verifies (see Remediation).

**What is stubbed.**
- The `trust.HTTPSGetter` replays captured responses. That is exactly how tinfoil-go ≥ v0.16.1 operates, and it stands in for the proxy in mode B.
- Stage 4's PCK chain is synthetic, because the fake-QE PCE signature needs SGX hardware.

Full original evidence:
- `/root/tinfoil-security-findings/go-tdx-collateral-casefold/evidence/` (hunter `run-pocs.sh`, outputs, including PoC 2b on tinfoil-go v0.16.1).
- `/root/tinfoil-review/work/go-verifier-quotes/`.
- Reviewer reruns in `/root/tinfoil-review/work/verify2/go-verifier-quotes--tdx-collateral-casefold-differential--{poc,impact}/`.

## Impact

For any TDX enclave verified by Go code:

- **Full bypass (mode A or B).** A Tinfoil SDK user (Go, tinfoil-proxy, Swift/iOS through the xcframework) or a Tinfoil service that checks upstream enclaves (model router, harness, keyserver) can be made to treat a host-controlled environment as a genuine Tinfoil enclave running the published code. The host operator can then read and alter all traffic. The client reports a successful verification.
- **TCB forgery only.** Intel's TCB recovery has no effect on these verifiers. Platforms with known TDX-module, microcode or QE vulnerabilities verify as `UpToDate`.
- **Expiry.** A reviewer noted that the hunter's "expired collateral accepted indefinitely" is moot. An attacker can always use current genuine Intel bodies as the signed carrier, and the DER-signed CRLs (30-day and 1-year windows) cannot be forged.

### Affected downstream packages

- `github.com/tinfoilsh/tinfoil-go` `v0.16.1` and `v0.17.0-rc.1` (document-carried collateral: whoever serves the document supplies the PCS bodies)
- `github.com/tinfoilsh/tinfoil-go` `v0.15.x` (collateral fetched live from `tdx-proxy.tinfoil.sh`)
- `tinfoil-swift` HEAD via the `Tinfoil.xcframework` `v0.17.0-rc.1`; the shipped iOS app via tinfoil-swift `0.8.2` and xcframework `v0.15.4` (live fetch)
- `tinfoil-proxy` (tinfoil-go `v0.16.1`) and `cvmimage` (tinfoil-go `v0.16.2` pre-release)
- Go enclave services and tools on tinfoil-go `v0.15.x`: `confidential-model-router`, `confidential-safeguards`, `confidential-doc-upload`, `confidential-websearch`, `confidential-tinfoil-harness`, `confidential-openai-adapter`, `tinfoil-cli`, `keyserver`
- Any other Go verifier that feeds Intel PCS collateral through go-tdx-guest

## Remediation

**go-tdx-guest (upstream):**
1. Decode the enforced struct **from the exact bytes that are signature-checked**. Unmarshal `rawBody` (the `tcbInfo` / `enclaveIdentity` member) into `pcs.TcbInfo` / `pcs.EnclaveIdentity`, and take only `signature` from the outer object.
2. Before that, require the top-level object to have exactly the members `{tcbInfo|enclaveIdentity, signature}`. Compare names case-sensitively, allow no duplicates, and allow no other members. Alternatively, use `encoding/json/v2` with `RejectUnknownMembers(true)` and its default duplicate rejection.
   - `DisallowUnknownFields` in v1 is **not** sufficient.
3. Add regression tests with case-variant members and with exact duplicates.

**Fix validated locally.** `poc/fix/go-tdx-guest-v0.3.1-strict-toplevel.diff` (about 40 added lines) implements item 2 in `getTcbInfo` / `getQeIdentity`. With it applied through a `go.mod` `replace`, stage 2 behaves as follows (`poc/fix/fixcheck-output.txt`):
- the genuine control still reaches the TCB-status decision;
- the case-variant bodies (B, C) fail with `unexpected or duplicate member "tcbinfo" in PCS response`;
- the exact duplicate (D) is rejected at parse time.

Item 1 is the more complete fix and is recommended in addition.

**tinfoil-go (defence in depth, independent of upstream):**
- Canonicalise every document-carried PCS body before replaying it. Parse with json/v2 (`RejectUnknownMembers`, duplicate rejection), require exactly two top-level members, and re-serialise as `{"<key>":<raw signed member>,"signature":"<sig>"}`.
- Bump go-tdx-guest once fixed, and release new versions of tinfoil-proxy, cvmimage, the xcframework (tinfoil-swift / iOS) and the v0.15.x consumers.
- Add tinfoil-conformance vectors for case-variant and nested members in `intel-pcs` bodies.

**Tinfoil, operationally:** bind the collateral to something the TD attests to, or have clients verify collateral against Intel PCS independently, so that a single document server cannot choose the collateral.

## References

- Finding 2 (`02-python-tdx-collateral-signed-vs-enforced/`): the same signed-vs-enforced class in tinfoil-python (duplicate-key and nested triggers). REPORT.md's statement there that "Go/V3 is not affected" holds only for exact duplicates.
- Finding 13 (`13-python-pck-crl-issuer-unbound/`): by contrast, go-tdx-guest's CRL issuer binding (`validateCRL`, `verify.go:725-745`, `:814`) is correct.
- Verdicts: `verification-verdicts-round2.json`, candidate `go-verifier-quotes/tdx-collateral-casefold-differential`. Two of two valid reviewers upheld it (0.85 critical, 0.9 high).
- Corrections relative to the hunter and REPORT.md, taken from the reviewers:
  - go-tdx-guest main's `verify.go` is **not** identical to v0.3.1, but the defective construct is unchanged there. This disclosure reproduces it dynamically on main `b0a2dd8`.
  - The cvmimage collateral code is at `tinfoil/cmd/shim/collaterals.go` and `tinfoil/internal/attestationmaterial/client.go`.
  - The severity figures, as described under Severity.
- Go `encoding/json` documentation: "Unmarshal matches incoming object keys to the keys used by Marshal ... preferring an exact match but also accepting a case-insensitive match."
- Intel PCS v4 API: TCB Info and QE Identity signatures cover the raw `tcbInfo` / `enclaveIdentity` JSON object.
