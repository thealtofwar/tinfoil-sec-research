# tinfoil-python enforces Intel TDX collateral that Intel's signature does not cover (duplicate-key and nested-object triggers)

| | |
|---|---|
| Component | `tinfoil` on PyPI (https://pypi.org/project/tinfoil/): `0.14.0` (latest); earlier releases not checked |
| Severity | **High**. CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4** for the primary scenario (full attestation bypass in direct mode). 9.1 in bundle/gateway mode if the Tinfoil-side position is taken as given; 5.9 for TCB-status forgery alone. See [Severity](#severity). |
| Bug class | CWE-347 (Improper Verification of Cryptographic Signature); CWE-436 (Interpretation Conflict) |
| Attacker position | Whoever answers the SDK's collateral requests to `https://tdx-proxy.tinfoil.sh` (Tinfoil, or a party holding a WebPKI certificate for that name). The full bypass also needs control of the attestation document and a custom Quoting Enclave on an Intel SGX/FLC machine. |
| Status | Unfixed at upstream HEAD as of 2026-10-08. 0.14.0 is still the latest PyPI release on 2026-10-11. Not disclosed. |

## Summary

`_verify_collateral_signature` checks Intel's ECDSA signature over the **first** `"tcbInfo":` or `"enclaveIdentity":` object it finds in the PCS response text. It finds that object with `str.find`. The values the SDK then enforces come from `json.loads(...)["tcbInfo"]`, which is the **top-level, last** member. Two response shapes split the two apart:

- **Duplicate key.** `{"tcbInfo": <genuine>, "signature": <sig>, "tcbInfo": <forged>}`.
- **Nested decoy.** `{"_": {"tcbInfo": <genuine>}, "tcbInfo": <forged>, "signature": <sig>}`. This response has no duplicate member anywhere, so a strict parser that rejects duplicates still accepts it.

Whoever serves the collateral can therefore set the TCB levels and status, the TDX module identity, `nextUpdate`, the evaluation number, and the QE identity (MRSIGNER, ISVPRODID, attributes) to any values. Intel's genuine signature still verifies. The forged collateral is also written to the on-disk cache and accepted again in later sessions.

On its own, this makes an out-of-date or vulnerable TDX platform pass as `UpToDate`. If the same party can also run its own Quoting Enclave and serve the attestation document, the client accepts a forged TDX quote that carries the attacker's TLS and HPKE keys, and the attacker can read the user's prompts.

## Threat model

**What is promised.**
- `tinfoil-python/README.md:7`: "before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key ... so only the verified enclave can read it."
- `tinfoil-go/collaterals/collaterals.go:8-9`: "Collateral is untrusted transport: the verifier re-checks every signature, so a malformed or substituted entry can only cause verification to fail."
- `tinfoil-conformance/docs/SPEC_COVERAGE_V3.md:180` (E2): "Duplicate-member behavior is a cross-parser differential; rejection is the only safe semantics."

Tinfoil's model excludes Tinfoil itself and network intermediaries from the trusted base. The collateral proxy is Tinfoil-operated and runs outside any enclave.

**Who can exploit it.** All modes use the same collateral path. `_http_get` rewrites every Intel PCS URL to `https://tdx-proxy.tinfoil.sh/...` (`collateral_tdx.py:52`, `:59-70`), and no client option changes this.

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Any mode: TCB-status / freshness forgery | Responses from `tdx-proxy.tinfoil.sh`, i.e. Tinfoil, a TLS-terminating front end, or a WebPKI-certificate holder for that name. Needed only once, because the result is cached. | Yes | A genuine but out-of-date or vulnerable Intel TDX platform is accepted as `UpToDate`. Exploiting that platform weakness is a separate step. |
| Direct mode (`TinfoilAI(enclave=...)`): full bypass | The above, **plus** the attestation document served at the enclave hostname (DNS plus a WebPKI certificate for the enclave name, or Tinfoil's own routing), **plus** a custom QE (see the preconditions below). | Yes (custom-QE step not exercised on hardware) | `Document.verify()` returns the attacker's TLS fingerprint and HPKE key. The client encrypts prompts to the attacker. |
| Bundle / gateway mode (`attestation_bundle_url`, `base_url`): full bypass | Tinfoil's bundle service, gateway and `tdx-proxy`, all Tinfoil-side (no DNS or WebPKI tricks needed), **plus** a custom QE. | Yes (same caveat) | Same as direct mode. |
| Passive or on-path attacker without a certificate for `tdx-proxy.tinfoil.sh` | - | No | `requests` verifies TLS. |

**Preconditions and assumptions.**

*Verified in code or by PoC:*
- Every TDX verification in tinfoil-python goes through `validate_collateral`. The SDK has no V3 document flow. The call chain is `TinfoilAI` / `SecureClient.verify()` (`client.py:862`) / `verify_from_bundle()` (`client.py:981`) → `Document.verify()` (`attestation.py:47-48`) → `verify_tdx_attestation` → `validate_collateral` (`attestation_tdx.py:218`).
- Whoever serves the attestation document chooses its format. A TDX-format document is therefore accepted for an enclave whose real platform is something else.
- The only check that ties a quote to Intel's TD Quoting Enclave is the QE-identity comparison at `collateral_tdx.py:1782`. Its expected values come from the forgeable object (PoC stage 4).
- tinfoil-python does not check the PCK's PPID against Tinfoil's platform endorsements (no PPID or endorsement logic outside `pck_extensions.py`). The attacker's SGX machine therefore does not have to be a Tinfoil host.

*Assumed, not exercised on hardware:*
- **Custom QE.** In Intel DCAP, the PCE certifies the report of any enclave that has the PROVISIONKEY attribute. With Flexible Launch Control (FLC), the host owner decides which enclaves get PROVISIONKEY. Root on any Intel SGX/FLC machine with a non-revoked PCK certificate can therefore run a "QE" that signs arbitrary TD quote bodies, and the platform's genuine PCK key certifies it.
- The end-to-end full-bypass runs in the evidence directory **simulated the attacker platform's PCK chain**: PCK-chain verification alone was pointed at a test root, because a new Intel-signed PCK cannot be produced. Collateral chains were still verified against the real pinned Intel root.
- If the PCE assumption were wrong, the finding reduces to TCB-status forgery (Medium).

*Unverified production facts:*
- Whether `tdx-proxy.tinfoil.sh` is a pure pass-through to Intel PCS. It was never contacted.
- Which Tinfoil enclaves run on TDX.
- A round-2 reviewer observed on 2026-10-08 that Intel PCS returns `410 Gone` for the `tcbEvaluationDataNumber=19` that 0.14.0 hard-codes (`collateral_tdx.py:846-849`). How the proxy answers today is unknown. This does not matter to an attacker who controls the proxy.

**Not affected / out of scope.**
- SEV-SNP verification: no JSON collateral is involved.
- PCK and Root CRLs: they are DER-signed structures. A separate CRL issue exists, see Finding 13.
- tinfoil-go (V3, document-carried collateral): not affected by either trigger here. Exact duplicates fail the signature in Go. Go has a different differential with the same effect; see Finding 8.
- `verify_tcb_eval_numbers_signature` (`collateral_tdx.py:1285-1312`) uses the same routine but is not on the default path.

## Severity

| Scenario | Vector | Score |
|---|---|---|
| Direct mode, full bypass (proxy control or WebPKI for `tdx-proxy` + enclave names, plus custom QE) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | 7.4 |
| Bundle/gateway mode, full bypass (Tinfoil-side position taken as given, plus custom QE) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| TCB-status / freshness forgery only | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` | 5.9 |

Rated **High** overall. All three round-1 reviewers rated it High, with confidence 0.86-0.90. A round-2 reviewer confirmed the nested trigger and scored it identically per mode. That reviewer classed it as part of this finding rather than as a separate one.

The full bypass needs three things: a privileged position (Tinfoil, or certificates for two `tinfoil.sh` names), a custom QE on real SGX hardware, and an assumption that was not demonstrated on hardware. That keeps the primary rating at 7.4 rather than 9.1. Forging the TCB status alone is roughly Medium, because it only matters together with a platform vulnerability.

## Technical details

All references are to `src/tinfoil/attestation/collateral_tdx.py`. Lines are identical in the 0.14.0 wheel and at HEAD `00fe2fe`.

Signed span = first textual occurrence (`_verify_collateral_signature`, L642-735):

```python
680    key_pattern = f'"{json_key}":'
681    key_pos = json_str.find(key_pattern)              # FIRST occurrence, any depth
685    prefix = json_str[:key_pos].rstrip()
687    if not prefix or prefix[-1] not in ('{', ','):     # a nested object's '{' passes too
705        _, obj_end = decoder.raw_decode(json_str, obj_start)
710    signed_json = json_str[obj_start:obj_end].encode('utf-8')
731        public_key.verify(signature_der, signed_json, ec.ECDSA(hashes.SHA256()))
```

Enforced object = top-level member after `json.loads`, where the last duplicate wins:

```python
552        data = json.loads(response_bytes)
556    tcb_info = _parse_tcb_info(data.get("tcbInfo", {}))                 # parse_tcb_info_response
584        data = json.loads(response_bytes)
588    enclave_identity = _parse_enclave_identity(data.get("enclaveIdentity", {}))
```

The enforced values drive these checks:
- freshness (`check_collateral_freshness`, called at L2084);
- TCB status (`validate_tcb_status`, L2092);
- TDX module identity (L2099);
- QE identity, including `if qe_report_mrsigner != qe_identity.mrsigner:` (L1782).

The cache makes the forgery persist:
- `fetch_tcb_info` (L806-873) and `fetch_qe_identity` (L875-943) write the raw forged body to the cache.
- On a cache hit (L829-843), they re-run the same signature routine and the same freshness check against the forged `nextUpdate` (2099 in the PoC).

## Proof of concept

`poc/` contains `poc_f2.py` (one file), `run.sh`, `data/` and `expected-output.txt`.
- **Code under test:** the unmodified `tinfoil==0.14.0` wheel from PyPI, installed into a venv under `/root/tinfoil-review/work/disclosures/02/`.
- **Quote:** Intel's production SPR quote, with its genuine PCK chain verified against the SDK's pinned Intel SGX Root CA.
- **Collateral:** genuine Intel-signed 2023 TCB Info, QE Identity and CRLs, shipped as `google/go-tdx-guest` v0.3.1 `testing/testdata` (sha256 values are recorded in the evidence directory).
- **Network:** no network access apart from `pip install`.

```
cd poc && ./run.sh
```

Stages and results (from `expected-output.txt`, run on 2026-10-11):

```
[1] genuine Intel TCB Info + QE Identity              -> REJECT  No matching TCB level found for the quote's SVN values
[2] dup-key tcbInfo forgery                           -> ACCEPT  TCB status=UpToDate
[3] nested tcbInfo forgery                            -> ACCEPT  TCB status=UpToDate
[4a] [2] + dup-key enclaveIdentity, mrsigner=4141..   -> REJECT(forged mrsigner enforced)  ... Got dc9e2a7c..., expected 4141..(unsigned value)
[4b] [3] + nested enclaveIdentity, mrsigner=4141..    -> REJECT(forged mrsigner enforced)  ... Got dc9e2a7c..., expected 4141..(unsigned value)
[5a] dup-key tcbInfo forgery, strict parser           -> REJECT  duplicate JSON member rejected: ['tcbInfo', 'signature', 'tcbInfo']
[5b] nested tcbInfo forgery, strict parser            -> ACCEPT  TCB status=UpToDate
[6a] nested forgery of both objects                   -> ACCEPT  tls_fp=6c62dec1b8191749..   (Document.verify())
[6b] next session, no network (poisoned cache)        -> ACCEPT  tls_fp=6c62dec1b8191749..
matches expected: True
```

What each stage shows:
- **[1]** is the negative control: honest input is rejected. Without the forgery, the platform's real TCB matches no Intel level.
- **[2]/[3]** flip that decision. The only change is the added unsigned object.
- **[4a]/[4b]** prove that the QE identity check enforces the unsigned object. The real Intel QE is now rejected against the attacker's MRSIGNER `4141..`. A custom QE whose MRSIGNER is `4141..` would pass.
- **[5a]/[5b]** patch a duplicate-rejecting `object_pairs_hook` into `collateral_tdx.json.loads`. That blocks the duplicate-key trigger but not the nested one.
- **[6a]/[6b]** run the public `Document.verify()` entry point at the shipped evaluation-number floor (19), then a second session with the network disabled.

**What is simulated or stubbed.** None of these knobs touches the signature or parsing code.
- **Clock.** Frozen to 2023-06-30, the validity window of the 2023 collateral. A real attacker wraps current Intel PCS responses and needs no clock change.
- **Network.** `requests.get` is replaced by a stand-in for `tdx-proxy.tinfoil.sh`, which is the attacker's position. It refuses any other URL.
- **Evaluation-number floor in stages 1-5.** `validate_collateral` is called with `min_tcb_evaluation_data_number=15` so the genuine 2023 data (evaluation number 15) reaches the TCB-level decision rather than failing as stale.
- **Policy pins in stage 6.** MR_SEAM, TD_ATTRIBUTES, XFAM and the minimum TEE_TCB_SVN are set to the 2023 sample quote's values.
- **Custom QE.** Not run. Stage 4 proves the attacker controls the expected MRSIGNER. Producing a quote whose QE carries that MRSIGNER needs real SGX hardware.

Full original evidence: `/root/tinfoil-security-findings/python-tdx-collateral-dupkey/evidence/`.
- `verifier-impact/scripts/e2e_tinfoilai_sim.py` and `e2e_output.txt`: the end-to-end run through the public `TinfoilAI()` API in direct and bundle/gateway modes. It reaches `securityVerified=True` with the attacker's keys, and the attacker decrypts the prompt. This run uses a **simulated** attacker PCK chain.
- `verifier-poc/scripts/poc3_real_https_stack.py`: the same flip over the real `requests`/TLS stack.
- `nested-variant/`: the nested trigger.

## Impact

For a Python SDK user talking to a TDX enclave:

- **Full bypass.** The party that controls collateral delivery and the attestation document can make `TinfoilAI` treat a host it controls as a verified Tinfoil enclave, given a custom QE on an SGX/FLC machine. The client pins the attacker's TLS key or seals EHBP request bodies to the attacker's HPKE key. Prompts, responses and `user_cache_secret` are readable by the attacker, while the client reports a successful verification.
- **TCB forgery only.** Without the custom QE, Intel's TCB policy is void. Out-of-date or vulnerable TDX platforms are accepted as `UpToDate`.
- **Persistence.** The forgery stays in the user's cache (`platformdirs` user cache, `tinfoil`) until the cache is cleared, because the forged `nextUpdate` can be set far in the future.

## Remediation

1. **Enforce exactly the bytes that are signed.**
   - Parse the response once, strictly: reject duplicate members at every depth with an `object_pairs_hook`, and require the top-level members to be exactly `{tcbInfo|enclaveIdentity, signature}`.
   - Find the value span of the depth-0 member with a real member walk (`JSONDecoder.raw_decode` over the top-level members), not `str.find`.
   - Verify the signature over that span and build the enforced object from `json.loads(span)`.
   - Rejecting duplicate keys alone is **not** sufficient (PoC stage 5b).
2. Apply the same rules to the cache path, and to `verify_tcb_eval_numbers_signature`.
3. Ship a release that ignores or invalidates existing collateral caches, so that poisoned entries are not reused.
4. Defence in depth: bound the cache lifetime by the issuer certificate's validity and a maximum age, not by the attacker-controlled `nextUpdate`. Add conformance vectors for both triggers and run them against tinfoil-python.

**Fix validated locally.** `/root/tinfoil-review/work/disclosures/02/fixcheck/fixcheck.py` monkeypatches the parsers and the signature routine as in item 1 (strict top-level members, depth-0 span), then runs the PoC unchanged. Every stage is rejected. The genuine collateral still parses and verifies, and is rejected only at the TCB-level decision, as in stage 1. Output is in `fixcheck/output.txt`.

## References

- Finding 8 (`08-go-tdx-guest-casefold-collateral/`): the same signed-vs-enforced class in tinfoil-go / go-tdx-guest, through JSON case-folding. REPORT.md's statement that "Go/V3 is not affected" is correct only for exact duplicate keys.
- Finding 13 (`13-python-pck-crl-issuer-unbound/`): a PCK CRL issuer-binding gap on the same collateral path.
- Original evidence: `/root/tinfoil-security-findings/python-tdx-collateral-dupkey/` (hunter, three round-1 verifiers, `nested-variant/`).
- Verdicts: `verification-verdicts.json` key `L5-python-tdx-collateral-dupkey` (3/3 upheld); `verification-verdicts-round2.json` candidate `python-sdk-verifier/tdx-collateral-nested-object-signature-differential` (mechanism confirmed; folded into this finding).
- Intel PCS v4 API: TCB Info and QE Identity responses are signed over the raw `tcbInfo` / `enclaveIdentity` object.
