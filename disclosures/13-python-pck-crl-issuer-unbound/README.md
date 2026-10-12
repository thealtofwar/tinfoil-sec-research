# tinfoil-python accepts a PCK CRL issued by any Intel-rooted CA, so a revoked PCK certificate can be hidden

| | |
|---|---|
| Component | `tinfoil` on PyPI (https://pypi.org/project/tinfoil/): `0.14.0` (latest); earlier releases not checked |
| Severity | **Medium**. CVSS 3.1 `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N` = **5.9** (collateral-proxy operator holding an Intel-revoked PCK key). See [Severity](#severity). |
| Bug class | CWE-299 (Improper Check for Certificate Revocation); CWE-295 (Improper Certificate Validation) |
| Attacker position | Whoever answers the SDK's collateral requests to `https://tdx-proxy.tinfoil.sh` (Tinfoil, or a WebPKI-certificate holder for that name). The attacker **also** needs the private key of a PCK certificate that Intel has revoked. |
| Status | Unfixed at upstream HEAD as of 2026-10-08. 0.14.0 is still the latest PyPI release on 2026-10-11. Not disclosed. |

## Summary

When tinfoil-python verifies a TDX quote, it fetches the PCK CRL for the PCK's issuing CA, `?ca=platform` or `?ca=processor`. It then accepts any CRL that verifies under any certificate chain from the `SGX-PCK-CRL-Issuer-Chain` header, as long as that chain ends at the Intel SGX Root CA. Nothing checks that the CRL was issued by the CA that issued the PCK certificate.

So the collateral path can answer the Platform-CA request with one of two other genuine Intel-signed CRLs:
- Intel's genuine **Processor** CA CRL, or
- Intel's genuine, empty **Root CA** CRL, served with the chain `[root, root]`.

A Platform-CA PCK serial cannot appear in either CRL, so a revoked PCK certificate is treated as valid. The substituted CRL is also cached and reused offline: for 30 days with the Processor CRL, and until 2027-02-26 with the Root CA CRL.

Exploiting this needs a PCK private key that Intel has already revoked. tinfoil-go is not affected: go-tdx-guest binds the CRL issuer.

## Threat model

**What is promised.**
- `tinfoil-python/README.md:7`: the SDK "verifies the enclave's attestation ... so only the verified enclave can read it."
- The SDK's own docstring at `collateral_tdx.py:1916-1917` says the PCK check is done "per Intel DCAP spec Section 2.3".
- `tinfoil-go/collaterals/collaterals.go:8-9`: "Collateral is untrusted transport: the verifier re-checks every signature, so a malformed or substituted entry can only cause verification to fail."

Revocation exists for one situation: a platform key is known to be compromised. Tinfoil's model excludes Tinfoil and network intermediaries from the trusted base.

**Who can exploit it.** All modes fetch collateral through `_http_get`, which rewrites every URL to `https://tdx-proxy.tinfoil.sh/...` (`collateral_tdx.py:52`, `:59-70`).

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Any mode, `tdx-proxy` operator (Tinfoil) or a front end that terminates its TLS | The PCK CRL response, **plus** the private key of an Intel-revoked PCK, **plus** delivery of the attestation document (enclave hostname or Tinfoil's bundle/gateway path) | Yes | A quote signed through the revoked platform is accepted. With that key the attacker can certify any QE and sign any quote, so the client binds to the attacker's keys. |
| Any mode, external party with a WebPKI certificate for `tdx-proxy.tinfoil.sh` | Same | Yes (lower likelihood) | Same |
| Collateral-path control **without** a revoked PCK key | CRL response only | The substitution is accepted and cached | No security effect by itself |
| Passive network attacker | - | No | `requests` verifies TLS |

**Preconditions and assumptions.**

*Verified in code or by PoC:*
- Every TDX verification in the SDK reaches `validate_collateral` → `fetch_collateral` (`collateral_tdx.py:1183-1226`) → `validate_certificate_revocation` (`:1908-1960`).
- The wrong-CA CRL is accepted and cached (PoC stages C and D).
- `verify_intel_chain` accepts `[Intel SGX Root CA, Intel SGX Root CA]` as an issuer chain (PoC stage D).

*Not demonstrated:*
- No revoked PCK certificate or key is public. The serial lookup therefore uses a self-signed stand-in that carries a serial from Intel's real platform CRL (57 entries on 2026-10-08). `validate_certificate_revocation` reads only `pck_cert.serial_number` (`collateral_tdx.py:1951-1952`), so the stand-in is faithful for this check.
- No forged quote signed through a revoked platform was produced.

*Unverified production facts:*
- The behaviour of `tdx-proxy.tinfoil.sh`.
- Whether any PCK relevant to an attacker or to Tinfoil has been revoked.
- Intel often handles broad key-extraction issues through TCB recovery rather than per-platform revocation. TCB recovery is checked separately. That narrows the realistic window to individually revoked platforms whose TCB is otherwise acceptable.

**Relationship to Finding 2.** While Finding 2 is unfixed, the same collateral-path attacker already has a stronger bypass that needs no key. This finding matters on its own **once Finding 2 is fixed**. Its mechanism (a DER-signed CRL, no parser trick) and its fix are independent.

**Not affected.**
- tinfoil-go and everything built on it (Swift/iOS, proxy, CLI, enclave services). go-tdx-guest v0.3.1 `verify/verify.go:725-745` (`validateCRL`) requires `crl.Issuer == intermediate.Subject` and `crl.CheckSignatureFrom(intermediate)`; `:814` requires the PCK CRL issuer to equal the PCK issuer.
- tinfoil-js (SEV-SNP only) and tinfoil-rs (no TDX). Both were checked by a reviewer.
- SEV-SNP paths in general.

## Severity

| Scenario | Vector | Score |
|---|---|---|
| Tinfoil as collateral-proxy operator, plus a revoked PCK key | `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N` | 5.9 |
| External WebPKI-capable on-path attacker, plus a revoked PCK key | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | 7.4 (on paper) |

Rated **Medium**. All three reviewers upheld the finding as Medium (confidence 0.7-0.85).
- CVSS 3.1 cannot express "must already hold a PCK key that Intel has revoked". That is the dominant precondition, and it is why the paper score of 7.4 overstates the risk. CVSS 4.0 would record it as `AT:P`.
- Two reviewers quoted 6.1 and 6.4 for the `PR:H` vector. The CVSS 3.1 formula gives 5.9 for that vector, so this write-up uses 5.9.
- One reviewer noted that under a strict "already-compromised hardware is out of scope" reading this could be Low. The rating stays Medium because CRL checking exists for exactly this case, and the reference verifiers (go-tdx-guest, Intel QVL) bind the issuer.

## Technical details

All references are to `src/tinfoil/attestation/collateral_tdx.py` (0.14.0 = HEAD `00fe2fe`).

The CRL check only requires *some* Intel-rooted chain whose first certificate signed the CRL:

```python
946 def _verify_crl_signature(crl, issuer_chain, ca_type):
964         verify_intel_chain(issuer_chain, f"PCK CRL ({ca_type}) issuer chain")   # chain from the response header
969     signing_cert = issuer_chain[0]
974         signing_cert.public_key().verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(hash_algo))
        # no check of crl.issuer against the PCK's issuer / the quote's intermediate CA
```

`ca_type` only chooses the URL and the cache file:
- `fetch_pck_crl`, L985-1060: `url = .../pckcrl?ca={ca_type}` (L1028), `_get_crl_cache_path(ca_type)` (L1008).
- On a cache hit, L1013-1024 re-runs the same check.

The revocation lookup uses whatever CRL came back:

```python
1951    pck_serial = pck_cert.serial_number
1952    revoked_pck = pck_crl.get_revoked_certificate_by_serial_number(pck_serial)
```

`fetch_collateral` (L1205-1209) calls `fetch_pck_crl(_determine_pck_ca_type(pck_cert))`. It passes neither the PCK issuer nor the intermediate certificate, even though `validate_certificate_revocation` receives `intermediate_cert` (L1911).

Freshness is bounded only by the CRL's own `nextUpdate` (`_is_crl_fresh`, L371). That bound is 30 days for the PCK CRLs and 2027-02-26 for the current Root CA CRL.

## Proof of concept

`poc/` contains `poc_f13.py`, `run.sh`, `data/` and `expected-output.txt`.
- **Code under test:** the unmodified `tinfoil==0.14.0` wheel from PyPI, installed into a venv under `/root/tinfoil-review/work/disclosures/13/`.
- **Quote and PCK chain:** Intel's production SPR quote (go-tdx-guest v0.3.1 testdata). Its real **Platform-CA** PCK chain is verified against the SDK's pinned Intel root.
- **Collateral:** genuine Intel PCS responses with their headers, fetched from `api.trustedservices.intel.com` on 2026-10-08: platform CRL, processor CRL, Root CA CRL, TCB Info and QE Identity. See `data/FETCH-NOTES.txt`.
- **Clock:** the real clock. The CRLs are valid until 2026-11-07. After that date, re-fetch the public collateral or freeze the clock.

```
cd poc && ./run.sh
```

Each scenario runs the production `fetch_collateral()` path, then a second `fetch_collateral()` with the network disabled to show the cached result, then `validate_certificate_revocation()` for a PCK carrying a serial that Intel revoked under the Platform CA.

```
[A control: genuine platform CRL + platform chain]
    fetched as ca_type='platform', CRL issuer='Intel SGX PCK Platform CA'; cached: 'Intel SGX PCK Platform CA'
    -> REJECT PCK certificate has been revoked. Serial: 6fc34e5023e728923435d61aa4b83c618166ad35, ...
[B control: platform CRL + processor chain (bad sig)]
    -> REJECT PCK CRL (platform) signature verification failed
[C attack:  processor CRL + processor chain]
    fetched as ca_type='platform', CRL issuer='Intel SGX PCK Processor CA'; cached: 'Intel SGX PCK Processor CA'
    -> ACCEPT (revoked PCK not detected)
[D attack:  Root CA CRL + [root, root] chain]
    fetched as ca_type='platform', CRL issuer='Intel SGX Root CA'; cached: 'Intel SGX Root CA'
    -> ACCEPT (revoked PCK not detected)
RESULT: {'A': 'REJECT', 'B': 'REJECT', 'C': 'ACCEPT', 'D': 'ACCEPT'}
matches expected: True
```

What the controls show:
- **A**, the honest input, detects the revocation.
- **B** shows the CRL signature check is live: a CRL with a mismatched chain is rejected.
- **C** and **D** use only genuine Intel-signed CRLs and genuine Intel chains, so no signature is forged.

**Stubs.**
- `requests.get` is a local stand-in for `tdx-proxy.tinfoil.sh`, the attacker's position.
- The revoked PCK certificate is a stand-in that carries a real revoked serial, as explained above.
- The attestation-document step and the use of the revoked key to sign a quote are not reproduced.

Original evidence:
- `/root/tinfoil-security-findings/python-pck-crl-issuer-not-bound/evidence/` (hunter PoC).
- Reviewer runs under `/root/tinfoil-review/work/verify2/python-sdk-verifier--tdx-pck-crl-issuer-not-bound--{code,impact,poc}/`. These include a loopback-proxy end-to-end run through `verify_tdx_attestation` and the Root-CRL variant.

## Impact

The SDK's PCK revocation check fails open against the party that serves collateral. A TDX platform whose PCK key was extracted and revoked by Intel can still sign QE reports and quotes that tinfoil-python accepts. The user's client would then bind to keys chosen by the holder of that platform key. Without such a key the bug has no effect.

## Remediation

1. Bind the CRL to the PCK's issuing CA from the quote's own chain, as go-tdx-guest does:
   - pass `pck_chain.intermediate_cert` into `fetch_pck_crl` / `_verify_crl_signature`;
   - require `crl.issuer == intermediate_cert.subject == pck_cert.issuer`;
   - verify the CRL signature with `intermediate_cert.public_key()` and not with `issuer_chain[0]` from the response header;
   - reject the response if `issuer_chain[0]` is not that CA.
2. Key the CRL cache by the issuer's name or key, not only by `ca_type`. Re-check the binding on cache hits.
3. In `verify_intel_chain`, reject a chain whose leaf is the root itself when a subordinate CA is expected.
4. Optionally, cap CRL age using `thisUpdate`, as go-tdx-guest does, in addition to `nextUpdate`.

**Fix validated locally.** `/root/tinfoil-review/work/disclosures/13/fixcheck/fixcheck.py` wraps `validate_certificate_revocation` with the issuer and signature binding from item 1 and re-runs the PoC unchanged. A and B are rejected as before. C and D are now rejected with "PCK CRL issuer ... is not the PCK issuing CA". Output is in `fixcheck/output.txt`.

## References

- Finding 2 (`02-python-tdx-collateral-signed-vs-enforced/`): same collateral path and attacker, and a stronger bypass while unfixed.
- Finding 8 (`08-go-tdx-guest-casefold-collateral/`): the Go verifier, which binds CRL issuers correctly but has a different collateral flaw.
- Verdicts: `verification-verdicts-round2.json`, candidate `python-sdk-verifier/tdx-pck-crl-issuer-not-bound` (3/3 upheld, Medium).
- Intel SGX/TDX DCAP Quote Verification: the PCK CRL must be issued by the PCK's issuing CA (Platform or Processor CA).
