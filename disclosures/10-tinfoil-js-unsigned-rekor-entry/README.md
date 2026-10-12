# tinfoil-js accepts Sigstore bundles whose Rekor entry is completely unsigned

| | |
|---|---|
| Component | `@freedomofpress/sigstore-browser` on npm: `0.1.11` through `0.1.14` (fixed in `0.1.15`, no advisory) |
| Severity | Medium (CVSS 3.1 `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N` = 5.9 for the primary scenario) |
| Bug class | CWE-347 (Improper Verification of Cryptographic Signature), CWE-1104 (use of unmaintained/vulnerable third-party component) |
| Attacker position | Serves the attestation bundle to the JS client (ATC / github-proxy operator, WebPKI-capable MITM, or custom bundle URL) **and** holds a genuine Fulcio leaf key for `tinfoilsh/confidential-model-router` with a `refs/tags/*` ref |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary
The JS verifier hands all transparency-log checks to `sigstore-browser`. In 0.1.14 that library
verifies a Rekor signed entry timestamp (SET) only if one is present, and a checkpoint signature only
if one is present. A bundle with neither, plus a one-leaf Merkle "proof" the attacker computes
themselves, is accepted. The unsigned `integratedTime` is then used as the time at which the
10-minute Fulcio certificate must be valid. So no Rekor key needs to sign anything, and the signing
time is attacker-chosen. Fulcio chain, SCT and DSSE signature are still enforced, so the attacker
still needs a genuine Fulcio-issued key for the repository. With such a key the bug turns a
short-lived, publicly logged signing capability into a permanent, unlogged one for affected JS clients.

## Threat model
What Tinfoil promises:
- `tinfoil-js/packages/verifier/README.md:111`: "**Verify Code Provenance** — Uses Sigstore (Fulcio + Rekor) to verify the release signature".
- `tinfoil-conformance/docs/SPEC_COVERAGE_V3.md:211` (P7): "At least one transparency-log (Rekor) entry verifies against the pinned log key ... signing event is publicly auditable. Reject if no Rekor entry or entry verification fails."

Attacker capability:

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Default `SecureClient` / `TinfoilAI` (EHBP), TLS transport, browser: Tinfoil or an insider operating `atc.tinfoil.sh` | Bundle delivery (by design) + a Fulcio key for the repo with a tag ref (Tinfoil release identity, or a leaked ephemeral key from any past release job) + an SNP enclave running the forged measurement | Yes, on installs resolving sigstore-browser <= 0.1.14 | Client reports `securityVerified=true` for an unlogged measurement; prompts sealed to the attacker's HPKE key / TLS pinned to their key. No Rekor record exists. |
| `Verifier.verify()` path: operator of `github-proxy.tinfoil.sh` | Same as above | Yes (same versions) | Same |
| External party with a WebPKI certificate for `atc.tinfoil.sh` / `github-proxy.tinfoil.sh` (on-path MITM) | MITM + leaked Fulcio key for the repo + SNP enclave | Yes, but needs two independent compromises | Same (CVSS 7.4 if scored PR:N, see Severity) |
| Custom `attestationBundleURL` operator | That URL + Fulcio key + SNP enclave | Yes | Same |
| Any attacker without a genuine Fulcio key for the repo | Bundle delivery only | No | Fulcio chain / SCT / DSSE checks still reject |
| Install resolving sigstore-browser >= 0.1.15 | - | No | Rejected (`Invalid bundle: inclusion proof`) |

Preconditions, verified in code:
- `@tinfoilsh/verifier@1.2.2` and `tinfoil@1.2.2` declare `"@freedomofpress/sigstore-browser": "^0.1.14"` (`package.json:34`, `packages/verifier/package.json:54`, `packages/tinfoil/package.json:65`); `package-lock.json:500-503` locks 0.1.14.
- The lockfiles of `omp-provider`, `pi-provider`, `opencode-provider` (HEAD) lock 0.1.14 (developer installs only; the published packages carry no lockfile).
- The bundle reaches the verifier unchecked: `packages/tinfoil/src/atc.ts:24-64`, `secure-client.ts:269-295` (ATC path); `packages/verifier/src/bundle.ts:14,53` (github-proxy path).
- The policy only checks issuer, `GitHubWorkflowRepository` and a `refs/tags/` workflow ref (`packages/verifier/src/sigstore.ts:86-92`).

Unverified production facts:
- How many deployed JS clients still resolve <= 0.1.14. A fresh `npm install tinfoil@1.2.2` today resolves 0.1.15 (checked locally 2026-10-11), so only lockfile-frozen installs (lockfiles created before 2026-09-28, the tinfoil-js repo/CI itself, bundles built from such lockfiles) are exposed. No npm advisory exists, so `npm audit` does not flag them.
- Whether `atc.tinfoil.sh` still serves the bundle format tinfoil-js 1.2.2 consumes (no production traffic was sent).
- Whether any Fulcio key for the repository has leaked, and whether a non-Tinfoil SEV-SNP machine satisfies the JS platform policy (no hardware test).

Not affected: `tinfoil-webapp` @ `c061681` (its `package-lock.json:1332-1333` resolves 0.1.15); `verification-center` (does not run the verifier); tinfoil-go / tinfoil-swift (sigstore-go v1.2.2 rejects "inclusion proof missing required checkpoint"); tinfoil-python (sigstore-python); tinfoil-rs (own checkpoint verification).

## Severity
- Primary (Tinfoil-side or insider attacker who holds the release identity and serves the bundle): `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N` = **5.9 Medium**.
- External attacker modelled as unprivileged (leaked ephemeral key + WebPKI MITM): `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = 7.4. CVSS 3.1 cannot express the mandatory leaked-key precondition, so we do not use this as the headline.

Justification: the bug is not a standalone forgery. Someone who holds the release identity could already
publish a Rekor-logged malicious release that every verifier accepts. What the bug removes is the
guarantee that such a signature is publicly logged and that a leaked ephemeral key is useless after 10
minutes. That is a real loss of a documented property (P7), but it needs a strong precondition. All
three independent reviewers rated it Medium (confidence 0.75-0.9). One reviewer wrote 6.4 for the PR:H
vector; that is an arithmetic slip (the vector computes to 5.9).

## Technical details
`tinfoil-js/packages/verifier/src/sigstore.ts:68-97` (HEAD `bedbe69`, identical in the published 1.2.2 `dist/sigstore.js:39-62`) creates `new SigstoreVerifier()` with default options, loads the bundled trusted root and calls `verifier.verifyDsse(bundle, policy)`. Tinfoil adds no transparency-log check of its own. On success `client.ts:78` sets `verifyCode=success` and `client.ts:124` `securityVerified: true`.

`@freedomofpress/sigstore-browser` 0.1.14, `src/sigstore.ts`:

```ts
// verifyInclusionPromise, :449
if (!entry.inclusionPromise?.signedEntryTimestamp) {
  if (!entry.inclusionProof) { throw ... }   // any inclusionProof object suffices
} else { /* verify SET */ }
// :503-511: unsigned entry.integratedTime is the cert-validity anchor
if (entry.integratedTime) { if (!cert.validForDate(new Date(Number(entry.integratedTime)*1000))) throw ... }

// verifyInclusionProof, :604-609
if (entry.inclusionProof) {
  await verifyMerkleInclusion(entry);          // root recomputed from attacker-supplied values
  if (entry.inclusionProof.checkpoint) {        // checkpoint signature only if present
    await verifyCheckpoint(entry, this.rawRoot.tlogs);
  }
}
```

`tsaThreshold` defaults to 0 (`:103`), and `logId` is not matched against the trusted root on this path.
`treeSize=1, logIndex=0, hashes=[], rootHash=SHA256(0x00 || canonicalizedBody)` satisfies `verifyMerkleInclusion`.
`verifyDsse` repeats the unsigned-time check at `:909-921`.

Fix upstream: sigstore-browser 0.1.15 (commit `e8d5d67`, 2026-09-19, "Harden bundle verification: per-entry tlog checks ..."; npm 2026-09-28) requires `inclusionProof.checkpoint.envelope` in `src/bundle.ts:171` and verifies SET/checkpoint per entry against a trusted log. tinfoil-js released 1.2.2 on 2026-10-03, after the fix, with the lockfile still at 0.1.14.

## Proof of concept
`poc/poc.mjs` loads the published `@tinfoilsh/verifier@1.2.2` from npm (no rebuild) with its bundled
Sigstore trusted root, and calls `Verifier.verifyBundle()` on the genuine production fixture copied
unchanged from `tinfoil-js/packages/verifier/test/fixtures/attestation-bundle.json` (sha256
`e01fabe4...fcc1e`; Fulcio leaf for `tinfoilsh/confidential-model-router`, tag ref, valid
1769121722-1769122322). It mutates only `tlogEntries[0]`. `fetch` is replaced with a throwing stub;
`verifyBundle()` is offline.

Cases: unmodified fixture; tampered checkpoint signature; tampered SET; ATTACK (SET deleted, checkpoint
deleted, self-made one-leaf proof, `logId` = 32 x `0x41`, `logIndex=1`, `integratedTime` chosen inside
the cert window); bound (same, one second after `notAfter`).

Run (needs node >= 20 and access to registry.npmjs.org; build trees go to `$WORK`, default
`/root/tinfoil-review/work/disclosures/10`):

```
cd poc && ./run.sh
```

`run.sh` installs `@tinfoilsh/verifier@1.2.2` twice via npm `overrides`: once with sigstore-browser
0.1.14 (what the tinfoil-js lockfile resolves) and once with 0.1.15 (negative control). Both use
crypto-browser 0.1.8. Output from the run on 2026-10-11 (`poc/expected-output.txt`):

```
@tinfoilsh/verifier 1.2.2 | @freedomofpress/sigstore-browser 0.1.14 | node v24.21.0 | now 2026-10-11T19:17:04.914Z
control: unmodified production fixture                     -> ACCEPTED securityVerified=true
control: checkpoint signature tampered                     -> rejected (Invalid checkpoint signature) securityVerified=false
control: SET (inclusionPromise) tampered                   -> rejected (Failed to verify the inclusion promise in the provided bundle.) securityVerified=false
ATTACK: no SET, no checkpoint, self-made proof, t=1769122000 -> ACCEPTED securityVerified=true
bound: same, integratedTime 1s after cert notAfter         -> rejected (Artifact signing was logged outside of the certificate validity.) securityVerified=false

@tinfoilsh/verifier 1.2.2 | @freedomofpress/sigstore-browser 0.1.15 | ...
ATTACK: no SET, no checkpoint, self-made proof, t=1769122000 -> rejected (Invalid bundle: inclusion proof) securityVerified=false
```

The tampered-checkpoint and tampered-SET controls show both signatures are checked when present; the
attack shows they are not required. The bound shows the unsigned `integratedTime` is the only time
anchor.

What is not demonstrated: signing a *different* measurement. That needs a Fulcio key for the
repository, which is exactly the precondition; the PoC keeps the genuine DSSE signature. No SNP
hardware test was done.

Original evidence (larger): `/root/tinfoil-security-findings/js-sigstore-tlog-unsigned-entry/evidence/hunter/`
- `sdk-level-forged-atc-output.txt`: public `SecureClient.ready()` against a loopback ATC serving the forged bundle resolves with all five steps `success`.
- `rekor-bypass-variants-output.txt`: variants with Rekor v2 `logId`, two unsigned entries, bogus mediaType, removed `timestampVerificationData` also accepted.
- `go-compare-output.txt`: tinfoil-go rejects the same bundle ("inclusion proof missing required checkpoint").
- Conformance vector `094-rekor-entry-unsigned-no-checkpoint-no-promise` in `/root/tinfoil-review/work/js-sdk-verifier/new-vectors/sigstore/`.

## Impact
On affected installs the transparency-log stage of code-provenance verification does nothing. Any
holder of a Fulcio key for `tinfoilsh/confidential-model-router` with a tag ref (Tinfoil's release
identity, an insider, or anyone who ever exfiltrated an ephemeral key from a release job) can sign
arbitrary `snp_measurement` statements at any later time. Paired with their own SEV-SNP enclave, the
JS SDK then reports `securityVerified=true` and encrypts user prompts to the attacker's key, and no
public Rekor record of the release exists for auditors to find.

### Affected downstream packages

- `@tinfoilsh/verifier` `1.2.2` and `tinfoil` `1.2.2` (npm), when the install resolves sigstore-browser <= `0.1.14`: the `tinfoil-js` repository lockfile and CI, consumer lockfiles created before 2026-09-28
- `omp-provider`, `pi-provider`, `opencode-provider` repository lockfiles (developer installs)
- Not affected: the Tinfoil Chat web app (its lockfile pins `0.1.15`) and fresh `npm install tinfoil@1.2.2`

## Remediation
1. Raise the floor to `"@freedomofpress/sigstore-browser": "^0.1.15"` in `package.json`, `packages/verifier/package.json`, `packages/tinfoil/package.json`; regenerate `package-lock.json`; release new `@tinfoilsh/verifier` / `tinfoil`; refresh the omp/pi/opencode provider lockfiles. Validated locally: 0.1.15 rejects every attack variant (output above).
2. Defence in depth in tinfoil-js itself (as already done for `x509CertificateChain` at `sigstore.ts:79-83`): require each tlog entry to carry `inclusionProof.checkpoint.envelope`, and do not accept `integratedTime` as a time anchor unless a SET verified against a log key in the trusted root.
3. Add vector 094 to tinfoil-conformance and run the JS adapter in CI. Vector 093 currently assumes JS verifies checkpoints; it does only when one is present.
4. Consider exact-version pins for verification-critical dependencies, and ask the sigstore-browser maintainers to publish an advisory so `npm audit` flags 0.1.14.

## References
- REPORT.md Finding 10; evidence dir `js-sigstore-tlog-unsigned-entry/`; verifier votes in `verification-verdicts-round2.json` (key `js-sdk-verifier/js-sigstore-tlog-unsigned-entry-accepted`, 3/3 upheld).
- Related provenance-trust findings: Finding 7 (`07-gateway-catalog-chooses-trusted-repo`), Finding 8 (go-tdx-guest collateral).
- sigstore-browser commit `e8d5d67`; sigstore-go `pkg/tlog/entry.go` (checkpoint required).
