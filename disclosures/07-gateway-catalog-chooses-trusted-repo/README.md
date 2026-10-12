# The unauthenticated gateway catalog chooses which `tinfoilsh/*` code a `NewGateway` client trusts

| | |
|---|---|
| Component | `github.com/tinfoilsh/tinfoil-go` (`NewGateway`): `v0.15.8-0.20260924012310-ff60af7e9ea6` through `v0.17.0-rc.1` (latest) |
| Severity | High for the in-model attacker (Tinfoil as gateway operator, or an insider): CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5. Medium for an external attacker (see Severity) |
| Bug class | CWE-807 (reliance on untrusted inputs in a security decision), CWE-345 (insufficient verification of data authenticity) |
| Attacker position | Controls the `/catalog` response of the gateway **and** administers a CVM on endorsed hardware that runs a freshly witnessed `tinfoilsh/*` release with `cvm_admin` (today: Tinfoil's own dev boxes) |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary

In gateway mode, tinfoil-go asks the gateway which GitHub repository each model's enclave runs, then
verifies the enclave's attestation against that repository. The only constraint on the answer is the
`tinfoilsh/` prefix. Tinfoil signs, publishes and freshness-witnesses releases of dev-box configurations
whose measured config grants the CVM administrator root (`cvm_admin: true`) and forwards decrypted EHBP
bodies to the administrator's own container. A gateway that names such a repo for an inference model makes
an unpinned client verify successfully and seal every prompt to the dev box. The party able to do this
today is Tinfoil itself (or an insider with gateway config access and a dev-box key); this is the party
`tinfoil-proxy` promises cannot read requests.

## Threat model

What is promised:

- `tinfoil-proxy/README.md:3`: "forwards requests through the Tinfoil gateway to an enclave serving the
  requested model, verifies that enclave against the public attestation transparency log, and encrypts
  request and response bodies to it ... so neither the gateway nor any other intermediary can read them."
- `tinfoil-go/gateway_catalog.go:25`: "Catalog maps model names to untrusted repository and replica entries."
- Tinfoil's own harness treats the catalog the same way and does not use it for trust:
  `confidential-tinfoil-harness/main.go:163`: "The catalog is plaintext config, not a trust input."

Who can exploit it:

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| tinfoil-proxy default (no `--pin`), or confidential-openai-adapter (has no pin support); attacker = Tinfoil / insider | The gateway's `/catalog` and attestation relay, plus admin of a dev-box CVM whose release has a witness < 7 days old. Both exist today. | Yes | Client reports successful verification; every request body (prompts, files, `cache_salt`) is EHBP-sealed to the dev box and decrypted there for the admin. Admin can forward to a real model so answers look normal. |
| Same clients; external attacker (gateway compromise or WebPKI cert for the gateway host) | Gateway position **and** admin of a freshly witnessed `cvm_admin` `tinfoilsh/*` CVM | Not today without also compromising a Tinfoil dev box or staff SSH/Teleport key | Same as above |
| Same clients; external attacker with a customer sandbox | `confidential-agent-sandbox` v0.1.8 is `cvm_admin` and customer-launchable, but its only witness (2026-09-22) is stale; `confidential-sandbox-gpu` is not usable (see below) | No as of 2026-10-08; becomes yes if Tinfoil re-witnesses `confidential-agent-sandbox` | Same as above |
| tinfoil-proxy with `--pin` + `--pinned-only`; any `NewGateway` user with `PinnedModelsOnly` | n/a | No | Pin mismatch is rejected (PoC control) |
| `NewClient` / `NewClientWithOptions` (explicit repo), incl. the Chat harness; JS, Python, Rust, Swift SDKs | n/a | No (no gateway catalog) | n/a |

Preconditions, verified in code (pristine sources, this PoC, and the three independent reviewers):

- Catalog filter is prefix-only; unpinned resolve returns the catalog repo; `VerifyV3` derives the only
  accepted signing identity from that string (Technical details).
- `tinfoilsh/confidential-ubuntu-tinfoil-config` v0.1.1 is signed by its own release workflow and its
  signed predicate contains `cvm_admin: true`, `ports: ["22:22"]`, `upstream-port: 22`,
  `authenticated: false` (PoC test A prints these from the signed bundle).
- Its freshness witness was logged 2026-10-07T18:03:26Z and is valid until 2026-10-14T18:03:26Z.
  Reviewers saw three witnesses for this digest (2026-09-27, 10-02, 10-07), i.e. it is being renewed.
  `confidential-ubuntu-config` v0.1.2 (also `cvm_admin`) was witnessed 2026-10-06T02:29:03Z.
- cvmimage shim (`58b08de`, `cmd/shim/main.go`, `api.go`): every config publishes TLS + HPKE keys in the
  attestation and, with `authenticated: false` and no `paths`, proxies decrypted bodies to the upstream
  port. `internal/containers/containers.go:490-495`: `cvm_admin` gives UID 0, privileged.

Unverified production facts (no Tinfoil host was contacted):

- That `inference-gateway.tinfoil.sh` serves `/catalog` in the `FetchCatalog` shape and relays attestation
  fetches for arbitrary hosts (inferred: the shipped proxy and adapter cannot work otherwise).
- That a running dev box (cvm-version 0.14.10) answers the v3 attestation endpoint with HPKE material and
  is reachable through the relay (inferred from shim code at cvmimage HEAD; that exact version was not
  inspected).
- That the dev boxes run on machines in platform-endorsements v0.0.17 (inferred from the active witnessing).
- The hardware-quote layer was not exercised (see Proof of concept).

Out of scope / not affected: see the last two table rows. `confidential-sandbox-gpu` v0.1.1 is **not** a
usable destination: its shim has `paths: [/enroll, /healthz]`, which `api.go` enforces before EHBP
decryption, it has no `cvm_admin` container, and its witness is stale.

## Severity

| Scenario | Vector | Score |
|---|---|---|
| Tinfoil or insider as gateway operator, all preconditions hold today | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 (High) |
| Same, also counting attacker-authored completions | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| Same, scoring the gateway + dev-box admin as provider-level privileges | `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N` | 5.9 (Medium) |
| External attacker who compromises the gateway and a Tinfoil dev box / staff key | `AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N` | 5.9-6.4 (Medium) |

Three independent reviewers upheld the finding (confidence 0.70-0.85). Two rated it High (7.4 and 7.5),
one Medium (5.9), on the grounds that exploitation needs provider-level access, is bounded by the 7-day
witness window, and is visible in the client's verification records. We rate it High because the
product's stated threat model ("neither the gateway nor any other intermediary can read them") puts the
gateway operator in scope, and for that attacker no new artifact, key or repository change is needed. For
a purely external attacker it is Medium. The substitution is silent but not invisible: `tinfoil-proxy`'s
`/verifications` endpoint (and `Gateway.Verifications()`) shows `reference:
tinfoilsh/confidential-ubuntu-tinfoil-config`; nothing flags it.

## Technical details

All references are to tinfoil-go `ef79d8e` unless noted.

1. `gateway_catalog.go:17`: `trustedRepoOwner = "tinfoilsh/"`. `gateway_catalog.go:43,47-50`:
   `FetchCatalog` deletes only entries that fail
   ```go
   return err == nil && repo == e.Repo && strings.HasPrefix(repo, trustedRepoOwner) && len(e.Hosts) > 0
   ```
2. `seal_transport.go:73-88`: `gatewayPolicy.resolve` returns `replica{ref: entry.Repo}` for any model
   without a `ModelPin` (line 88). Pinned models are checked against the pin (lines 82-86).
3. `gateway.go:79-82`: `enclave.NewHandle(r.host, r.ref, &policy.defaults)` then `.ViaRelay(base.Host)`.
4. `enclave/verify.go:38`: `s.verifier.VerifyV3(docBytes, nonce, s.repo)` with the catalog repo.
5. `verify/internal/provenance/provenance.go:121-131`: `signingIdentity(repo)` accepts any workflow file
   of that repo on any `refs/tags/*`. `freshness.go:50-78`: any control-plane witness for that artifact
   younger than 7 days. Nothing checks the workload role, `cvm_admin`, or an allow-list of inference repos.
6. `verify/verifier.go:138-154`: after reference values, the quote layer (`quote.Authenticate`,
   `quote.Assemble`) checks machine policy, chip ID, launch measurement, VM shape and REPORT_DATA. None
   of these depend on the repo. A real dev box produces a quote that matches its own measurement.

Shipped consumer versions have the same logic:
- `tinfoil-go v0.16.1/seal_transport.go:79` (prefix filter) and `:271` (`replica{ref: entry.Repo}`);
  `tinfoil-proxy/main.go:50-51` (`--pin`, `--pinned-only` default off), `proxy.go:134` (`NewGateway`),
  `README.md:103` ("Pinning is off by default").
- `tinfoil-go v0.15.8-...ff60af7e9ea6/seal_transport.go:75`: `return strings.HasPrefix(e.Repo,
  trustedRepoOwner) && len(e.Hosts) > 0` (no bare-slug check); `confidential-openai-adapter/main.go:45`
  calls `NewGateway` and that tinfoil-go version has no `ModelPins`, so the adapter cannot pin.

## Proof of concept

`poc/` holds three Go test files, the four public Sigstore bundles they need (`poc/data/`, downloaded from
GitHub's public release-attestation API; ~62 KB), and `run.sh`. `run.sh` clones the local pristine
tinfoil-go at `ef79d8e`, drops the tests in, and runs them. No network access is needed beyond the Go
module cache. Nothing in tinfoil-go is modified.

```
cd poc && ./run.sh        # optional: TINFOIL_GO_SRC=<tinfoil-go checkout>, WORK=<build dir>
```

Clock: the dev-box witness expires 2026-10-14T18:03:26Z. `run.sh` pins the appraisal clock with
`POC_NOW=2026-10-11T12:00:00Z` (tests A and C pass it to the shipped freshness check; test C sets the
verifier's `now`). With `POC_NOW=2026-10-15T00:00:00Z` test A fails with `freshness witness is stale`, as
expected; a real attack after that date needs the next witness, which Tinfoil has been issuing every few days.

- **Test A** (`verify/internal/provenance`): the public dev-box release passes `AuthenticateCode` and
  `AuthenticateFreshness` for its own repo name. Control: same bundle with
  repo=`tinfoilsh/confidential-model-router` is rejected (SAN mismatch).
- **Test B** (root package): a loopback HTTPS gateway serves
  `{"llama3-3-70b": {"repo": "tinfoilsh/confidential-ubuntu-tinfoil-config", "hosts": [...]}}`.
  `FetchCatalog` keeps it, default `resolve` returns it, `NewGateway(...).Serves(model)` is true.
  Controls: a `someone-else/evil` entry is dropped; with a `ModelPin` the substitution is rejected.
- **Test C** (`verify`): a nonce-bound v3 document carrying the public dev-box code bundle,
  platform-endorsements v0.0.17 and both witnesses goes through the shipped `verifyV3`. It is accepted by
  envelope, provenance and both freshness checks, and rejected only at layer `quote`. Control: the same
  document with repo=`confidential-model-router` is rejected at layer `provenance`.

Expected output (excerpt, from the run on 2026-10-11; full log in `poc/expected-output.txt`):

```
ACCEPTED code artifact: repo=tinfoilsh/confidential-ubuntu-tinfoil-config tag=v0.1.1 commit=77c9e646f8535abed7f5a8aa928a10414a6e5bc7
  signed measured config: cvm_admin: true
  signed measured config: ports: ["22:22"]
  signed measured config: upstream-port: 22
  signed measured config: authenticated: false
  freshness witness ACCEPTED: witnessed 2026-10-07T18:03:26Z, valid until 2026-10-14T18:03:26Z, POC_NOW 2026-10-11T12:00:00Z
  control: repo=tinfoilsh/confidential-model-router REJECTED: ... expected SAN value to match regex "^https://github\.com/tinfoilsh/confidential-model-router/..."
FetchCatalog kept llama3-3-70b -> repo=tinfoilsh/confidential-ubuntu-tinfoil-config hosts=[devbox.example.internal]
default policy resolve(llama3-3-70b): replica.ref="tinfoilsh/confidential-ubuntu-tinfoil-config" (the repo VerifyV3 will trust)
NewGateway accepted catalog; Serves(llama3-3-70b)=true; enclave handle host=devbox.example.internal repo=tinfoilsh/confidential-ubuntu-tinfoil-config
  control: with a ModelPin the substitution is REJECTED: attestation error: model "llama3-3-70b": expected repository "tinfoilsh/confidential-model-router", gateway offered "tinfoilsh/confidential-ubuntu-tinfoil-config"
reference values ACCEPTED for repo=tinfoilsh/confidential-ubuntu-tinfoil-config tag=v0.1.1 ...; platform-endorsements v0.0.17 (17 machines); FreshnessExpiresAt=2026-10-14T18:03:26Z
verifyV3(repo=tinfoilsh/confidential-ubuntu-tinfoil-config): rejected only at layer="quote" (placeholder quote): attestation error: no amd-vcek endorsement collateral for the cpu
  control verifyV3(repo=tinfoilsh/confidential-model-router): rejected at layer="provenance": ...
--- PASS (all three tests)
```

Limitation (stated plainly): the hardware-quote layer was not and cannot be exercised here. Test C uses a
placeholder quote; a genuine SEV-SNP/TDX quote with the dev box's launch measurement can only be produced
by the dev-box CVM on endorsed hardware, i.e. by its operator. The claim that a real dev box passes that
layer rests on code reading: the quote/policy layer (`verify/verifier.go:143-154`, `quote.Assemble`)
compares the quote against the code measurement from step 5 and the platform policy, and has no input
that identifies the workload role. The verifiable end-to-end chain stops there.

Stubs: the loopback gateway's certificate is added to `http.DefaultTransport`'s roots (stands in for the
real gateway's WebPKI certificate); the dev-box host name is fictitious and never contacted.

Original evidence (hunter + three reviewer reproductions, including a reviewer's end-to-end
`NewGateway` → POST test that also stops only at the quote layer):
`/root/tinfoil-security-findings/gateway-catalog-any-repo/evidence/`.

## Impact

A user of tinfoil-proxy (default settings) or confidential-openai-adapter who sends a request for
`llama3-3-70b` gets a normal-looking answer and a successful verification record, while the request
plaintext was decrypted in a CVM whose administrator is a Tinfoil staff member, not in the attested
inference enclave. No error is raised, no new transparency-log artifact is created, and the only trace is
the repo name in the client's verification records.

### Affected downstream packages

- `tinfoil-proxy` CLI, desktop app and container (tinfoil-go `v0.16.1`; pinning off by default)
- `confidential-openai-adapter` (tinfoil-go `v0.15.8-0.20260924012310-ff60af7e9ea6`; no pinning support)

## Remediation

1. Do not let the catalog choose the repository. Ship a client-side allow-list of inference repositories
   per model, or accept only a catalog signed under a pinned Sigstore identity.
2. Make `--pinned-only` (with a built-in default pin set) the default in tinfoil-proxy; add `ModelPins`
   support to confidential-openai-adapter by upgrading tinfoil-go.
3. In the verifier, reject code artifacts whose signed measured config declares `cvm_admin`, a debug
   toolbox, or an unauthenticated upstream, unless the caller opts in. Or add a signed `role: inference`
   predicate field that gateway clients require.
4. Stop issuing freshness witnesses for non-inference repositories under the same witness identity, or
   use a separate identity for them.
5. Surface the verified repo in the desktop UI and warn when it is not the expected inference repo.

A local fix was not validated. The PoC's `ModelPin` control shows that the existing pin path already
blocks the substitution, so (1)/(2) close it for proxy and adapter users.

## References

- REPORT.md Finding 7; evidence `gateway-catalog-any-repo/`.
- Related transport findings that also involve the gateway position: Finding 1 (EHBP plaintext retry),
  Finding 4 (forged responses). This finding is independent of them and works with a fixed EHBP.
- `tinfoilsh/freshness-witness` README ("active repository set from its container database"): no role filter.
- `tinfoilsh/tinfoil-config` README and cvmimage `docs/runtime-policy.md`: `cvm_admin` semantics.
