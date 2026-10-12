# confidential-model-router sends METRICS_API_KEY to model enclaves over unpinned (WebPKI-only) TLS

| | |
|---|---|
| Component | `github.com/tinfoilsh/confidential-model-router`: HEAD `6494b7d` (2026-10-06) |
| Severity | Low-Medium (CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` = 3.7 for a metrics-only key; `C:H` = 5.9 if the key has broader admin scope, which we could not verify) |
| Bug class | CWE-295 (Improper Certificate Validation: missing pin), CWE-522 (Insufficiently Protected Credentials) |
| Attacker position | A TLS peer on the router's egress path to a model-enclave hostname that holds any WebPKI-valid certificate for that hostname. Realistically, the enclave's host or cloud operator |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary
The router polls each model enclave's `/metrics` endpoint once a second and sends
`Authorization: Bearer <METRICS_API_KEY>`. Every other router-to-enclave hop is pinned to the enclave's
attested TLS key with `TLSBoundRoundTripper`. The metrics poller uses a plain `http.Client` with the default
transport, so it accepts any certificate a public CA has issued for the hostname. A party that can intercept
the router's connection to an enclave hostname and present such a certificate receives the key every second.
The host operator of a GPU machine is the typical example: it controls the enclave's IP and can usually pass
ACME HTTP-01 or TLS-ALPN-01 for the name. The router itself calls this an "admin API key". Its real
permission scope lives in Tinfoil's closed control plane.

## Threat model
Tinfoil's model: the router is an attested enclave that talks only to attested model enclaves, and the
operators of GPU hosts are not trusted. The router enforces this for inference, files and other enclave
calls by pinning the attested TLS key. `manager/proxy.go:188`, `manager/http_client.go:56` and
`manager/file_inputs.go:177` all use `tinfoilClient.TLSBoundRoundTripper{ExpectedPublicKey: ...}`. The
metrics poller is the one exception.

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Production router with overload polling enabled; host or cloud operator of a model enclave | On-path position for the router's connections to that enclave's hostname (DNAT on the host), plus a WebPKI certificate for the hostname (ACME HTTP-01 or TLS-ALPN-01 against the IP it controls) | Yes, unless CAA `validationmethods`/`accounturi` restrict issuance | Receives `METRICS_API_KEY` once per second |
| Same, CA mis-issuance or DNS/BGP hijack plus a certificate | Certificate and route | Yes | Same |
| Plain network attacker without a trusted certificate | Network path | No | TLS validation fails |
| Router with no model carrying `overload.max_requests_waiting > 0` | n/a | No | The poller never starts |
| Inference, file and other enclave hops | n/a | No | Pinned; the PoC control shows `certificate fingerprint mismatch` and 502 |

Verified in code:
- `tinfoil-config.yml:22` provisions `METRICS_API_KEY` as a router secret.
- `main.go:225` describes the flag as an "admin API key sent as a bearer token when polling enclave
  /metrics"; `main.go:487-491` installs it.
- `manager/metrics.go:56-64` builds the client without a transport. `:152-165` sets the bearer and calls
  `m.client.Do`.
- `manager/manager.go:330-339` (`addEnclave`) has `verification.TLSPublicKeyFP` available but passes it only
  to `newProxy`.
- `cvmimage/tinfoil/cmd/shim/api.go:88-90` says the control plane has an "admin-key requirement for
  /metrics".

Unverified production facts (no production system was contacted):
- Whether the live router config from api.tinfoil.sh carries overload blocks that start the poller. The
  feature, the secret provisioning and the comment "enclaves require an admin key" (`metrics.go:26-27`)
  suggest it does.
- The permission scope of the real `METRICS_API_KEY`: metrics-only, or a broader `admin_` organisation key.
  This alone decides between Low and Medium-High.
- Whether the same value is also used as the CVM-level `METRICS_API_KEY` that gates `/.well-known/metrics`
  (`cvmimage/tinfoil/internal/metrics/metrics.go:142`). If it is, the key reads metrics on every CVM.
- The CAA/ACME posture of enclave hostnames, and whether model-enclave hosts are run by parties other
  than Tinfoil.

Out of scope / not affected: user prompts and responses (they use pinned hops and EHBP). The secondary
effect in the PoC is that the attacker's fake metrics can set the router's overload flag for that enclave.
That is not an escalation, because the host operator can already deny service to its own enclave.

## Severity
- Metrics-only key (the lower bound we can verify): `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` = **3.7**.
- Key with broader admin permissions (unverified): `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = **5.9**.
  One verifier gave an upper bound of `S:C/C:H/I:H/A:H` = 8.0 if it is a full organisation admin key.

Verifiers split 2/3. The code reviewer rated it Medium if the key is broad and Low if it is metrics-only. The
PoC reviewer rated it Medium (5.0-6.4). The impact reviewer refuted it as Low, because only an operational
credential is exposed and its scope is unknown. We report **Low-Medium**. The pin gap is certain and easy to
fix. The consequence depends on a control-plane fact that only Tinfoil can check.

## Technical details
`manager/metrics.go:56-64`:

```go
func newEnclaveMetrics(host, model string) *enclaveMetrics {
	return &enclaveMetrics{
		host:  host,
		model: model,
		client: &http.Client{
			Timeout: 5 * time.Second,      // default transport: WebPKI only, no pin
		},
	}
}
```

`manager/metrics.go:152-165`:

```go
req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/metrics", m.host), nil)
...
if key, _ := pollAPIKey.Load().(string); key != "" {
	req.Header.Set("Authorization", "Bearer "+key)
}
resp, err := m.client.Do(req)
```

Compare `manager/proxy.go:188`: `base: &tinfoilClient.TLSBoundRoundTripper{ExpectedPublicKey: tlsKeyFP}`.

## Proof of concept
`poc/run.sh` clones the local pristine router at `6494b7d` into `/root/tinfoil-review/work/disclosures/19/`. It
then:
- makes a stand-in CA and an attacker leaf certificate for `gpu-1.inf6.example` with openssl;
- drops in `poc_metrics_unpinned_test.go` plus a one-line helper (`poc_helper_unfixed.go` or
  `poc_helper_fixed.go`, chosen by build tag);
- runs the test with `SSL_CERT_FILE` set to the stand-in CA.

The test does the following:
- It starts a "genuine enclave" TLS server whose key fingerprint plays the attested `TLSPublicKeyFP`.
- It starts an attacker TLS server that holds the CA-issued certificate but not the attested key.
- It redirects dials of `gpu-1.inf6.example:443` to the attacker, as a host DNAT rule would.
- It builds the `Enclave` exactly as `addEnclave` does: a pinned `newProxy` and an unpinned
  `newEnclaveMetrics`, with an overload config that starts polling and `SetMetricsPollAPIKey(<canary>)`.
- Control: an inference request through the pinned proxy to the same host must fail closed.

```
cd poc && ./run.sh          # shipped code
cd poc && FIX=1 ./run.sh    # with fix-pin-metrics.patch, plus the full manager test suite
```

Output from the runs on 2026-10-11 (`poc/expected-output.txt`, `poc/expected-output-fixed.txt`):

```
level=error msg="proxy error" enclave=gpu-1.inf6.example error="certificate fingerprint mismatch" ... reason=tls_mismatch
poc_metrics_unpinned_test.go:167: control: proxied inference request through pinned transport -> HTTP 502 ...
poc_metrics_unpinned_test.go:176: attacker received 3 request(s)
poc_metrics_unpinned_test.go:179:   #0 path=/metrics authorization="Bearer tk_ADMIN_METRICS_API_KEY_SECRET_do_not_leak" ...
poc_metrics_unpinned_test.go:200: VULNERABLE: METRICS_API_KEY ("tk_ADMIN_METRICS_API_KEY_SECRET_do_not_leak") was sent to a TLS peer whose key (e7d2127d135c3c96...) is not the attested key (4beb407199ba1ae2...); the pinned proxy path to the same host failed closed (502)
--- FIX=1:
poc_metrics_unpinned_test.go:176: attacker received 0 request(s)
poc_metrics_unpinned_test.go:194: FIXED: pinned metrics poller sent nothing to the attacker (0 request(s) with the key)
full manager suite with the fix:
ok  	github.com/tinfoilsh/confidential-model-router/manager
```

What is simulated:
- The public CA is a stand-in trusted via `SSL_CERT_FILE`, standing for a certificate the attacker obtained
  for the real hostname.
- The on-path position is a dial override on `http.DefaultTransport`. Both the pinned and the unpinned
  clients dial through it.
- Real `addEnclave` needs a genuine SEV-SNP/TDX attestation, so the `Enclave` struct is built by hand with
  the same fields as `manager.go:330-339`.
- The key is a canary.

Original evidence: `/root/tinfoil-security-findings/router-metrics-key-unpinned/`.

## Impact
A GPU host operator, or anyone who can get a certificate for an enclave hostname and intercept the
router's egress, obtains Tinfoil's `METRICS_API_KEY` and keeps receiving it. At minimum, they can read
vLLM metrics on model enclaves fleet-wide: queue depth, load and model usage patterns. There is no rotation
on exposure. If the key is a broader admin key, as `main.go:225` suggests, the exposure covers whatever
that key authorises in the control plane. No user prompt or response is exposed.

## Remediation
- Pin the scrape to the attested key. Pass `verification.TLSPublicKeyFP` into `newEnclaveMetrics` and use
  `&tinfoilClient.TLSBoundRoundTripper{ExpectedPublicKey: tlsKeyFP}` as its transport.
  `poc/fix-pin-metrics.patch` does this, and also updates `localharness.go` and the four existing test call
  sites. It was validated locally: the PoC shows 0 requests reach the attacker, and
  `go test ./manager/` passes.
- Scope `METRICS_API_KEY` to metrics read only, if it is not already, and rotate it after fixing.
- Defence-in-depth: set CAA `validationmethods=dns-01` and `accounturi` on the enclave domains, so host
  operators cannot obtain certificates for enclave hostnames.

## References
- REPORT.md, "Lower-severity and informational items", first bullet; evidence
  `/root/tinfoil-security-findings/router-metrics-key-unpinned/`.
- Verifier verdicts: `verification-verdicts-round2.json`, key `router/router-metrics-poll-unpinned-admin-key`
  (2/3 upheld; one Low).
- Related pinned hops: `manager/proxy.go:188`, `manager/http_client.go:56`, `manager/file_inputs.go:177`.
