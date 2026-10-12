# PoC: router metrics poller sends METRICS_API_KEY over unpinned TLS

Component: confidential-model-router @ 6494b7d (2026-10-06), manager/metrics.go
`newEnclaveMetrics` (L56-64: `client: &http.Client{Timeout: 5s}`, default
WebPKI transport) and `scrape` (L152-163: `https://<enclave>/metrics` with
`Authorization: Bearer <METRICS_API_KEY>`).

Every other hop from the router to a model enclave uses
`tinfoilClient.TLSBoundRoundTripper{ExpectedPublicKey: <attested FP>}`
(manager/proxy.go:188, manager/http_client.go:56, manager/file_inputs.go:177).
The /metrics scrape is the one hop that is not bound to the attested key.

## Run

    ./run.sh

(generates a stand-in CA + leaf for gpu-1.inf6.example, copies the test into
the work copy of the router, runs it with SSL_CERT_FILE pointing at the CA.)

## Result (evidence/run.log)

- The pinned reverse-proxy request to the same host fails closed:
  `proxy error ... certificate fingerprint mismatch` -> HTTP 502.
- The metrics poller, within ~1s, delivers
  `Authorization: Bearer tk_ADMIN_METRICS_API_KEY_SECRET_do_not_leak`
  to the attacker's TLS server, whose key is not the attested one.
