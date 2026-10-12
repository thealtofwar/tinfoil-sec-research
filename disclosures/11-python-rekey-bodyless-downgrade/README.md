# tinfoil-python resends a one-shot-body POST as an unencrypted, bodyless request after a forged key-rotation error, and accepts the forged plaintext 200

| | |
|---|---|
| Component | `tinfoil` on PyPI (https://pypi.org/project/tinfoil/): `0.14.0` (latest), when installed with `tinfoil-ehbp` `0.4.0` (the default resolution); not exploitable with `tinfoil-ehbp` `0.3.x` |
| Severity | Medium (CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` = 5.9 for the proxy / gateway topology) |
| Bug class | CWE-345 (insufficient verification of data authenticity); a sealed exchange is silently downgraded to an unsealed one (CWE-757-like) |
| Attacker position | The client's TLS peer: a `base_url=` proxy or gateway (by design), or in direct mode an on-path party holding a WebPKI certificate for the enclave hostname |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary

When the EHBP transport reports a key-configuration mismatch (HTTP 422 `application/problem+json`),
tinfoil-python re-attests and retries with the same `httpx.Request` object. If the request body is a
one-shot stream (a file object, `io.BytesIO`, a plain iterator, or a non-generator async iterable), the
first, encrypted attempt has already consumed it. `tinfoil-ehbp` 0.4.0 decides whether a request has a
body only by peeking the stream, so it sends the retry with no body, no `Ehbp-Encapsulated-Key`, and
returns the response without any nonce check. The 422 is unauthenticated plaintext, so the TLS peer can
forge it, then answer the bodyless retry with a forged plaintext `200`. The application receives that
`200` as the enclave's authenticated answer to its sealed POST, and its real request is never delivered.
No plaintext is leaked. Exposure is limited to callers of the documented general-purpose
`make_secure_http_client()` / `make_secure_async_http_client()` clients that pass one-shot bodies; the
`TinfoilAI` / OpenAI SDK JSON path is not affected.

## Threat model

What is promised:

- `tinfoil/client.py` (wheel lines 408-410), `_EHBPReVerifyingTransport` docstring: "The mismatch is
  reported before the request is processed, so it is safe to rebuild the transport from the freshly
  attested key and retry the request once."
- `make_secure_http_client()` docstring (wheel lines 765-773): "request bodies are encrypted end-to-end
  with the enclave's attested HPKE public key ... if the enclave rotates its key ... the underlying
  transport automatically re-verifies attestation and retries the request once."
- EHBP `SPEC.md:222-228` (section 5.4.3): after a 422 the client should "Re-send the original request".
  `SPEC.md:185` (section 5.3): "exchanges that claim success always fail closed without a valid nonce."

Who can exploit it:

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| `SecureClient(base_url=proxy_or_gateway)` + `make_secure_http_client()` / async, one-shot body | Be the proxy or gateway operator (TLS peer by design) | Yes | Forged `200` body returned as the answer; real request dropped |
| Default direct mode (no `base_url`), one-shot body | A WebPKI certificate for the enclave hostname plus an on-path position (EHBP mode's inner transport is an unpinned `httpx.HTTPTransport()`, wheel line 735) | Yes, higher complexity | Same |
| Same, body is `bytes` / `str` / `json=` / form data / seekable multipart | - | No: the retry is re-encrypted and the forged `200` fails with `MissingResponseNonceError` | - |
| `TinfoilAI` / `AsyncTinfoilAI` (OpenAI SDK) chat, embeddings, seekable audio upload | - | No (verified for chat here; multipart by a reviewer) | - |
| Body is a generator / async generator | - | No: httpx raises `StreamConsumed` (fails closed) | - |
| `transport="tls"` | - | No (TLS pinned to the attested key) | - |
| `tinfoil-ehbp` 0.3.0-0.3.2 installed | - | No: that transport buffers the body with `request.read()`, so the retry is re-sealed (verified here with 0.3.2) | - |
| Network attacker without a trusted certificate | - | No | - |

Preconditions verified in code:

- The 422 trigger needs only status 422, `Content-Type: application/problem+json` and
  `"type": "urn:ietf:params:ehbp:error:key-config"` (`ehbp/_http.py:41-54`). Nothing is authenticated.
- Re-attestation succeeds, because a real attacker forwards the genuine attestation untouched (here it is
  stubbed; see below).
- The user-cache-secret wrapper forwards unread stream bodies unchanged, so it does not buffer them.

Unverified production facts (no production traffic was sent):

- Whether any customer application passes one-shot bodies through the raw secure httpx client. A grep over
  all public Tinfoil repositories found no first-party code that does.
- How many Python SDK users run with `base_url=` (proxy or gateway) versus the default direct mode.
- Whether the production gateway or enclaves ever emit a genuine 422 key-config error. This does not
  affect exploitability, since any TLS peer can forge one.

Not affected (by mechanism): tinfoil-go refuses the retry when `GetBody` is nil (`recovery_transport.go:63-65`);
JS (undici throws on a consumed stream), Rust (rebuilds the request from a factory) and Swift (replays the
`Data` body) were reported unaffected by the hunter; only the Go claim was independently re-checked.

## Severity

- Proxy / gateway topology: `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` = **5.9**. `AC:H` because exploitation
  depends on the application choosing a one-shot body shape on the raw httpx surface, which the attacker
  does not control. The attacker itself needs nothing beyond its normal position.
- Direct mode: same vector, **5.9**, realistically lower, since a trusted certificate for the enclave
  hostname plus an on-path position is also required.

All three reviewers upheld the finding at Medium (confidence 0.7-0.9). The impact reviewer called it a
"low-end Medium": every shipped Tinfoil Python surface (`TinfoilAI`, `AsyncTinfoilAI`, `NewSecureClient`,
`SecureClient.post(body: bytes)`) is unaffected, and a triager who weighs that as decisive could rate it
Low. It is kept at Medium because it is silent, cheap for the attacker, reproduced on the shipped wheels
through the public API, and breaks the SDK's documented retry-safety promise. Integrity only.

## Technical details

`tinfoil` 0.14.0 `tinfoil/client.py` (wheel line numbers; HEAD `00fe2fe` is 4 lines lower:
class at 398, retry at 441 / 484):

```python
402 class _EHBPReVerifyingTransport(httpx.BaseTransport):
419     def handle_request(self, request: httpx.Request) -> httpx.Response:
420         inner = self._inner
421         try:
422             return inner.handle_request(request)          # first attempt consumes request.stream
423         except KeyConfigMismatchError:                     # forged 422 lands here
            ...
430                 retry_inner = self._secure_client._build_ehbp_sync_transport()   # re-attests
            ...
445                 return retry_inner.handle_request(request)  # SAME request, stream already exhausted
```

The async class (`_AsyncEHBPReVerifyingTransport`, line 455) does the same at line 488.

`tinfoil-ehbp` 0.4.0 `ehbp/transport.py`:

```python
170 def handle_request(self, request: httpx.Request) -> httpx.Response:
171     # The stream alone decides whether a body exists: headers are caller
172     # supplied, and trusting Content-Length: 0 forwarded a non-empty
173     # stream in plaintext. Peeking an empty stream costs nothing.
174     encrypted = self._identity.encrypt_request_stream(
175         cast(httpx.SyncByteStream, request.stream)
176     )
177     if encrypted is None:
178         return self._inner.handle_request(_bodyless_passthrough(request))   # no key, no nonce check
```

Async equivalent at lines 248-253. `encrypt_request_stream` (`ehbp/identity.py:255-266`) returns `None`
when `_first_nonempty` (`identity.py:109-115`) finds no bytes. httpx 0.28.1 only raises `StreamConsumed`
for generators; a file object or plain iterator simply yields nothing the second time.

The two components are each reasonable alone. tinfoil-python assumes the request can be replayed;
tinfoil-ehbp 0.4.0 (unlike 0.3.x, which called `request.read()`) treats an exhausted stream as "no body".
Together they turn a sealed POST into an unsealed bodyless one whose response is trusted.

## Proof of concept

Files in `poc/`:

- `poc_rekey_bodyless.py`: drives the public API. `SecureClient(enclave=..., measurement=...,
  transport="ehbp", base_url=<loopback peer>)` and `.make_secure_http_client()` /
  `.make_secure_async_http_client()`, plus `tinfoil.TinfoilAI(...)` for the OpenAI SDK control. The
  loopback peer answers request 1 with the forged 422 and request 2 with a forged plaintext `200`. It
  never holds the HPKE private key.
- `run.sh`: downloads the PyPI wheels and prints their sha256, builds venvs under `$WORK` (default
  `/root/tinfoil-review/work/disclosures/11`), and runs the script three times:
  1. `tinfoil==0.14.0` + `tinfoil-ehbp==0.4.0`, unmodified (expect vulnerable);
  2. the same wheels with a 2-line fix in `_EHBPReVerifyingTransport` and its async twin (expect fixed);
  3. `tinfoil==0.14.0` + `tinfoil-ehbp==0.3.2`, unmodified (version-bound check, expect not exploitable).

Prerequisites: Python 3 (tested with 3.14.4), network access to PyPI. Run: `cd poc && ./run.sh`.
Optionally set `HOME` to a scratch directory so the SDK's auto-generated `~/.tinfoil/user_cache_secret`
is not written to your real home.

Key output (full run in `poc/expected-output.txt`):

```
f04e1c0ed98e22619c03e6fc8b9a2cab60a4e9ed2001ffec58ab5cd848d77642  tinfoil-0.14.0-py3-none-any.whl
e65b09e2526741bce07ae013fcf4e9b28347fad590d7a002a1f5b1254ccdece7  tinfoil_ehbp-0.4.0-py3-none-any.whl
##### shipped wheels, expect=vulnerable
=== control  content=bytes
  peer saw request {'n': 2, 'ehbp_key': True, 'content_length': None, 'body_len': 155, 'canary_visible': False}
  verify() calls: 2; client outcome: raised MissingResponseNonceError: MISSING_RESPONSE_NONCE: missing Ehbp-Response-Nonce header
=== control  OpenAI SDK chat via TinfoilAI
  peer saw request {'n': 2, 'ehbp_key': True, ... 'body_len': 149, ...}
  verify() calls: 2; client outcome: raised MissingResponseNonceError: ...
=== attack   content=open(file,'rb')
  peer saw request {'n': 1, 'ehbp_key': True, 'content_length': None, 'body_len': 108, 'canary_visible': False}
  peer saw request {'n': 2, 'ehbp_key': False, 'content_length': '0', 'body_len': 0, 'canary_visible': False}
  verify() calls: 2; client outcome: status=200 body='{"id": "forged", "object": "chat.completion", ...
  VULNERABLE: retry went out unencrypted and bodyless; forged plaintext 200 accepted
(same for io.BytesIO(...), iter([...]) and the async non-generator async iterable)
RESULT: as expected (POC_EXPECT=vulnerable)
##### patched wheels, expect=fixed
=== attack   content=open(file,'rb')
  verify() calls: 2; client outcome: raised KeyConfigMismatchError: KEY_CONFIG_MISMATCH: stale key
RESULT: as expected (POC_EXPECT=fixed)
##### tinfoil 0.14.0 + tinfoil-ehbp 0.3.2 (unpatched), expect=fixed
=== attack   content=open(file,'rb')
  peer saw request {'n': 2, 'ehbp_key': True, 'content_length': None, 'body_len': 108, 'canary_visible': False}
  verify() calls: 2; client outcome: raised ProtocolError: missing Ehbp-Response-Nonce header
RESULT: as expected (POC_EXPECT=fixed)
```

`canary_visible: False` on every request: the prompt never reaches the peer in plaintext.

What is stubbed: only `SecureClient.verify()`, replaced by a function that returns
`GroundTruth(hpke_public_key=<genuine X25519 public key>)`, which is what a successful attestation hands
over. The SecureClient constructor, the wrapper chain (`_HostBoundTransport` ->
`_EnclaveURLHeaderTransport` -> `_UserCacheSecretTransport` -> `_EHBPReVerifyingTransport` ->
`EHBPTransport` -> `httpx.HTTPTransport`), tinfoil-ehbp and httpx are the shipped wheel code. The peer
speaks plain HTTP on loopback (`base_url` accepts `http://`); for a TLS-terminating peer this is
equivalent, because EHBP mode does no TLS pinning. A reviewer reproduced the same result in direct mode
over loopback TLS with a client-trusted certificate.

Full original evidence (hunter scripts and logs, including the async and OpenAI-SDK bounding scripts):
`/root/tinfoil-security-findings/python-rekey-bodyless-downgrade/evidence/`.

## Impact

An application that uploads a file or streams a body through the secure client can be handed an
attacker-chosen response (any JSON or text) that it believes came from the attested enclave, while its
real request is silently dropped. The attacker never sees the request. For example, a document-processing
or transcription integration that streams a file through `make_secure_http_client()` and parses the
result would accept a fabricated result.

## Remediation

1. tinfoil-python: retry after `KeyConfigMismatchError` only when the request body is replayable, else
   re-raise, mirroring tinfoil-go's "cannot retry request after key rotation: body is not replayable".
   The PoC's fix control used, in both the sync and async classes:
   ```python
   if not isinstance(request.stream, httpx.ByteStream):
       raise  # one-shot body already consumed; never resend it bodyless
   ```
   This is a minimal fix that fails closed. It also refuses replayable multipart streams; a production fix
   should allow those, or buffer the body (`request.read()`) before the first attempt when it is small. It
   should also run the check before re-attesting.
2. tinfoil-ehbp: never fall back to the bodyless pass-through for a request that was meant to carry a
   body. For example, if the stream yields nothing but the request declares one (`Transfer-Encoding`, or
   `Content-Length` > 0), raise instead of sending a bodyless request.
3. Defence in depth: on a bodyless pass-through, refuse a nonce-less 2xx when the request method normally
   carries a body (POST/PUT/PATCH).

## References

- Finding 4 (`04-ehbp-go-3xx-response-forgery`): same class in Go (sealed POST turned into an unsealed GET
  by a 303), different mechanism. REPORT.md lists tinfoil-python as unaffected by that one, which remains
  correct.
- Finding 1 (`01-ehbp-go-http2-retry-plaintext`): Go client retry below the encryption layer
  (confidentiality).
- EHBP `SPEC.md` sections 5.3, 5.4.3 and 7.4.
- REPORT.md section "Finding 11"; verifier verdicts `verification-verdicts-round2.json` key
  `ehbp-cross-language/python-rekey-retry-bodyless-downgrade`.
