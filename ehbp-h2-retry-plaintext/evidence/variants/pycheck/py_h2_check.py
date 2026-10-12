"""Local-only: run the EHBP Python transport (repo HEAD) over an HTTP/2 inner
transport against the standalone attacker that refuses / GOAWAYs the first
stream. Report whether any plaintext body reached the attacker."""
import json, os, ssl, subprocess, sys, time
sys.path.insert(0, "/root/.claude/jobs/632f70ea/tmp/repos/encrypted-http-body-protocol/python/src")
import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import ehbp
from ehbp.identity import ServerIdentity

ATT = sys.argv[1]
WORK = os.path.dirname(os.path.abspath(__file__))
SECRET = b'{"model":"m","messages":[{"role":"user","content":"PY-SECRET SSN 078-05-1120"}]}'

def run(mode):
    ca = os.path.join(WORK, f"ca-{mode}.pem")
    p = subprocess.Popen([ATT, "-mode", mode, "-count", "1", "-ca", ca], stdout=subprocess.PIPE, text=True)
    addr = json.loads(p.stdout.readline())["listen"]
    pub = X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    inner = httpx.HTTPTransport(http2=True, verify=ssl.create_default_context(cafile=ca), retries=3)
    t = ehbp.EHBPTransport(ServerIdentity.from_public_key_hex(pub), inner=inner)
    c = httpx.Client(transport=t)
    try:
        r = c.post(f"https://{addr}/v1/chat/completions", content=SECRET, headers={"content-type": "application/json"})
        res = f"status={r.status_code} http={r.http_version}"
    except Exception as e:
        res = f"error={type(e).__name__}: {e}"
    time.sleep(0.3)
    p.terminate()
    out = p.stdout.read()
    caps = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    leaked = any("078-05-1120" in x["body"] for x in caps)
    print(f"[python ehbp, inner http2, attacker mode={mode}] client: {res}")
    for x in caps:
        print(f"   capture n={x['n']} stream={x['stream']} key={x['ehbp_key'][:16]}.. plaintext={'078-05-1120' in x['body']} len={len(x['body'])}")
    print(f"   RESULT leaked_plaintext={leaked}")

for m in ("refuse", "goaway"):
    run(m)
