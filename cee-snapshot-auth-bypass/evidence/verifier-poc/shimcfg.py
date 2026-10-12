"""Emit a tfshim config whose `shim:` settings are taken verbatim from
code-execution-environment/tinfoil-config.yml. Only local-test knobs
(listen port, self-signed TLS, key/cache paths) are added on top; they are
printed separately so it is clear they do not come from the production file.

usage: python -I shimcfg.py <tinfoil-config.yml> <out shim.yml> <listen-port> <state-dir>
"""
import sys
import yaml

src, out, port, state = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
with open(src) as f:
    cfg = yaml.safe_load(f)
shim = dict(cfg["shim"])  # production block, unmodified
print("production shim block from", src, "->", shim)
local = {
    "listen-port": port,  # production default is 443
    "tls-mode": "self-signed",  # production default is cert-proxy (public CA cert)
    "hpke-key-file": state + "/hpke_key.json",
    "cache-dir": state + "/cache",
}
print("local-only additions ->", local)
for k in local:
    assert k not in shim, k
shim.update(local)
with open(out, "w") as f:
    yaml.safe_dump(shim, f, sort_keys=False)
