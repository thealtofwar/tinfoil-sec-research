"""
TCB-status decision flip on a REAL Intel platform quote (no PCK simulation).

Real data (google/go-tdx-guest v0.3.1 testdata): tdx_prod_quote_SPR_E4.dat with
its genuine Intel PCK chain, genuine QE (Intel TD_QE MRSIGNER), and genuine
Intel-signed TCB Info / QE Identity / CRLs.  Only the clock is frozen to
2023-06-30 (validity window of the captured collateral).

validate_collateral() is the production function verify_tdx_attestation() calls
(Step 5).  We call it directly because this 2023 quote predates Tinfoil's
MR_SEAM allow-list / minimum TEE_TCB_SVN policy (Step 4), which is unrelated
to collateral.
"""
import copy
import datetime as _dt
import json
import os
import sys
import tempfile
from unittest import mock

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import tinfoil.attestation.cert_utils as cu
import tinfoil.attestation.collateral_tdx as ct
from tinfoil.attestation.abi_tdx import parse_quote
from tinfoil.attestation.verify_tdx import verify_tdx_quote

DATA = sys.argv[1]
FROZEN = _dt.datetime(2023, 6, 30, tzinfo=_dt.timezone.utc)


class FrozenDateTime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)


cu.datetime = FrozenDateTime
ct.datetime = FrozenDateTime
rd = lambda n, m="rb": open(os.path.join(DATA, n), m).read()
GENUINE_QE, GENUINE_TCB = rd("qe_identity.json").rstrip(), rd("tcb_info.json").rstrip()
HDR = {k: rd(f, "r").strip() for k, f in [("qe", "qeIdentityIssuerChain.txt"), ("tcb", "tcbInfoIssuerChain.txt"),
                                          ("crl", "pckCrlIssuerChain.txt")]}
PCK_CRL_PEM = x509.load_der_x509_crl(rd("pckcrl.der")).public_bytes(serialization.Encoding.PEM)
RAW = rd("quote.dat")
quote = parse_quote(RAW)
pck_chain = verify_tdx_quote(quote, RAW)  # REAL PCK chain -> REAL pinned Intel root, real QE report sig
print("real quote: PCK chain + quote sig + QE report sig verified against the pinned Intel SGX Root CA")
print("  tee_tcb_svn", quote.td_quote_body.tee_tcb_svn.hex(), "| QE mrsigner",
      quote.signed_data.certification_data.qe_report_data.qe_report_parsed.mr_signer.hex()[:16], "(Intel TD_QE)")


def forged_tcb():
    t = copy.deepcopy(json.loads(GENUINE_TCB)["tcbInfo"])
    zero = lambda: [{"svn": 0} for _ in range(16)]
    t.update(tcbLevels=[{"tcb": {"sgxtcbcomponents": zero(), "pcesvn": 0, "tdxtcbcomponents": zero()},
                         "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}],
             tdxModuleIdentities=[{"id": "TDX_00", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                                   "attributesMask": "FFFFFFFFFFFFFFFF",
                                   "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z",
                                                  "tcbStatus": "UpToDate"}]}])
    return GENUINE_TCB[:-1] + b',"tcbInfo":' + json.dumps(t, separators=(",", ":")).encode() + b"}"


def net(tcb_body):
    def get(url, timeout=None, **kw):
        r = requests.Response(); r.status_code = 200; r.url = url
        if "/tdx/certification/v4/tcb?" in url:
            r._content = tcb_body; r.headers["TCB-Info-Issuer-Chain"] = HDR["tcb"]
        elif "/qe/identity?" in url:
            r._content = GENUINE_QE; r.headers["SGX-Enclave-Identity-Issuer-Chain"] = HDR["qe"]
        elif "/pckcrl?ca=platform" in url:
            r._content = PCK_CRL_PEM; r.headers["SGX-PCK-CRL-Issuer-Chain"] = HDR["crl"]
        elif url.endswith("IntelSGXRootCA.der"):
            r._content = rd("rootcrl.der")
        else:
            raise AssertionError(url)
        return r
    return get


for label, body in [("genuine Intel TCB Info", GENUINE_TCB), ("genuine Intel TCB Info + appended duplicate 'tcbInfo'", forged_tcb())]:
    with tempfile.TemporaryDirectory() as d, mock.patch.object(ct, "_TDX_CACHE_DIR", d), \
            mock.patch.object(requests, "get", net(body)):
        try:
            res = ct.validate_collateral(quote, pck_chain, min_tcb_evaluation_data_number=15)
            print(f"[ACCEPTED] {label}: platform TCB status = {res.tcb_level.tcb_status.value}")
        except ct.CollateralError as e:
            print(f"[REJECTED] {label}: {e}")
