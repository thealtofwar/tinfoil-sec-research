"""Causality check: same scenario D as PoC2, with collateral_tdx's json.loads replaced by a
duplicate-key-rejecting variant (candidate fix). Expect REJECT."""
import json as _json, sys, types, runpy
import tinfoil.attestation.collateral_tdx as ct

def _strict_hook(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _json.JSONDecodeError(f"duplicate key(s) {sorted({k for k in keys if keys.count(k) > 1})}", "", 0)
    return dict(pairs)

shim = types.SimpleNamespace(**{n: getattr(_json, n) for n in dir(_json) if not n.startswith("__")})
shim.loads = lambda s, **kw: _json.loads(s, object_pairs_hook=_strict_hook, **kw)
ct.json = shim
sys.argv = [sys.argv[0], sys.argv[1]]
g = runpy.run_path(sys.argv[0].replace("fixcheck.py", "poc2_e2e_document_verify.py"), run_name="not_main")
import copy, dataclasses, json, os, tempfile
q = g["parse_quote"](g["QUOTE"]); b = q.td_quote_body; at = g["at"]
cfg15 = dataclasses.replace(at.TdxVerificationConfig(), accepted_mr_seams=(b.mr_seam,), expected_td_attributes=b.td_attributes,
                            expected_xfam=b.xfam, expected_minimum_tee_tcb_svn=b.tee_tcb_svn, min_tcb_evaluation_data_number=15)
forged = copy.deepcopy(json.loads(g["GENUINE_TCB"])["tcbInfo"]); z = [{"svn": 0} for _ in range(16)]
forged.update(tcbEvaluationDataNumber=99, nextUpdate="2099-01-01T00:00:00Z",
              tcbLevels=[{"tcb": {"sgxtcbcomponents": z, "pcesvn": 0, "tdxtcbcomponents": z}, "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}],
              tdxModuleIdentities=[{"id": "TDX_00", "mrsigner": "00"*48, "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF",
                                    "tcbLevels": [{"tcb": {"isvsvn": 0}, "tcbDate": "2023-02-15T00:00:00Z", "tcbStatus": "UpToDate"}]}])
with tempfile.TemporaryDirectory() as d:
    print("== D with duplicate-rejecting json.loads in collateral_tdx (candidate fix)")
    g["run"]("D-fixed", g["append_duplicate"](g["GENUINE_TCB"], "tcbInfo", forged), g["GENUINE_QE"], cfg15, os.path.join(d, "x"))
