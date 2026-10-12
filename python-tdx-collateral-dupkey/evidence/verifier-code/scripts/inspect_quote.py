import json, sys, os
from tinfoil.attestation.abi_tdx import parse_quote
from tinfoil.attestation.verify_tdx import extract_pck_cert_chain
from tinfoil.attestation.pck_extensions import extract_pck_extensions
from cryptography import x509
D = sys.argv[1]
raw = open(os.path.join(D, "quote.dat"), "rb").read()
q = parse_quote(raw)
b = q.td_quote_body
print("tee_tcb_svn   =", b.tee_tcb_svn.hex())
print("mr_seam       =", b.mr_seam.hex())
print("mr_signer_seam=", b.mr_signer_seam.hex())
print("seam_attrs    =", b.seam_attributes.hex())
print("td_attributes =", b.td_attributes.hex())
print("xfam          =", b.xfam.hex())
print("report_data   =", b.report_data.hex()[:64], "...")
ch = extract_pck_cert_chain(q)
for c in (ch.pck_cert, ch.intermediate_cert, ch.root_cert):
    print("cert:", c.subject.rfc4514_string(), "| valid", c.not_valid_before_utc, "->", c.not_valid_after_utc, "| serial", hex(c.serial_number))
ext = extract_pck_extensions(ch.pck_cert)
print("fmspc", ext.fmspc, "pceid", ext.pceid, "pcesvn", ext.tcb.pce_svn, "cpusvn", ext.tcb.cpu_svn.hex())
qe = q.signed_data.certification_data.qe_report_data.qe_report_parsed
print("QE report: mrsigner", qe.mr_signer.hex(), "isvprodid", qe.isv_prod_id, "isvsvn", qe.isv_svn, "attrs", qe.attributes.hex(), "miscselect", qe.misc_select)
tcb = json.loads(open(os.path.join(D, "tcb_info.json"), "rb").read())["tcbInfo"]
print("TCB info issue", tcb["issueDate"], "next", tcb["nextUpdate"], "evalnum", tcb["tcbEvaluationDataNumber"])
for lvl in tcb["tcbLevels"]:
    t = lvl["tcb"]
    print("  level", lvl["tcbStatus"], "pcesvn", t["pcesvn"], "sgx", [c["svn"] for c in t["sgxtcbcomponents"]], "tdx", [c["svn"] for c in t["tdxtcbcomponents"]])
for mi in tcb.get("tdxModuleIdentities", []):
    print("  module", mi["id"], [(l["tcb"].get("isvsvn"), l["tcbStatus"]) for l in mi["tcbLevels"]])
qei = json.loads(open(os.path.join(D, "qe_identity.json"), "rb").read())["enclaveIdentity"]
print("QE identity issue", qei["issueDate"], "next", qei["nextUpdate"], "evalnum", qei["tcbEvaluationDataNumber"], "levels", [(l["tcb"]["isvsvn"], l["tcbStatus"]) for l in qei["tcbLevels"]])
for name in ("pckcrl.der", "rootcrl.der"):
    crl = x509.load_der_x509_crl(open(os.path.join(D, name), "rb").read())
    print(name, "issuer", crl.issuer.rfc4514_string(), "last", crl.last_update_utc, "next", crl.next_update_utc, "revoked count", len(list(crl)))
from tinfoil.attestation.collateral_tdx import _parse_issuer_chain_header
for name in ("qeIdentityIssuerChain.txt", "pckCrlIssuerChain.txt"):
    for c in _parse_issuer_chain_header(open(os.path.join(D, name)).read().strip()):
        print(name, c.subject.rfc4514_string(), c.not_valid_before_utc, "->", c.not_valid_after_utc)
