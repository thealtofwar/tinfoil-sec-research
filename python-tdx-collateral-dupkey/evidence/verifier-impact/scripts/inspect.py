import json, sys, os
from cryptography import x509
from tinfoil.attestation.abi_tdx import parse_quote
from tinfoil.attestation.verify_tdx import extract_pck_cert_chain
from tinfoil.attestation.pck_extensions import extract_pck_extensions
from tinfoil.attestation import collateral_tdx as ct
D = sys.argv[1]
q = open(os.path.join(D, "quote.dat"), "rb").read()
quote = parse_quote(q)
b = quote.td_quote_body
print("tee_tcb_svn", b.tee_tcb_svn.hex()); print("mr_seam", b.mr_seam.hex()); print("td_attr", b.td_attributes.hex(), "xfam", b.xfam.hex(), "seam_attr", b.seam_attributes.hex())
qe = quote.signed_data.certification_data.qe_report_data.qe_report_parsed
print("QE mrsigner", qe.mr_signer.hex(), "isvprodid", qe.isv_prod_id, "isvsvn", qe.isv_svn, "attr", qe.attributes.hex(), "misc", qe.misc_select)
ch = extract_pck_cert_chain(quote)
for c in (ch.pck_cert, ch.intermediate_cert, ch.root_cert):
    print("cert", c.subject.rfc4514_string(), "| issuer", c.issuer.rfc4514_string(), "|", c.not_valid_before_utc, "->", c.not_valid_after_utc, "serial", hex(c.serial_number))
ext = extract_pck_extensions(ch.pck_cert)
print("PCK ext fmspc", ext.fmspc, "pceid", ext.pceid, "pcesvn", ext.tcb.pce_svn, "cpusvn", ext.tcb.cpu_svn.hex())
tcb = ct.parse_tcb_info_response(open(os.path.join(D, "tcb_info.json"), "rb").read()).tcb_info
print("TCBInfo fmspc", tcb.fmspc, "pceId", tcb.pce_id, "evalnum", tcb.tcb_evaluation_data_number, "issue", tcb.issue_date, "next", tcb.next_update)
for l in tcb.tcb_levels:
    print("  level", l.tcb_status.value, "sgx", [c.svn for c in l.tcb.sgx_tcb_components], "pce", l.tcb.pce_svn, "tdx", [c.svn for c in l.tcb.tdx_tcb_components], l.tcb_date)
for m in tcb.tdx_module_identities:
    print("  module", m.id, "mrsigner", m.mrsigner.hex()[:16], "levels", [(l.tcb.isv_svn, l.tcb_status.value) for l in m.tcb_levels])
qi = ct.parse_qe_identity_response(open(os.path.join(D, "qe_identity.json"), "rb").read()).enclave_identity
print("QEIdentity mrsigner", qi.mrsigner.hex(), "isvprodid", qi.isv_prod_id, "evalnum", qi.tcb_evaluation_data_number, "issue", qi.issue_date, "next", qi.next_update, "levels", [(l.tcb.isv_svn, l.tcb_status.value) for l in qi.tcb_levels])
pck = x509.load_der_x509_crl(open(os.path.join(D, "pckcrl.der"), "rb").read())
print("PCK CRL issuer", pck.issuer.rfc4514_string(), "last", pck.last_update_utc, "next", pck.next_update_utc, "revoked", len(list(pck)))
root = x509.load_der_x509_crl(open(os.path.join(D, "rootcrl.der"), "rb").read())
print("Root CRL last", root.last_update_utc, "next", root.next_update_utc, "revoked", [hex(r.serial_number) for r in root])
for name in ("qeIdentityIssuerChain.txt", "tcbInfoIssuerChain.txt", "pckCrlIssuerChain.txt"):
    chain = ct._parse_issuer_chain_header(open(os.path.join(D, name)).read().strip())
    print(name, [(c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, str(c.not_valid_before_utc.date()), str(c.not_valid_after_utc.date()), hex(c.serial_number)) for c in chain])
