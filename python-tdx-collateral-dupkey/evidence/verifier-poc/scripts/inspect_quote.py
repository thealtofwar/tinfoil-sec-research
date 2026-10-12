import sys, datetime as _dt
import tinfoil.attestation.cert_utils as cu
import tinfoil.attestation.collateral_tdx as ct
from tinfoil.attestation.abi_tdx import parse_quote
from tinfoil.attestation.verify_tdx import verify_tdx_quote
from tinfoil.attestation.pck_extensions import extract_pck_extensions
FROZEN = _dt.datetime(2023, 6, 30, tzinfo=_dt.timezone.utc)
class F(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)
cu.datetime = F; ct.datetime = F
raw = open(sys.argv[1], "rb").read()
q = parse_quote(raw)
b = q.td_quote_body
print("tee_tcb_svn", b.tee_tcb_svn.hex(), "mr_seam", b.mr_seam.hex()[:16], "mr_signer_seam", b.mr_signer_seam.hex()[:16], "seam_attr", b.seam_attributes.hex())
print("td_attributes", b.td_attributes.hex(), "xfam", b.xfam.hex())
qe = q.signed_data.certification_data.qe_report_data.qe_report_parsed
print("QE: mrsigner", qe.mr_signer.hex(), "isvprodid", qe.isv_prod_id, "isvsvn", qe.isv_svn, "attrs", qe.attributes.hex(), "miscselect", qe.misc_select)
chain = verify_tdx_quote(q, raw)
print("verify_tdx_quote: OK (real Intel PCK chain + QE report sig + AK binding + quote sig)")
pc = chain.pck_cert
print("PCK subject", pc.subject.rfc4514_string(), "issuer", pc.issuer.rfc4514_string())
print("PCK validity", pc.not_valid_before_utc, "->", pc.not_valid_after_utc)
e = extract_pck_extensions(pc)
print("fmspc", e.fmspc, "pceid", e.pceid, "pcesvn", e.tcb.pce_svn, "cpusvn", list(e.tcb.cpu_svn))
