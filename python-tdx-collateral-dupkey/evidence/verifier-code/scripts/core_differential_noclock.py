import json, os, sys
import tinfoil.attestation.collateral_tdx as ct
D = sys.argv[1]
qe = open(os.path.join(D, "qe_identity.json"), "rb").read().rstrip()
tcb = open(os.path.join(D, "tcb_info.json"), "rb").read().rstrip()
chain = ct._parse_issuer_chain_header(open(os.path.join(D, "qeIdentityIssuerChain.txt")).read().strip())
signer = chain[0]
def dup(g, key, obj):
    return g[:-1] + b',"' + key.encode() + b'":' + json.dumps(obj, separators=(",", ":")).encode() + b"}"
f = json.loads(qe)["enclaveIdentity"]; f["mrsigner"] = "41" * 32
mq = dup(qe, "enclaveIdentity", f)
p = ct.parse_qe_identity_response(mq)
ct._verify_collateral_signature(mq, "enclaveIdentity", p.signature, signer, "QE Identity")  # raises on failure
print("QE: signature OK over first object; parsed mrsigner =", p.enclave_identity.mrsigner.hex())
t = json.loads(tcb)["tcbInfo"]; t["tcbLevels"] = [dict(t["tcbLevels"][0], tcbStatus="UpToDate", tcb=dict(t["tcbLevels"][0]["tcb"], pcesvn=0))]
mt = dup(tcb, "tcbInfo", t)
pt = ct.parse_tcb_info_response(mt)
ct._verify_collateral_signature(mt, "tcbInfo", pt.signature, signer, "TCB Info")
print("TCB: signature OK over first object; parsed levels =", [(l.tcb_status.value, l.tcb.pce_svn) for l in pt.tcb_info.tcb_levels])
print("first-key offset used by signature check:", mq.decode().find('"enclaveIdentity":'), "| last (parsed) offset:", mq.decode().rfind('"enclaveIdentity":'))
