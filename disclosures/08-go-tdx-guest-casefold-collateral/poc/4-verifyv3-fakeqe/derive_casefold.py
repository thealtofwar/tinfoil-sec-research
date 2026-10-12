"""Derive the case-fold variant from the SAME control fixture (same synthetic keys):
the only difference is an extra unsigned "enclaveidentity" member in the captured
QE Identity PCS response. Signed member and signature are byte-identical."""
import base64, json, sys
src, dst = sys.argv[1], sys.argv[2]
fx = json.load(open(src))
doc = json.loads(base64.b64decode(fx["input"]["document_b64"]))
q = base64.b64decode(doc["cpu_evidence"]["report_base64"])
off = 48 + 584 + 4 + 64 + 64 + 2 + 4
qe_mrsigner = q[off + 128: off + 160].hex().upper()
for c in doc["collateral"]:
    if c["format"].endswith("intel-pcs/v1"):
        for r in c["data"]["responses"]:
            if r["url"].endswith("/qe/identity"):
                raw = base64.b64decode(r["body_base64"])
                i = raw.index(b'"enclaveIdentity":') + len(b'"enclaveIdentity":')
                obj, end = json.JSONDecoder().raw_decode(raw[i:].decode())
                signed = raw[i:i + end]
                sig = json.loads(raw)["signature"]
                forged = (b'{"enclaveIdentity":' + signed + b',"enclaveidentity":' +
                          json.dumps({"mrsigner": qe_mrsigner}).encode() +
                          b',"signature":' + json.dumps(sig).encode() + b'}')
                assert json.loads(forged)["enclaveIdentity"] == obj
                r["body_base64"] = base64.b64encode(forged).decode()
fx["id"] = "fakeqe-casefold-derived"
fx["input"]["document_b64"] = base64.b64encode(json.dumps(doc, separators=(",", ":")).encode()).decode()
json.dump(fx, open(dst, "w"), indent=1)
print("QE report MRSIGNER in quote:", qe_mrsigner, "-> added unsigned enclaveidentity.mrsigner override")
