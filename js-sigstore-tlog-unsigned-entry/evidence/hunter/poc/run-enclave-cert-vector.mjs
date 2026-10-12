import fs from 'node:fs';
import path from 'node:path';
const [distDir, vectorDir] = process.argv.slice(2);
const input = JSON.parse(fs.readFileSync(path.join(vectorDir, 'input.json'), 'utf8'));
const { verifyCertificate } = await import(path.resolve(distDir, 'cert-verify.js'));
let out;
try {
  const r = await verifyCertificate(input.certificate_pem, input.expected_domain, input.attestation_document, input.expected_hpke_public_key_hex);
  out = { accepted: true, hpke: r.hpkePublicKey, hatt: r.attestationHash };
} catch (e) {
  out = { accepted: false, error: String(e && e.message) };
}
console.log(JSON.stringify(out));
