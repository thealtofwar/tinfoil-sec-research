// Usage: node run-sev-vector.mjs <distDir> <vectorDir>
import fs from 'node:fs';
import path from 'node:path';
import { freezeDate } from './freeze-date.mjs';
const [distDir, vectorDir] = process.argv.slice(2);
const input = JSON.parse(fs.readFileSync(path.join(vectorDir, 'input.json'), 'utf8'));
freezeDate(input.expiration_check_date_unix);
const { verifyAttestation } = await import(path.resolve(distDir, 'attestation.js'));
let out;
try {
  const r = await verifyAttestation({ format: 'https://tinfoil.sh/predicate/sev-snp-guest/v2', body: input.attestation_doc_b64 }, input.vcek_der_b64);
  out = { accepted: true, measurement: r.measurement, tls: r.tlsPublicKeyFingerprint, hpke: r.hpkePublicKey };
} catch (e) {
  out = { accepted: false, error: String(e && e.message), cause: e && e.cause ? String(e.cause.message) : undefined };
}
console.log(JSON.stringify(out));
