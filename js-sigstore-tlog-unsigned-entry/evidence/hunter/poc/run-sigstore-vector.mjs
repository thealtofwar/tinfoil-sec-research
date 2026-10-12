// Usage: node run-sigstore-vector.mjs <distDir> <vectorDir>
// Runs tinfoil-js verifySigstoreBundle (shipped policy) against a tinfoil-conformance sigstore vector,
// with the vector's trust root injected (distDir must have sigstore-trusted-root.js replaced) and Date frozen.
import fs from 'node:fs';
import path from 'node:path';
import { freezeDate } from './freeze-date.mjs';
const [distDir, vectorDir] = process.argv.slice(2);
const input = JSON.parse(fs.readFileSync(path.join(vectorDir, 'input.json'), 'utf8'));
freezeDate(input.verification_time_unix);
const { verifySigstoreBundle } = await import(path.resolve(distDir, 'sigstore.js'));
const bundle = JSON.parse(Buffer.from(input.bundle_b64, 'base64').toString('utf8'));
let out;
try {
  const r = await verifySigstoreBundle(bundle, input.expected_digest_sha256_hex, input.repo, undefined);
  out = { accepted: true, measurement: r.measurement, releaseTag: r.releaseTag };
} catch (e) {
  out = { accepted: false, error: String(e && e.message), cause: e && e.cause ? String(e.cause.message) : undefined };
}
console.log(JSON.stringify(out));
