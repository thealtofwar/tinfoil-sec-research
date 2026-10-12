// Variant I: Rekor-v2-shaped entry (no integratedTime), no SET, no checkpoint, plus a garbage RFC3161 timestamp.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { Verifier } from '../dist/client.js';
const fixture = JSON.parse(fs.readFileSync(new URL('../test/fixtures/attestation-bundle.json', import.meta.url), 'utf8'));
const leafHashB64 = (b64) => createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(b64, 'base64')])).digest('base64');
async function run(label, mutate) {
  const bundle = structuredClone(fixture); mutate(bundle);
  const v = new Verifier({ configRepo: 'tinfoilsh/confidential-model-router' });
  let r; try { await v.verifyBundle(bundle); r = 'ACCEPTED'; } catch (e) { r = 'rejected: ' + (e.cause ? e.cause.message : e.message); }
  console.log(label.padEnd(78), '->', r);
}
const strip = (b) => { const e = b.sigstoreBundle.verificationMaterial.tlogEntries[0]; delete e.inclusionPromise; e.inclusionProof = { logIndex: '0', rootHash: leafHashB64(e.canonicalizedBody), treeSize: '1', hashes: [] }; return e; };
await run('I. no integratedTime, no SET, no checkpoint, garbage rfc3161 timestamp', (b) => { const e = strip(b); e.integratedTime = null; b.sigstoreBundle.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [{ signedTimestamp: Buffer.from('not a timestamp').toString('base64') }] }; });
await run('J. no integratedTime, no SET, no checkpoint, rfc3161Timestamps: [] (control, expect reject)', (b) => { const e = strip(b); e.integratedTime = null; b.sigstoreBundle.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [] }; });
