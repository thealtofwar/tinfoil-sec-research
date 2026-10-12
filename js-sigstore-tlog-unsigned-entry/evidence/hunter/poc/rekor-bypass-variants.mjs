// Additional variants on the shipped verifier + shipped trusted root, to pin down exactly which tlog checks run.
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
await run('A. no SET, proof without checkpoint, logId = Rekor v2 log2025-1 id', (b) => { const e = strip(b); e.logId = { keyId: 'zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=' }; });
await run('B. no SET, proof WITH checkpoint but checkpoint.envelope = "" (empty)', (b) => { const e = strip(b); e.inclusionProof.checkpoint = { envelope: '' }; });
await run('C. no SET, proof with checkpoint = {} (no envelope)', (b) => { const e = strip(b); e.inclusionProof.checkpoint = {}; });
await run('D. no SET, proof without checkpoint, logIndex/treeSize huge', (b) => { const e = strip(b); e.inclusionProof.logIndex = '999999999'; e.inclusionProof.treeSize = '1000000000'; e.inclusionProof.hashes = []; });
await run('E. no SET, no checkpoint, canonicalizedBody rewritten (kind dsse, sig+payloadHash consistent)', (b) => {
  const e = strip(b);
  const body = { apiVersion: '0.0.1', kind: 'dsse', spec: { signatures: [{ signature: b.sigstoreBundle.dsseEnvelope.signatures[0].sig, verifier: 'YQ==' }], payloadHash: { algorithm: 'sha256', value: createHash('sha256').update(Buffer.from(b.sigstoreBundle.dsseEnvelope.payload, 'base64')).digest('hex') } } };
  e.canonicalizedBody = Buffer.from(JSON.stringify(body)).toString('base64');
  e.inclusionProof.rootHash = leafHashB64(e.canonicalizedBody);
});
await run('F. two entries, both unsigned (different logIndex)', (b) => { const e = strip(b); const e2 = structuredClone(e); e2.logIndex = '2'; b.sigstoreBundle.verificationMaterial.tlogEntries.push(e2); });
await run('G. mediaType bogus (-> treated as v0.1), SET removed, proof present no checkpoint', (b) => { strip(b); b.sigstoreBundle.mediaType = 'application/x-whatever'; });
await run('H. timestampVerificationData removed entirely, no SET, no checkpoint', (b) => { strip(b); delete b.sigstoreBundle.verificationMaterial.timestampVerificationData; });
