// Runs all tinfoil-conformance vectors of the sigstore / attestation-sev / enclave-cert stages
// through the shipped tinfoil-js verifier code (dist), injecting per-vector trust roots.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
const here = path.dirname(new URL(import.meta.url).pathname);
const dist = path.resolve(here, '..', 'dist');
const vectorsRoot = process.argv[2];
const outFile = process.argv[3];
const stages = { 'sigstore': 'run-sigstore-vector.mjs', 'attestation-sev': 'run-sev-vector.mjs', 'enclave-cert': 'run-enclave-cert-vector.mjs' };
const results = [];
for (const [stage, runner] of Object.entries(stages)) {
  const dir = path.join(vectorsRoot, stage);
  if (!fs.existsSync(dir)) continue;
  for (const v of fs.readdirSync(dir).sort()) {
    const vdir = path.join(dir, v);
    if (!fs.existsSync(path.join(vdir, 'input.json'))) continue;
    const input = JSON.parse(fs.readFileSync(path.join(vdir, 'input.json'), 'utf8'));
    const manifest = fs.readFileSync(path.join(vdir, 'manifest.yaml'), 'utf8');
    const exitCode = Number((manifest.match(/exit_code:\s*(\d+)/) || [])[1]);
    const rejCode = (manifest.match(/rejection_code:\s*(.*)/) || [])[1];
    // per-vector dist copy with injected roots
    const tmp = fs.mkdtempSync(path.join(here, 'tmp', 'jsv-'));
    fs.cpSync(dist, tmp, { recursive: true });
    if (input.trust_root_b64) {
      const root = Buffer.from(input.trust_root_b64, 'base64').toString('utf8');
      fs.writeFileSync(path.join(tmp, 'sigstore-trusted-root.js'), 'export default ' + root + ';\n');
    }
    if (input.amd_root_ca_pem || input.ask_pem) {
      let certs = fs.readFileSync(path.join(dist, 'sev', 'certs.js'), 'utf8');
      if (input.amd_root_ca_pem) certs = certs.replace(/export const ARK_CERT = `[\s\S]*?`;/, 'export const ARK_CERT = `' + input.amd_root_ca_pem.trim() + '`;');
      if (input.ask_pem) certs = certs.replace(/export const ASK_CERT = `[\s\S]*?`;/, 'export const ASK_CERT = `' + input.ask_pem.trim() + '`;');
      fs.writeFileSync(path.join(tmp, 'sev', 'certs.js'), certs);
    }
    const r = spawnSync('node', [path.join(here, runner), tmp, vdir], { encoding: 'utf8' });
    fs.rmSync(tmp, { recursive: true, force: true });
    let out;
    try { out = JSON.parse(r.stdout.trim().split('\n').pop()); } catch { out = { accepted: null, error: 'runner crashed: ' + r.stderr.slice(0, 300) }; }
    const expectedAccept = exitCode === 0;
    const verdict = out.accepted === null ? 'CRASH' : (out.accepted === expectedAccept ? 'OK' : (out.accepted ? 'DIVERGENCE-ACCEPTS' : 'DIVERGENCE-REJECTS'));
    results.push({ stage, vector: v, expected: expectedAccept ? 'accept' : 'reject(' + (rejCode || '').trim() + ')', js: out.accepted ? 'accept' : 'reject', verdict, detail: (out.error || '') + (out.cause ? ' / cause: ' + out.cause : '') });
    console.log(`${verdict.padEnd(20)} ${stage}/${v}  expected=${expectedAccept ? 'accept' : 'reject'} js=${out.accepted ? 'accept' : 'reject'} ${out.error ? '-- ' + out.error.slice(0, 100) + (out.cause ? ' / ' + out.cause.slice(0, 120) : '') : ''}`);
  }
}
fs.writeFileSync(outFile, JSON.stringify(results, null, 2));
