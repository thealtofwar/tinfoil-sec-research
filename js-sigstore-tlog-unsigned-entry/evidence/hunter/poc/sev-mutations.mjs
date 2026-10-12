// Sanity mutations of the real SEV-SNP report / VCEK on the shipped verifier (expect all rejected except trailing-bytes)
import fs from 'node:fs';
import zlib from 'node:zlib';
import { verifyAttestation } from '../dist/attestation.js';
const fixture = JSON.parse(fs.readFileSync(new URL('../test/fixtures/attestation-bundle.json', import.meta.url), 'utf8'));
const report = zlib.gunzipSync(Buffer.from(fixture.enclaveAttestationReport.body, 'base64'));
console.log('report bytes', report.length);
async function run(label, mut) {
  const r = Buffer.from(report); let vcek = fixture.vcek; const extra = mut(r) ;
  const body = Buffer.from(zlib.gzipSync(extra && extra.bytes ? extra.bytes : r)).toString('base64');
  if (extra && extra.vcek) vcek = extra.vcek;
  try { const res = await verifyAttestation({ format: 'https://tinfoil.sh/predicate/sev-snp-guest/v2', body }, vcek); console.log(label.padEnd(60), '-> ACCEPTED', res.measurement.registers[0].slice(0, 16), 'hpke', res.hpkePublicKey.slice(0, 16)); }
  catch (e) { console.log(label.padEnd(60), '-> rejected:', (e.cause ? e.cause.message : e.message).slice(0, 110)); }
}
await run('control', () => {});
await run('report_data[32] flipped (HPKE key)', (r) => { r[0x50 + 32] ^= 1; });
await run('report_data[0] flipped (TLS fp)', (r) => { r[0x50] ^= 1; });
await run('measurement byte flipped', (r) => { r[0x90] ^= 1; });
await run('debug policy bit set (bit 19)', (r) => { r[0x08 + 2] |= 0x08; });
await run('signature r byte flipped', (r) => { r[0x2A0] ^= 1; });
await run('trailing 100 bytes appended', (r) => ({ bytes: Buffer.concat([r, Buffer.alloc(100, 7)]) }));
await run('version set to 2 (v2 parsing, family bytes must be zero)', (r) => { r[0] = 2; });
await run('vmpl = 3', (r) => { r[0x30] = 3; });
await run('host_data set to 0xff..', (r) => { r.fill(0xff, 0xc0, 0xe0); });
await run('chip_id zero + mask_chip_key', (r) => { r.fill(0, 0x1a0, 0x1e0); r[0x48] |= 2; });
await run('signer_info = VLEK(1<<2)', (r) => { r[0x48] |= 4; });
await run('vcek = ASK cert (DER of hardcoded ASK)', () => ({ vcek: Buffer.from(fs.readFileSync(new URL('../dist/sev/certs.js', import.meta.url), 'utf8').match(/ASK_CERT = `-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----`/)[1].replace(/\s+/g, ''), 'base64').toString('base64') }));
