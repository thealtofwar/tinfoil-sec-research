// Independent verifier run. Serves the assistant-bubble DOM produced by the
// real chat components (tests/verify/remote-image-exfil.verify.test.tsx) from
// a loopback https "app" origin with the EXACT Content-Security-Policy value
// from the pristine repo's vercel.json, and records which requests reach a
// separate loopback https "sink" origin. Negative controls (fetch() from a
// same-origin script -> connect-src, iframe -> frame-src, inline script)
// show that the policy is being enforced by the browser.
// Loopback only; nothing contacts any Tinfoil host.
import { createRequire } from 'node:module'
import https from 'node:https'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const require = createRequire(path.join(here, 'package.json'))
const { chromium } = require('playwright')

const PRISTINE_VERCEL = '/root/tinfoil-review/repos/tinfoil-webapp/vercel.json'
const RENDERED = path.join(here, '..', 'out', 'rendered-bubble.html')
const SINK_PORT = 47001
const APP_PORT = 47002

const tls = {
  key: readFileSync(path.join(here, 'key.pem')),
  cert: readFileSync(path.join(here, 'cert.pem')),
}

const vercel = JSON.parse(readFileSync(PRISTINE_VERCEL, 'utf8'))
const catchAll = vercel.headers.find((h) => h.source === '/(.*)')
const csp = catchAll.headers.find((h) => h.key === 'Content-Security-Policy').value
const referrerPolicy = catchAll.headers.find((h) => h.key === 'Referrer-Policy').value
console.log('[verify] CSP from pristine vercel.json:\n  ' + csp)

// The rendered bubble points at https://verifier-sink.invalid/... ; rewrite
// that host to the loopback sink so the browser can actually reach it.
const bubble = readFileSync(RENDERED, 'utf8')
  .replaceAll('https://verifier-sink.invalid', `https://127.0.0.1:${SINK_PORT}`)
  .replaceAll('http://verifier-sink.invalid', `http://127.0.0.1:${SINK_PORT}`)

const sinkHits = []
const sink = https.createServer(tls, (req, res) => {
  sinkHits.push({ url: req.url, referer: req.headers.referer ?? null })
  console.log('[sink] request:', req.url, 'referer=', req.headers.referer ?? '(none)')
  res.writeHead(200, { 'content-type': 'image/png', 'access-control-allow-origin': '*' })
  res.end()
})
await new Promise((r) => sink.listen(SINK_PORT, '127.0.0.1', r))

const page =
  '<!doctype html><html><head><meta charset="utf-8"><title>local verify</title></head>' +
  '<body><main>' + bubble + '</main>' +
  // negative controls, NOT part of model content:
  `<iframe src="https://127.0.0.1:${SINK_PORT}/ctl-iframe"></iframe>` +
  `<script>new Image().src="https://127.0.0.1:${SINK_PORT}/ctl-inline-script"</script>` +
  `<script src="/ctl.js"></script>` +
  '</body></html>'
const ctlJs = `fetch("https://127.0.0.1:${SINK_PORT}/ctl-fetch-connect-src").catch(()=>{});`

const app = https.createServer(tls, (req, res) => {
  if (req.url === '/ctl.js') {
    res.writeHead(200, { 'content-type': 'text/javascript', 'Content-Security-Policy': csp })
    return res.end(ctlJs)
  }
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'Content-Security-Policy': csp,
    'Referrer-Policy': referrerPolicy,
  })
  res.end(page)
})
await new Promise((r) => app.listen(APP_PORT, '127.0.0.1', r))

const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors'] })
const ctx = await browser.newContext({ ignoreHTTPSErrors: true })
const tab = await ctx.newPage()
const cspMsgs = []
tab.on('console', (m) => { if (/Content Security Policy/i.test(m.text())) cspMsgs.push(m.text()) })
await tab.goto(`https://127.0.0.1:${APP_PORT}/chat/abc`, { waitUntil: 'load' })
await tab.waitForTimeout(2000)
const imgs = await tab.$$eval('img', (els) => els.map((e) => ({ src: e.src, complete: e.complete, w: e.naturalWidth })))
console.log('[verify] <img> in page:', imgs)
console.log('[verify] CSP console messages:', cspMsgs.length)
for (const m of cspMsgs) console.log('   -', m.slice(0, 150))
await browser.close(); sink.close(); app.close()

const leaks = sinkHits.filter((h) => h.url.includes('leak='))
const ctl = sinkHits.filter((h) => h.url.startsWith('/ctl-'))
console.log('\n[verify] sink hits:', sinkHits.map((h) => h.url))
console.log(`[verify] RESULT: ${leaks.length} image request(s) with chat data reached the sink; ${ctl.length} negative-control request(s) got through (expect 0)`)
for (const h of leaks) console.log('   leaked:', decodeURIComponent(new URL('https://x' + h.url).searchParams.get('leak')), '| via', new URL('https://x' + h.url).searchParams.get('k'), '| referer:', h.referer)
process.exit(leaks.length >= 3 && ctl.length === 0 ? 0 : 1)
