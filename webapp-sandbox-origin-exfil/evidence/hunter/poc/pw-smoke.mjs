import { chromium } from 'playwright'
const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost'] })
const page = await browser.newPage()
await page.route('**/*', (route) => route.fulfill({ status: 200, headers: { 'content-type': 'text/html' }, body: '<title>ok</title><p>intercepted ' + route.request().url() }))
await page.goto('https://example.invalid/test')
console.log(await page.title(), await page.evaluate(() => location.origin), (await browser.version()))
await browser.close()
