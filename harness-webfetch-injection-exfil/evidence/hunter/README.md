# PoC: indirect prompt injection -> web_fetch exfiltration through the Tinfoil Chat harness

Local only. Nothing here contacts any Tinfoil host.

## Chain

1. The Tinfoil Chat harness (`confidential-tinfoil-harness`) offers the model the `web_fetch`
   tool whenever web search is on, which is the default for every thread and profile
   (`context.go:194-195`, `records.go:109`). Every tool call the model emits is executed
   automatically, with no user confirmation and no URL policy (`agent.go:127,195-274`).
2. `web_fetch` reaches the websearch enclave's `fetch` tool, whose handler forwards every URL
   verbatim to Exa `/contents` with `maxAgeHours: 2` (`internal/server/handlers.go:202-204`,
   `internal/fetch/fetch.go:24-29,130-132`). Exa live-crawls any URL it has not cached in the
   last two hours, so the attacker's web server receives the URL, query string included.
   The fetch handler never runs the PII filter (`PIICheckEnabled: false`).
3. The only defence against an injected page is the websearch injection classifier, and the
   shipped service skips it for every host whose registrable domain is in the Cloudflare Radar
   top-500k list unless the caller sends `X-Tinfoil-Tool-Injection-Check` explicitly
   (`internal/tools/service.go:236-251,339-376`, `internal/domainrank/ranker.go:18,137-155`).
   The harness never sends that header. github.com, medium.com, reddit.com, substack.com and
   every other user-content host in the top 500k are therefore never screened. The classifier
   is also fail-open (`service.go:360-364`). The harness's own mitigation is one sentence in
   the tool system prompt (`tools.go:55`).
4. Second channel, no websearch involved: the `render_link_preview` widget is executed by the
   harness server-side by POSTing the model-chosen URL to the metadata enclave
   (`widgets.go:66-74`), which scrapes it through context.dev with `maxAgeMs=0`
   (`contextdev/client.go:68-72`): always a fresh request to the attacker's server.

5. Third channel, client-side (webapp, noted only): assistant markdown images and the
   `render_image` widget render model-chosen `https:` URLs directly in the victim's browser
   (`tinfoil-webapp/src/components/chat/renderers/components/markdown-components.tsx:446-455`,
   `genui/widgets/Image.tsx:140-141`; CSP `img-src 'self' data: blob: https:` in `vercel.json`).

## Components

- `exastub/`: loopback stand-in for `api.exa.ai` and `api.cloudflare.com`, reached by the
  shipped websearch code through `HTTPS_PROXY` (CONNECT) with a throwaway CA passed through
  `SSL_CERT_FILE`. Emulates Exa's live crawl by fetching every `/contents` URL from the
  attacker's server. Serves a 7-domain "top-500k" CSV to the shipped `CloudflareRanker`.
- `attacker/`: the adversary's ordinary web server: hosts the poisoned page and logs every
  request (that log is the exfiltrated data).
- `../confidential-websearch/cmd/poc-websearch/main.go`: the shipped websearch packages
  (`internal/server`, `internal/tools`, `internal/fetch`, `internal/domainrank`, MCP handler)
  wired as in `cmd/websearch-mcp/main.go`, with the three production-only clients replaced:
  a local classifier that flags the PoC payload (perfect classifier), no PII client, no usage
  reporter. No shipped file is modified.
- `../confidential-tinfoil-harness/poc_exfil_test.go`: the shipped harness (`testChatHarness`
  wiring from the repo's own tests) with a *scripted* model that follows the injection, the
  websearch tool family pointed at poc-websearch through a TLS front, a victim profile with
  personalization, a project with a confidential document and a chat with an earlier
  message containing an SSN.
- `../confidential-website-metadata-fetcher/poc_linkpreview_test.go` and
  `TestPoC_LinkPreviewWidgetForwardsModelChosenURL`: the second channel.

## Run

    ./run.sh                      # chain PoC; output in out/
    (cd ../confidential-tinfoil-harness && POC_WEBSEARCH_ADDR=... POC_ATTACKER_LOG=... GOWORK=off go test -run TestPoC_ -v .)
    (cd ../confidential-website-metadata-fetcher && GOWORK=off go test -run TestPoC_ -v .)

## Captured output (out/)

- `harness-test.final.log`: the two scenarios. Scenario 1 (page on github.com): no
  classifier call, the model receives the injection, calls `web_fetch` with two exfil URLs,
  the attacker log contains the decoded system prompt (personalization, project instructions,
  project document) and the earlier user message with the SSN. Scenario 2 (same page on a
  long-tail host): classifier call #1 flags it, model sees "content blocked by safety
  filters", nothing leaks.
- `websearch.final.log`: every MCP request from the harness carries no
  `X-Tinfoil-Tool-Injection-Check` header; classifier invoked only in scenario 2.
- `exastub.final.log`: the Exa `/contents` requests with `maxAgeHours: 2` and the crawler
  fetches of the exfil URLs.
- `attacker.final.log`: the attacker's request log with the decoded chunks.
- `metadata-channel-test.log`, `linkpreview-harness-test.log`: second channel.

## What is scripted / assumed

- The model is scripted to follow the injection. Model compliance with injected
  instructions is well documented for all current open-weight models; Tinfoil's own
  tool prompt and classifier exist because of it. Not exercised against production models
  (no production traffic allowed).
- Exa's live crawl of an uncached URL is emulated. The shipped request sets
  `maxAgeHours: 2`, whose documented meaning is "crawl if not cached within 2 hours".
- The top-500k list is replaced by a 7-domain stub; github.com etc. are in the real list.
