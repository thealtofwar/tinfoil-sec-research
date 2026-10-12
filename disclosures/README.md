# Tinfoil vulnerability disclosures (one file per issue)

Each directory below is a standalone disclosure for security@tinfoil.sh. Directory 08 can also go to
the google/go-tdx-guest maintainers. Each one contains:

- `README.md`: summary, threat model with a table of attacker positions, per-scenario CVSS 3.1
  severity, root cause with file:line references, impact, remediation and references.
- `poc/`: a minimal proof of concept with `run.sh`, plus `expected-output.txt` captured from a local run
  on 2026-10-11, including negative controls. Some directories also have fix patches and a fixed-mode
  output.

Every PoC runs locally against the shipped code at the pinned versions. No PoC sends traffic to Tinfoil
production. Heavy build trees live outside these directories, under `/root/tinfoil-review/work/disclosures/`.

Status for all issues: unfixed at upstream HEAD as of 2026-10-08, and not yet disclosed.

| # | Issue | Severity (primary scenario) | Attacker position | PoC |
|---|---|---|---|---|
| [08](08-go-tdx-guest-casefold-collateral/) | go-tdx-guest enforces Intel TDX collateral from an unsigned case-variant JSON member, so tinfoil-go accepts unsigned TCB Info and QE Identity | Critical impact / High CVSS: 7.4 (9.1 if host root is the adversary); 4.8-5.9 for TCB forgery only | Whoever supplies the PCS responses (document server in v0.16.1+, tdx-proxy in v0.15.x); full bypass also needs host root on an endorsed TDX machine | Ran: real Intel quote and collateral, also on go-tdx-guest main; fix diff validated |
| [03](03-code-execution-snapshot-auth-bypass/) | code-execution `/snapshot` skips the per-chat token and returns the plaintext workspace | High, 8.2 | Anyone who can reach the sandbox shim (verified for Tinfoil infrastructure; internet reach unverified) | Ran: unmodified binaries behind tfshim; fix control |
| [01](01-ehbp-go-http2-retry-plaintext/) | EHBP Go client resends request bodies in plaintext on HTTP/2 retries | High, 7.5 (gateway/proxy); 5.9 direct | The client's TLS peer: gateway or proxy by design, or a WebPKI-capable on-path party | Ran on EHBP v0.3.2 and v0.4.0 and at SDK level; one-line fix validated |
| [02](02-python-tdx-collateral-signed-vs-enforced/) | tinfoil-python enforces TDX collateral that Intel's signature does not cover (duplicate-key and nested-object triggers) | High, 7.4 (9.1 bundle/gateway); 5.9 for TCB forgery only | Whoever answers tdx-proxy requests; full bypass also needs a custom QE under FLC | Ran: real Intel artifacts; fix validated |
| [07](07-gateway-catalog-chooses-trusted-repo/) | The unauthenticated gateway catalog chooses which `tinfoilsh/*` code a `NewGateway` client trusts | High, 7.5 for Tinfoil or an insider; Medium for outsiders | Gateway catalog control plus an attested `cvm_admin` CVM (today Tinfoil's dev boxes) | Ran: provenance, catalog and VerifyV3 layers; quote layer by code review |
| [06](06-webapp-remote-image-exfiltration/) | Tinfoil Chat web app auto-loads model-authored remote images: zero-click exfiltration by prompt injection | High, 7.5 (5.3-6.5 conservative) | Author of a web page or document the model reads | Ran: vitest on the shipped pipeline plus headless Chromium under the production CSP |
| [17](17-ios-remote-image-exfiltration/) | The iOS app auto-fetches model-authored remote images | High, 7.5 (5.3-6.1 conservative) | Same as 06 | Static trace only (no iOS runtime); XCTest and manual steps provided |
| [09](09-harness-webfetch-injection-exfiltration/) | The chat harness auto-executes model-chosen `web_fetch`/link-preview URLs, so the conversation leaks through enclave crawler traffic | High, 7.4 (5.3-6.5 variants) | Author of a page or document the model reads, plus a web server | Ran: loopback harness and services, scripted model |
| [04](04-ehbp-go-3xx-response-forgery/) | tinfoil-go / EHBP Go accept forged responses: nonce-less 3xx and a 303 POST-to-GET downgrade | Medium, 5.9 (integrity) | The client's TLS peer | Ran on EHBP v0.3.2 and v0.4.0; fix control |
| [05](05-summarizer-tls-pin-after-send/) | confidential-summarizer sends each request before it checks the TLS pin | Medium, 5.9 | Network path plus a WebPKI certificate for the router hostname | Ran on HTTP/1.1 and HTTP/2; current-SDK control |
| [10](10-tinfoil-js-unsigned-rekor-entry/) | tinfoil-js accepts Sigstore bundles whose Rekor entry is unsigned (sigstore-browser 0.1.14) | Medium, 5.9 (web app not affected: it locks 0.1.15) | Bundle server plus a Fulcio leaf key for the router repo | Ran; 0.1.15 control |
| [11](11-python-rekey-bodyless-downgrade/) | tinfoil-python resends a one-shot body as a bodyless unencrypted request after a forged 422 and accepts a forged 200 | Medium, 5.9 (integrity) | The client's TLS peer | Ran on the PyPI wheels; fix validated |
| [13](13-python-pck-crl-issuer-unbound/) | tinfoil-python accepts a PCK CRL from any Intel-rooted CA | Medium, 5.9 | tdx-proxy control plus a revoked PCK key | Ran: genuine Intel CRLs; fix validated |
| [15](15-proxy-desktop-unsigned-autoupdate/) | The Tinfoil Proxy desktop app installs unsigned auto-updates on Windows and Linux | Medium / hardening, 6.8 | Release-channel control or an OS-trusted TLS intermediary | Ran: artifact analysis plus electron-updater against a fake feed |
| [16](16-webapp-sandbox-origin-exfiltration/) | The artifact sandbox origin lets model-authored artifacts and previews reach any HTTPS host | Medium, 6.5 | Prompt injection plus one click on Preview | Ran: 6/9 leaks; hardened CSP 0/9 |
| [18](18-swift-ehbp-nonceless-response-accepted/) | tinfoil-swift / EHBP Swift / openai-swift-fork accept a forged nonce-less non-2xx response as the completion | Medium, 5.9 (integrity) | The client's TLS peer | Ran with Swift 6.2.1 on Linux; fix validated |
| [14](14-sandbox-unauthenticated-connect-tunnel/) | The agent-sandbox shim's CONNECT tunnel gives anonymous clients all 16 published ports | Medium, 4.8 (7.4 upper bound) | Any internet client that knows the sandbox hostname | Ran on the shipped shim with the real config |
| [12](12-sync-attachment-key-derivable/) | confidential-sync: the control plane can derive forked-attachment keys from metadata plus a guessed plaintext | Medium (low end), 4.2 | Tinfoil's control-plane operator or anyone reading its database or logs | Ran on the unmodified enclave with a stub control plane |
| [19](19-router-metrics-key-unpinned-tls/) | confidential-model-router sends METRICS_API_KEY over unpinned TLS | Low-Medium, 3.7 (5.9 if the key has broad scope) | WebPKI-capable on-path party on the router's egress path | Ran; fix patch validated |

Not split out: clean frame-boundary truncation of EHBP streams is a protocol limitation that Tinfoil
already documents. Its evidence stays in `../ehbp-stream-truncation-known-limitation/`.

The combined report is `../REPORT.md`. Some disclosures supersede its details, because they were
re-checked on 2026-10-11 and their agents corrected line numbers, CVSS arithmetic and scope. Each README
lists its own corrections. The main ones:

- **Finding 10:** the Tinfoil Chat web app is not affected.
- **Finding 6:** the `?q=` / `#send=` auto-submit did not reproduce in production.
- **Finding 7:** the outsider example (renting `confidential-sandbox-gpu`) was wrong.
- **Finding 4:** `CheckRedirect` alone is not a sufficient fix.
