# Instructions for writing one standalone disclosure (read fully before starting)

Output location: `/root/tinfoil-security-findings/disclosures/<NN>-<slug>/`
- `README.md`: the disclosure itself (structure below).
- `poc/`: a MINIMAL, self-contained proof of concept plus `run.sh` (or exact commands in the README),
  and `expected-output.txt` captured from an actual run you did today.

Sources you must use:
- `/root/tinfoil-security-findings/REPORT.md` (the section for your finding, plus the summary table).
- The finding's existing evidence directory under `/root/tinfoil-security-findings/<name>/`
  (hunter + verifier PoCs; these are large, so distil them).
- Verifier verdicts: `/root/tinfoil-security-findings/verification-verdicts.json` (round 1, findings 1-5)
  and `/root/tinfoil-security-findings/verification-verdicts-round2.json` (round 2; `candidates[].votes`).
  Use their CVSS vectors, caveats and corrections. Where a verifier corrected the hunter (e.g. a
  narrower context, lower severity), the disclosure must reflect the correction.
- Pristine source clones: `/root/tinfoil-review/repos/<repo>` (DO NOT modify). Hunters' working copies:
  `/root/tinfoil-review/work/...`. Toolchain: `source /root/tinfoil-review/env.sh` (Go 1.27.1 + module
  cache, cargo, node 24, python 3.14; Swift 6.2.1 may be under /root/tinfoil-review/work/ios-swift).

Hard rules:
1. LOCAL ONLY. Never send traffic to any Tinfoil production host (`*.tinfoil.sh`, `*.tinfoil.dev`),
   never call their APIs, never touch their GitHub. Downloading public packages/modules is fine.
2. Do not modify `/root/tinfoil-review/repos/`. Build in a copy under your output `poc/` dir or under
   `/root/tinfoil-review/work/disclosures/<NN>/` (keep large build trees OUT of the disclosure dir).
3. The PoC must be minimal: the fewest files that demonstrate the bug against SHIPPED code at the stated
   versions, with a negative control (show the attack fails when the bug is fixed or the input is honest).
   Prefer a single test file dropped into a checkout of the affected repo at a pinned commit/version, plus
   a `run.sh` that does the checkout/copy (from the local pristine clone or the module cache), drops the
   file in, and runs it. Clearly state anything stubbed and why the stub does not change security
   behaviour (e.g. "attestation step replaced by handing over the key a successful verification yields").
4. RUN the PoC yourself and paste the key output lines into `expected-output.txt` and the README.
   If something cannot be run here (no iOS runtime, needs hardware), say so plainly and give precise
   reproduction steps instead.
5. Keep secrets out: no real API keys; canary data only.
6. Writing style: plain, factual, short sentences. No marketing. Exact file:line references.

README.md structure (use these headings):

```
# <Title>

| | |
|---|---|
| Component(s) | repo @ commit / package@version (and every shipped consumer version) |
| Severity | <rating> (CVSS 3.1 <vector> = <score> for the primary scenario) |
| Bug class | e.g. CWE-347 / CWE-436 ... |
| Attacker position | one line |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary
3-6 sentences: what is wrong, who can exploit it, what they get.

## Threat model
- What Tinfoil's security model promises here (quote README/SPEC/AGENTS.md with path).
- Attacker capability table: one row per deployment mode / attacker position:
  | Deployment mode / attacker | What they must control | Exploitable? | Result |
- Preconditions and assumptions, separated into "verified in code" and "unverified production facts".
- Explicitly out of scope / not affected (components or modes checked and found safe).

## Severity
Per-scenario CVSS 3.1 vectors with scores and a one-paragraph justification. Mention where independent
reviewers disagreed and why you chose the rating.

## Technical details
Root cause with exact file:line references (pristine HEAD and pinned versions). Short code excerpts.

## Proof of concept
What the PoC does, prerequisites, exact commands (`cd poc && ./run.sh`), expected output (excerpt),
negative control, and what is simulated/stubbed. Note the full original evidence directory path.

## Impact
Concrete user-visible consequence.

## Remediation
Specific fix (code-level where possible) and defence-in-depth suggestions. If a fix was validated
locally, say how.

## References
Related findings in this report set (by number + directory name), upstream issues/specs.
```
