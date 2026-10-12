# code-execution-environment: `/snapshot` skips the per-chat container token and returns the plaintext workspace

| | |
|---|---|
| Component | `github.com/tinfoilsh/code-execution-environment`: HEAD `8676c64`; release `v0.0.17` ships the same shim configuration (its api-server source not checked) |
| Severity | High (CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L` = 8.2 for the primary scenario: infrastructure attacker, see the reachability caveat) |
| Bug class | CWE-306 (missing authentication for critical function), CWE-862 (missing authorization) |
| Attacker position | Any party that can open a TLS connection to a sandbox CVM's shim. Verified in code for Tinfoil's host / control plane / data-center network; unverified for the public internet. |
| Status | Unfixed at upstream HEAD as of 2026-10-08 (local clone HEAD `8676c64`); not disclosed |

## Summary

Every code-execution sandbox protects its tool endpoints with a per-chat token,
`X-Code-Execution-Container-Auth-Token`. The client derives this token from the chat key, so Tinfoil
infrastructure never sees it. The api-server skips that check for one path: `/snapshot`. The executor
answers `/snapshot` with a base64 tar of all of `/workspace`, in plaintext. The measured shim config
exposes `/snapshot` and does not enable shim authentication. So anyone who can reach a sandbox's shim
can send one unauthenticated `POST /snapshot` and get the complete workspace of an active session. That
includes the prior-session workspace that is stored encrypted under the user's key and restored into the
container. A local run with the unmodified api-server, executor and pinned tfshim confirms it: `/read`
without the token returns 401, and `/snapshot` without the token returns 200 with the victim's file.

## Threat model

What the design promises:
- `confidential-tinfoil-harness/README.md:14`: "The client keeps custody of its content encryption key and
  sends it inside the encrypted request body."
- The token exists to keep other parties out. The webapp derives it client-side:
  `tinfoil-webapp/src/services/exec-snapshot/key-derivation.ts:10,52-61`, i.e.
  `HKDF(chatKEK, "tinfoil-code-execution-v1:" + chatId)`. The api-server locks to the first token it sees
  (`api-server/main.go:79-93`).
- `executor/snapshot.go:3`: "/snapshot and /restore handle the workspace tar in plaintext. Encryption
  happens upstream." The plaintext is meant for the orchestrator enclave only.
- The orchestrator reaches each sandbox over an "attested-TLS hop"
  (`confidential-model-router/local_testing.md:53-57`). That hop exists because the network between the
  orchestrator and the sandbox is untrusted.

Who can exploit it:

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Tinfoil host, hypervisor, control plane or data-center network (in Tinfoil's threat model as untrusted) | Network reach to the sandbox CVM's shim port and knowledge of which sandbox serves which session. The control plane provisions the sandboxes, so it has both. | Yes (code path verified; reach follows from the provisioning design) | Full plaintext of `/workspace` for any active session |
| Internet party | The sandbox's public hostname must be reachable and discoverable (e.g. `NAME.ORG.containers.tinfoil.dev`, certificates in CT logs) | Unverified. Plausible: `double-blind-eval/docs/TINFOIL-CONTAINERS.md:29` describes "a public HTTPS endpoint per container". The orchestrator repo is private. | Same as above, for anyone |
| Another Tinfoil Chat user through the orchestrator | The victim's 256-bit `accessToken` | No (routing is by `accessToken`, `local_testing.md:61-64`) | None |
| Prompt-injected code in another user's sandbox | Network from the executor | No (`tinfoil-config.yml:35` `network_mode: "none"`) | None |
| Orchestrator enclave (`confidential-code-execution`) | Nothing extra | By design; it already holds the workspace encryption key | Not a vulnerability |

Preconditions:

Verified in code:
- `api-server/main.go:155-163`: `/snapshot` goes through `checkLifecycle` only.
- `api-server/main.go:99-121`: `/snapshot` is refused only while the container is `warm` (410) or
  `killed`. After the first user tool call the container is `active` and `/snapshot` is served.
- `tinfoil-config.yml:39-49`: the shim forwards `/snapshot`; no `authenticated:` key.
- tfshim v0.3.18 `config/config.go:13,27`: listens on 443 by default; `authenticated` defaults to false.
  `main.go:62-72`: no validator when unauthenticated. `api.go:165`: even with a validator, keys are checked
  only on `/v1/chat/completions`. `api.go:198`: path allowlist only. No client certificates.
- EHBP v0.1.7 middleware passes bodyless requests through, and EHBP does not authenticate clients anyway.

Unverified production facts:
- Whether sandbox CVMs are reachable from the internet and whether their hostnames are discoverable. The
  orchestrator (`confidential-code-execution`) is private.
- Whether code execution is live for users. The webapp hard-disables it
  (`tinfoil-webapp/src/components/chat/chat-interface.tsx:396`, `const canUseCodeExecution = false` at
  `c061681`). The harness wires it to `code-execution.tinfoil.sh`
  (`confidential-tinfoil-harness/tools.go:44-45`, `tinfoil-config.yml:56`).
- Whether the v0.0.17 api-server image (`api-server@sha256:e1cb4f49...`) contains the same exemption. The
  v0.0.17 module zip has only `tinfoil-config.yml` and README (identical `shim:` block); the local clone
  is shallow. HEAD `8676c64` is from 2026-05-20, five days after v0.0.17.

Not affected / out of scope:
- `/user-uploads` is not in the snapshot (`executor/uploads.go:15`). Uploads leak only if copied into
  `/workspace`. `/tmp` is not included.
- All other api-server paths enforce the token (401 missing, 403 mismatch; shown in the PoC).
- The exemption is deliberate (`api-server/main_test.go:208-225`, "the orchestrator triggers eviction
  snapshots without a per-user auth token in flight"). Nothing restricts the endpoint to the orchestrator.

## Severity

| Scenario | Vector | Score |
|---|---|---|
| Infrastructure attacker, one request (kills the session: next call and eviction get 410) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L` | 8.2 |
| Infrastructure attacker, overlapping the orchestrator's eviction snapshot (no visible effect) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| Internet attacker, if public reach and hostname discovery hold | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L` | 8.2 |

PR:N because the request needs no credential and Tinfoil's model gives the operator no access to
enclave data. The base vector is the same for the internet case; what changes is the number of possible
attackers, which raises priority but not the CVSS score. Three independent reviewers upheld the finding
(confidence 0.75-0.85) and all rated it High. One noted it would be Medium if Tinfoil argues only its own
infrastructure can reach the containers; another noted it would matter less if code execution is not
enabled in production. None gave a vector; the vectors above are ours.

## Technical details

`api-server/main.go:147-167` (HEAD `8676c64`):

```go
// /snapshot bypasses the auth-token lock as it needs to be called in the background.
...
if path == "/snapshot" {
    status, msg, ok = g.checkLifecycle(path)
} else {
    status, msg, ok = g.check(path, r.Header.Get(authTokenHeader))
}
```

`g.check` (main.go:124-129) calls `checkAuth` (main.go:79-93) and then `checkLifecycle`. `/snapshot`
only gets the second. The request body is then proxied to the executor and the response streamed back
unchanged (main.go:169-199). After a complete snapshot the gate moves to `killed` (main.go:200-208).

`executor/snapshot.go:149-165` writes `{"tar":"<base64 tar of workspaceRoot>"}` with no key material.

`tinfoil-config.yml:39-49`:

```yaml
shim:
  upstream-port: 8000
  paths: [/exec, /read, /write, /snapshot, /restore, /sync-uploads/manifest, /sync-uploads/blobs, /health]
```

## Proof of concept

`poc/run.sh` does the following, all on loopback:
1. Exports `8676c64` from the pristine clone. It rewrites only the three filesystem path constants
   (`/workspace`, `/user-uploads`, `/run/execsock/exec.sock`) so the binaries run outside a container
   without root. It builds api-server and executor with `CGO_ENABLED=0 -trimpath`, as the Dockerfiles do.
2. Builds tfshim v0.3.18 from the Go module cache, unmodified (module `h1:vx0xjrnKAhs4cxjTHbCHYzvYEmK7xly2U+T4RSFAc/8=`).
3. Builds the shim config from the verbatim `shim:` block of `tinfoil-config.yml`, plus local-only knobs:
   port 18443, `tls-mode: self-signed`, key and cache paths. `DOMAIN: localhost` makes the shim use its
   dummy attestation. None of these are on the request path.
4. Runs all three processes as uid 65534 (`nobody`) with no capabilities.
5. Victim (orchestrator acting with the victim's token) writes `notes/secret.txt` containing a random
   canary. The attacker sends `/read` with no token and with a wrong token, then `/snapshot` with no
   token, all through the shim.
6. Negative control: the same steps with the api-server rebuilt with `poc/fix.patch` (send `/snapshot`
   through `g.check`).

Run it:

```
cd poc && ./run.sh
```

Requires the toolchain from `/root/tinfoil-review/env.sh`, `git`, `curl` and `setpriv`. It must start as
root only so that `setpriv` can drop to uid 65534. Build trees go to
`/root/tinfoil-review/work/disclosures/03/`.

Output from the run on 2026-10-11 (`poc/expected-output.txt`):

```
################ vulnerable build (api-server, shipped executor, tfshim v0.3.18)
processes: nobody executor;nobody api-server;nobody tfshim;
[victim]   /write notes/secret.txt (token)   HTTP 200  {"path":"notes/secret.txt","size":53}
[attacker] /read  (no token)                 HTTP 401  {"error":"missing container auth token"}
[attacker] /read  (wrong token)              HTTP 403  {"error":"container auth token mismatch"}
[attacker] /snapshot (no token, no body)     HTTP 200  {"tar":"bm90ZXMvAAAA...
    tar entry: notes/secret.txt (53 bytes)
    contents of notes/secret.txt: CANARY-2c7d46c979ec patient=Jane Doe dx=confidential
RESULT vulnerable: attacker without token obtained the victim's workspace (canary matched)

################ fixed build (api-server-fixed, shipped executor, tfshim v0.3.18)
[attacker] /snapshot (no token, no body)     HTTP 401  {"error":"missing container auth token"}
[orchestrator] /snapshot (victim token)      HTTP 200  {"tar":"bm90ZXMvAAAA...
RESULT fixed: /snapshot without token refused; token holder still snapshots
```

What is simulated or not covered:
- No CVM, no real attestation, self-signed TLS. The attestation and TLS layers do not authenticate the
  client, so they do not change who may call `/snapshot`.
- The PoC runs unprivileged, so `/exec` is not exercised: it needs `CAP_SETUID` to drop bash to uid 1001.
  `/write` passes the same token gate and moves the container to `active` the same way.
- The token is random bytes in place of the HKDF output. The api-server only compares it.
- The earlier evidence also covers production uids and capabilities in a chroot, a restored prior-session
  workspace, uploads copied into `/workspace`, and the overlap with the eviction snapshot (both requests
  200; deterministic for large workspaces, 19/20 for small ones):
  `/root/tinfoil-security-findings/cee-snapshot-auth-bypass/evidence/` (`verifier-poc/run.out`,
  `verifier-poc/race_small.out`, `verifier-impact/`).

## Impact

An attacker who can reach a sandbox's shim gets the full contents of the user's code-execution
workspace for the current chat:
- files restored from earlier sessions, which are otherwise stored encrypted under a key derived from
  the user's chat key;
- uploads the model copied into `/workspace`;
- model outputs and any secrets written there.

This holds for every active session. The one-request form ends the session, so the user's next tool call
fails with 410 and unsaved work since the last snapshot is lost. An attacker who can time the request
against the orchestrator's eviction snapshot leaves no visible trace.

### Affected downstream packages

- `confidential-tinfoil-harness` (code-execution tool family)
- `confidential-model-router` toolruntime (code-execution profile)
- `tinfoil-webapp` exec-snapshot flow (UI disabled at `c061681`)

## Remediation

- Require a credential on `/snapshot`. Option 1: send it through `g.check` like every other path, and have
  the orchestrator keep the container token until eviction (it already receives `containerAuthToken`
  in `_meta`). `poc/fix.patch` does this; the PoC's negative control shows the token holder can still
  snapshot and an anonymous caller gets 401.
- Option 2: a separate orchestrator-only credential, for example derived from the workspace encryption
  key the orchestrator already holds at eviction, or bound to the orchestrator's attested-TLS identity.
- Defence in depth: encrypt the tar inside the container under the user's key before it leaves the
  executor; stop exposing `/snapshot` (and `/restore`) through the public shim if only the orchestrator
  needs them; restrict shim access to the orchestrator (mTLS or the shim's `authenticated:` mode with a
  path list that covers these routes).
- Update `TestProxy_SnapshotBypassesAuth` (`api-server/main_test.go:208-225`) to assert the opposite.

## References

- Finding 14 (`sandbox-tunnel-no-auth`): another sandbox shim that answers
  anonymous callers.
- Finding 12 (`12-sync-attachment-key-derivable`): another place where the operator can read data that is
  meant to stay client-keyed.
- Full evidence: `/root/tinfoil-security-findings/cee-snapshot-auth-bypass/evidence/`.
- Verifier verdicts: `/root/tinfoil-security-findings/verification-verdicts.json`, key
  `L2-cee-snapshot-auth-bypass`.
