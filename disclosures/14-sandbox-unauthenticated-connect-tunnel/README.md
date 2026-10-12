# confidential-agent-sandbox: the shim's CONNECT tunnel gives anonymous clients access to all 16 published ports

| | |
|---|---|
| Component | `github.com/tinfoilsh/cvmimage` (shim CONNECT tunnel with `authenticated: false`): `v0.14.8` through HEAD `58b08de`, including `v0.15.0-rc8` |
| Severity | Medium (CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` = 4.8 for a typical dev service; 7.4 upper bound, see Severity) |
| Bug class | CWE-306 (Missing Authentication for Critical Function), CWE-1188 (Insecure Default) |
| Attacker position | Any internet client that knows a running sandbox's hostname. No Tinfoil account, API key, permit, SSH key or disk key is needed |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed. Tinfoil's own config comment acknowledges that the tunnel is unkeyed |

## Summary
The agent sandbox publishes 16 container ports and sets `shim.authenticated: false`. With that setting
the cvmimage shim never builds an API-key validator. Its CONNECT authorisation runs only when a
validator exists, so the shim opens a raw TCP stream to `127.0.0.1:<port>` for any HTTP/2 CONNECT,
including one with no credential at all. Anyone who knows the sandbox hostname (hostnames appear in public
Certificate Transparency logs) can reach whatever the owner, or the AI agent inside the sandbox, has bound
on those ports. Examples are a password-less Redis or Postgres, a dev web server serving the project tree,
Chrome DevTools, and VNC/RDP. Port 22 is also reachable, but sshd accepts only the enrolled key. Nothing
listens on the other 15 ports by default.

## Threat model
What Tinfoil documents:
- `cvmimage/docs/runtime-policy.md:90-93`: "published ports remain loopback-only and reachable through
  the shim's **authenticated, attested CONNECT tunnel**."
- `tinfoil-config/README.md:43`: "Other published ports remain private."
- `tinfoil-cli/ssh.go:42-44`: the session "is tunnelled through the shim's CONNECT endpoint rather than
  exposed on the public internet"; `tinfoil-cli/tunnel.go:45`: `--sandbox` "must be sealed to your disk key".
- Against that, the sandbox config itself says (`confidential-agent-sandbox/tinfoil-config.yml:44-47`):
  "reachable only through the shim's CONNECT tunnel, which this config leaves unkeyed: what a session binds
  on one of these answers to anyone who knows the domain." The sandbox README does not mention this.

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| confidential-agent-sandbox, anonymous internet client | Knowledge of the hostname; the owner or agent has bound a service on `0.0.0.0` (or inner `docker -p`) on one of the 15 non-SSH published ports | Yes | Full TCP access to that service (data read/write, DevTools takeover, desktop) |
| Same, port 22 | Nothing extra | Reaches sshd only | No access without the enrolled SSH key |
| Same, default boot, nothing bound | Hostname | No impact | CONNECT to a port with no listener returns 502; ports can be enumerated (404 for unpublished) |
| confidential-ubuntu / confidential-debian (`authenticated: false`, only `22:22`) | Hostname | Not materially | Reaches pubkey-only sshd |
| Any deployment with `authenticated: true` | n/a | No | 401 without a valid key; tunnels disabled if no validator (`api.go:305-306`) |
| Any customer config with default `authenticated: false` plus non-SSH `ports:` | Hostname + a listening service | Yes | Same as the sandbox |

Preconditions verified in code:
- `authenticated: false` and the 16 ports are in the measured sandbox config (`tinfoil-config.yml:50-66,87-93`).
- Published ports are bound on `127.0.0.1` (`cvmimage/tinfoil/internal/containers/containers.go:556-581`,
  `internal/containernet/network.go:20`), which is exactly what the tunnel dials.
- `nftables.conf:39` accepts TCP 443 from any source.
- The owner gate (seal / RTMR3 check, optional API key) is only in the client (`tinfoil-cli` @ `9e53ba4`,
  `tunnel.go:372-373` sends `Authorization` only if a key is configured).
- In the default `cert-proxy` TLS mode the sandbox domain is a SAN of a publicly trusted certificate
  (`cvmimage/tinfoil/cmd/boot/cert.go:37-80`). Two verifiers read public CT data via Cert Spotter (crt.sh was
  returning 502) and found many `<words>-<8 chars>.box2.tinfoil.sh` names.

Unverified production facts (no Tinfoil host was contacted):
- That a sandbox's port 443 accepts connections from arbitrary sources with no authenticating edge. The CLI
  dials `<domain>:443` directly and pins the enclave key, which strongly suggests no edge.
- That live sandboxes run this shim code. Cvm-version 0.14.8 is not in the public cvmimage history at HEAD. A
  verifier fetched the shim sources at public tag v0.14.8 and found the same logic.
- Which CT-listed `box2` names are agent sandboxes, and whether any of them have services bound.
- That inner-docker `-p` mappings reach the outer `127.0.0.1` DNAT (plausible; not exercised).

Out of scope / not affected: deployments with `authenticated: true`; configs that publish only port 22. The
`confidential-sandbox-gpu` v0.15.x line is built from a non-public repo and was not checked.

## Severity
- Typical case (dev web server, file server): `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` = **4.8**.
- Upper bound (password-less database, DevTools, VNC/RDP bound by the owner or agent):
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` = **7.4**.
- Default sandbox with nothing bound: no impact beyond port enumeration.

AC:H is used because success depends on a service that the attacker does not control being bound on a
published port. REPORT.md scored `AC:L/C:L/I:L` = 6.5. All three verifiers used AC:H, so this disclosure
uses AC:H. Two verifiers rated the finding Medium. One rated it Low: the vendor documents the behaviour as
intended, and the exposure is created by the owner, as on any public VM. We report it as Medium for three
reasons. The sandbox runs an autonomous agent that binds such services routinely. Tinfoil's runtime-policy
doc and CLI help say the opposite of the behaviour. And the user is never told.

## Technical details
`cvmimage/tinfoil/cmd/shim/main.go:259-287` (HEAD `58b08de`) creates a validator only when
`authenticated` is true:

```go
var validator key.Validator
if config.ControlPlane != "" {
    ...
    if config.Authenticated {
        ... validator = &metricsValidator{...}
    } else {
        log.Println("Warning: API key verification disabled (unauthenticated endpoint)")
    }
}
```

`api.go:246-248`: the CONNECT check is skipped when there is no validator:

```go
// A CONNECT carries no path for requiresAuth to match, so it always needs a key.
authorize := func(w http.ResponseWriter, r *http.Request) bool {
    apiKey := extractBearerToken(r.Header.Get("Authorization"))
    if validator != nil && (r.Method == http.MethodConnect || requiresAuth(...)) {
```

The rate limiter, the only other key check, is nil because `rate-limit` is unset. `api.go:305-306` fails
closed only for `authenticated: true` with no validator. `tunnel.go:50-101` calls `authorize`
(line 63) and then `targets[port]` (line 67, 404 for unpublished ports). It then dials
`127.0.0.1:<port>` (lines 78-79) and relays bytes. The comment above line 63 says an unkeyed CONNECT
gets 401. That holds only when a validator exists. Without one, the 200/404 difference also reveals which
ports are published. Tinfoil's own test `tunnel_test.go:134` (`TestTunnelReachesPublishedPortOnly`)
asserts that a tunnel with no validator returns 200 for a keyless CONNECT.

## Proof of concept
`poc/poc_sandbox_tunnel_test.go` is one test file that goes into `cvmimage/tinfoil/cmd/shim/` at
`58b08de`. It uses the existing package helpers `publishedPorts`, `connectTo` and `fakeValidator`.

- It parses the 16 ports from the real sandbox config (`d78ec38`) using the shipped `publishedPorts`.
- It binds a stub TCP service on `127.0.0.1:<port>` for each port. The stub answers `PING` with `+PONG`,
  like a password-less Redis.
- It builds the shipped `NewShimServer` the way `main.go` does for `authenticated: false`
  (`validator == nil`), behind a real TLS + HTTP/2 `httptest` server.
- It sends an HTTP/2 CONNECT with an empty header set to each port.
- Controls: `authenticated: true` with a validator gives 401. `authenticated: true` without a validator
  gives 404, because tunnels are disabled.

Run (as root, because the stub binds `127.0.0.1:22`):

```
cd poc && ./run.sh
```

`run.sh` clones the local pristine cvmimage into `/root/tinfoil-review/work/disclosures/14/`, checks out
`58b08de`, extracts `tinfoil-config.yml` from confidential-agent-sandbox `d78ec38`, copies the test in,
and runs `go test ./cmd/shim/ -run TestPoC_ -v`. Output from the run on 2026-10-11 (full output in
`poc/expected-output.txt`):

```
poc_sandbox_tunnel_test.go:105: confidential-agent-sandbox publishes 16 ports: 22 3000 3001 3306 3389 4000 5000 5173 5432 5900 6379 8000 8001 8888 9000 9222
poc_sandbox_tunnel_test.go:130: port  6379: anonymous CONNECT -> 200, service replied "+PONG (stub on published port 6379)"
poc_sandbox_tunnel_test.go:130: port  9222: anonymous CONNECT -> 200, service replied "+PONG (stub on published port 9222)"
poc_sandbox_tunnel_test.go:138: RESULT: an unauthenticated internet client reached a service on all 16 published sandbox ports through the shim tunnel
poc_sandbox_tunnel_test.go:143: port  8080 (not published): anonymous CONNECT -> 404 (Not Found)
poc_sandbox_tunnel_test.go:155: control authenticated:true + validator, keyless CONNECT -> 401
poc_sandbox_tunnel_test.go:163: control authenticated:true, no validator, keyless CONNECT -> 404 (tunnels disabled)
PASS
```

What is simulated: the services are stubs on loopback. The attestation document passed to
`NewShimServer` is a dummy because it is not used on the CONNECT path. The PoC exercises the shim
library behind a real HTTP/2 TLS server, not a booted CVM. The Docker DNAT from the container to
`127.0.0.1:<port>` is taken from code. The original hunter and verifier evidence is in
`/root/tinfoil-security-findings/sandbox-tunnel-no-auth/`.

## Impact
Anyone who reads a sandbox hostname from CT logs can use any service that the user or their coding agent
started on a published port: a dev database with no password, a `python -m http.server` exposing the
working tree and any tokens in it, a Chrome DevTools endpoint with the user's logged-in sessions, or a
VNC/RDP desktop. The sandbox holds the user's working files and has open egress, so a compromised dev
service gives direct access to that data. The user is told that the sandbox is sealed to their disk key
and that ports are private. Nothing tells them otherwise.

### Affected downstream packages

- `confidential-agent-sandbox` `d78ec38` (cvm-version `0.14.8`): publishes 16 ports with `authenticated: false`, so all 16 are reachable anonymously
- `confidential-ubuntu` and `confidential-debian`: `authenticated: false` but only port 22 published (SSH key still required)
- `tinfoil-config` `043b28e`: `authenticated` defaults to `false`, so any customer container config that publishes ports inherits the exposure

## Remediation
- In the shim, require a credential on CONNECT to non-SSH ports even when `authenticated` is false for
  HTTP paths. A good option is a secret bound to the enrolment (derived at `/enroll` from the permit or the
  disk key) that `tinfoil forward --sandbox` sends as a bearer. Do not rely on `validator != nil` for
  CONNECT.
- Short term: publish only `22:22` in the sandbox config, or set `authenticated: true`. Alternatively, add
  an explicit per-port opt-in such as `public: true` for ports meant to be reachable anonymously.
- Make the 401 for unkeyed CONNECTs unconditional so ports cannot be enumerated (the comment above
  `tunnel.go:63` intends this).
- Fix the documentation (`runtime-policy.md`, `tinfoil-config/README.md`, CLI help), or make it true.

## References
- REPORT.md Finding 14; evidence `/root/tinfoil-security-findings/sandbox-tunnel-no-auth/`.
- Verifier verdicts: `verification-verdicts-round2.json`, key
  `sandbox-containers-keyserver/sandbox-tunnel-no-auth-all-published-ports` (2/3 upheld; one Low).
- Related: Finding 7 (`disclosures/07-gateway-catalog-chooses-trusted-repo/`), where the catalog trusts `cvm_admin` dev-box releases
  that also use `authenticated: false`.
