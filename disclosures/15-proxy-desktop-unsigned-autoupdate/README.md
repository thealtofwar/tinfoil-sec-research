# Tinfoil Proxy desktop app installs unsigned auto-updates on Windows and Linux

| | |
|---|---|
| Component | `github.com/tinfoilsh/tinfoil-proxy` desktop app (Windows and Linux builds): `v0.2.3` (latest release) and `v0.3.0-rc.2` (HEAD `74d105c`) |
| Severity | Medium / hardening (CVSS 3.1 `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` = 6.8 for an OS-trusted TLS intermediary; marginal value Low-Medium against a release-channel compromise) |
| Bug class | CWE-494 (Download of Code Without Integrity Check), CWE-347 (Improper Verification of Cryptographic Signature) |
| Attacker position | Control of what the app receives from the GitHub release feed: release-asset write access, or a TLS-terminating intermediary trusted by the victim's OS, or a mis-issued certificate for github.com |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary
The desktop app downloads and installs updates on its own at launch and every 6 hours. On Windows and
Linux the only integrity check is a SHA-512 that comes from the same GitHub feed as the installer. The
Windows builds have no Authenticode signature, and `app-update.yml` has no `publisherName`. electron-updater
6.8.9 therefore skips its signature check entirely. The Linux `.deb` is installed with
`pkexec ... dpkg -i` and no signature check. Anyone who can serve release metadata and an installer in
place of GitHub's runs code on every Windows and Linux desktop user. On Windows this runs silently at
the next app quit. On Linux it runs as root after the user accepts the polkit prompt. That defeats every
confidentiality property the proxy provides. The precondition is control of a trust anchor (the release
channel or an OS-trusted TLS position), so we rate this Medium, as a hardening gap.

## Threat model
Tinfoil's promise (`tinfoil-proxy/README.md:3`): the proxy "encrypts request and response bodies ... so
neither the gateway nor any other intermediary can read them". The desktop app runs that binary
(`README.md:189`). Whoever controls the update controls the binary and the API key.

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Windows NSIS app, release-asset writer (stolen maintainer or CI token, GitHub-side compromise) | Write access to `tinfoilsh/tinfoil-proxy` releases | Yes | Code as the user, silent at next quit. Signing would only be defence-in-depth here if the CI also holds the signing key |
| Windows NSIS app, TLS-terminating intermediary trusted by the OS (enterprise TLS inspection) or CA mis-issuance for github.com | HTTPS responses for `github.com` / `objects.githubusercontent.com` | Yes | Same. Signing would stop this |
| Linux `.deb` app, either position above | Same | Yes, after the user approves a generic polkit prompt to run `/bin/bash` as root | Root code execution |
| Any platform, plain on-path attacker without a trusted certificate | Network path only | No | TLS fails |
| macOS app | Any of the above | No | Squirrel.Mac requires a matching Developer ID signature; the mac build is signed and notarized |
| CLI binary, Docker image, `install.sh` | n/a | Not via this path | Not auto-updated by electron-updater |

Verified in code and artifacts:
- `app/src/main/updater.ts:11-14,37-42` sets `autoDownload = true` and `autoInstallOnAppQuit = true` and
  checks for updates at start and every 6 h. `app/src/main/index.ts:59` starts it on every platform.
- `app/electron-builder.yml` has no `win.publisherName`, no signing configuration and no `forceCodeSigning`.
- `.github/workflows/release.yml:111-122` gives signing secrets only to the macOS job. Lines 124-128 give the
  Windows and Linux job `GH_TOKEN` only.
- The public v0.2.3 `Tinfoil-Proxy-Setup.exe`, the bundled `resources/bin/tinfoil-proxy.exe` and
  `resources/elevate.exe`, and `tinfoil-proxy-windows-amd64.exe` all have an empty PE security directory.
  The `app-update.yml` inside the installer and the one inside the `.deb` contain no `publisherName`. The
  `.deb` ships `resources/package-type = deb`, which makes electron-updater use `DebUpdater`. A verifier
  found the same for the v0.3.0-rc.2 installer.
- `README.md:189` says "macOS and Windows builds auto-update". The Linux `.deb` auto-updates as well.

Unverified production facts:
- GitHub-side protections on the release path: the `release` environment rules, required reviewers, 2FA,
  token scope, and who holds write access.
- How many Windows and Linux desktop-app users exist. The README steers most users to the CLI.
- Whether victims' Linux desktops run a polkit agent (`pkexec --disable-internal-agent` needs one).
- How Windows SmartScreen and UAC treat the spawned silent per-user NSIS installer. Not observed. The code
  spawns it with `child_process.spawn` and no Mark-of-the-Web, and the install is per-user.

## Severity
- OS-trusted TLS intermediary or CA mis-issuance, Windows or Linux:
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` = **6.8**. UI:R counts the app quit on Windows and the
  polkit approval on Linux. One verifier argued for UI:N on Windows (8.1), because quitting the app is
  routine.
- Release-channel compromise: the score is similar, but signing in CI is only defence-in-depth there.
  The release job runs `npm ci` and `electron-builder` with `GH_TOKEN`, and a malicious dependency would
  also see any CI-held signing key unless the key sits in an HSM or a cloud signing service.

Verifiers split 2/3. The code-trace and impact reviewers rated it Medium (6.8 and 7.5-8.1 nominal). The
PoC reviewer confirmed every fact but rated it Low, because exploitation presupposes a compromised trust
anchor. We report **Medium / hardening**. The client-side behaviour is certain. The realistic attacker is
an enterprise TLS-inspection box or a stolen release token, not an arbitrary network attacker.

## Technical details
electron-updater 6.8.9, `out/NsisUpdater.js:84-100`. The update is accepted when `verifySignature`
returns null (`:52`):

```js
async verifySignature(tempUpdateFile) {
    let publisherName;
    try {
        publisherName = (await this.configOnDisk.value).publisherName;
        if (publisherName == null) {
            return null;            // no Authenticode check at all
        }
```

app-builder-lib 26.16.1, `out/publish/PublishManager.js:202-206`, writes `publisherName` only when a
Windows signing identity exists. The tinfoil-proxy release has none, so the shipped config is:

```
owner: tinfoilsh
repo: tinfoil-proxy
provider: github
releaseType: release
updaterCacheDirName: tinfoil-proxy-updater
```

On quit, `BaseUpdater.js:70-88` calls `install(true, false)`, which runs the installer with
`--updated /S` (`NsisUpdater.js:107-109`). On Linux, `DebUpdater.js:33-51` runs `dpkg -i` through
`LinuxUpdater.js:34-51` (`pkexec --disable-internal-agent /bin/bash -c 'dpkg -i <cache path>'`). The only
other check is the SHA-512 from `latest.yml` / `latest-linux.yml`, which the attacker serves too.

## Proof of concept
`poc/run.sh` (with `poc/pe_sigcheck.py` and `poc/harness.cjs`):

- **A. Artifact analysis.** It checks that the local copies of the public v0.2.3 assets match the release's
  own `latest*.yml` SHA-512, and parses the PE security directory of four Windows binaries. It extracts
  `app-update.yml` from the NSIS installer with `7z` and from the `.deb` with `dpkg-deb`, and checks for
  `publisherName`. `run.sh` does not download anything from GitHub. It uses copies fetched earlier in the
  review. To reproduce elsewhere, fetch the assets from
  `https://github.com/tinfoilsh/tinfoil-proxy/releases/download/v0.2.3/` and set `ARTIFACTS=<dir>`.
- **B. Loopback update simulation.** It installs exactly `electron-updater@6.8.9` from npm. It configures
  `NsisUpdater` and `DebUpdater` with the shipped `app-update.yml` and `autoDownload` /
  `autoInstallOnAppQuit` as in `updater.ts`. A fake GitHub feed on 127.0.0.1 serves a forged release
  v9.9.9 whose payload is arbitrary bytes, with a matching SHA-512 in its own `latest*.yml`.
- **Negative control.** The same feed and payload, with `publisherName` added to the Windows config. That
  is the field a signed build ships.

Run: `cd poc && ./run.sh` (needs python3, 7z, dpkg-deb, openssl, node 24 and npm). Output from the run on
2026-10-11 (full output in `poc/expected-output.txt`):

```
Tinfoil-Proxy-Setup.exe: sha512 matches latest.yml (v0.2.3)
Tinfoil-Proxy-Setup.exe: PE32 security_dir(offset=0x0, size=0) -> NO AUTHENTICODE SIGNATURE
<installer>/resources/bin/tinfoil-proxy.exe: PE32+ security_dir(offset=0x0, size=0) -> NO AUTHENTICODE SIGNATURE
publisherName absent in both
[windows-shipped-config] Authenticode verifier calls: 0
[windows-shipped-config] update-downloaded version=9.9.9; file is the attacker payload: true
[windows-shipped-config] install command on quit: <run>/windows-shipped-config/cache/tinfoil-proxy-updater/pending/Tinfoil-Proxy-Setup.exe --updated /S
[linux-shipped-config] update-downloaded version=9.9.9; file is the attacker payload: true
[linux-shipped-config] install command on quit: pkexec --disable-internal-agent /bin/bash -c 'dpkg -i <run>/linux-shipped-config/cache/tinfoil-proxy-updater/pending/tinfoil-proxy_amd64.deb'
[control-windows-with-publisherName] Authenticode verifier calls: 1
[control-windows-with-publisherName] update REJECTED: New version 9.9.9 is not signed by the application owner: ...
```

What is simulated:
- The harness runs under Node on Linux, not Electron on Windows. The GitHub provider is pointed at
  `127.0.0.1` over HTTP by appending `host:` and `protocol:` to a copy of the shipped config. This stands in
  for the attacker's position: they control the release, or they terminate TLS with a trusted certificate.
- Electron's `net` executor is replaced by Node `http`.
- Install commands are recorded, not run.
- On Linux there is no PowerShell, so the Authenticode verifier is a stub that reports "not signed", which
  is what Windows reports for this payload. The finding is that it is called 0 times with the shipped
  config. The control shows it is called and blocks the update once `publisherName` is set.

Original evidence: `/root/tinfoil-security-findings/proxy-desktop-unsigned-autoupdate/`. The verifier's
fuller harness, including an attacker-set `isAdminRightsRequired` that requests UAC elevation, is in
`/root/tinfoil-review/work/verify2/local-clients--proxy-desktop-unsigned-autoupdate--impact/poc/`.

## Impact
An attacker in either position replaces the Tinfoil Proxy on users' machines. On Windows the replacement
runs silently as the user the next time the app quits. If the attacker sets `isAdminRightsRequired`, it
can also request UAC elevation. On Linux it runs as root after a routine-looking authentication prompt.
The attacker can then read the user's Tinfoil API key, prompts and responses. The proxy is installed to
keep that data private.

## Remediation
- Sign the Windows installer and all bundled executables with Authenticode, for example with Azure
  Trusted Signing or an HSM-held key, so the key is not extractable by a CI dependency. Set
  `win.publisherName` (or `win.signtoolOptions.publisherName`) so that `app-update.yml` carries it and
  electron-updater enforces the check. Consider `forceCodeSigning: true` so an unsigned build fails.
- Linux: do not auto-install the `.deb` through pkexec. Point users to a signed apt repository, or verify a
  detached signature (minisign or GPG, with the key pinned in the app) before calling `dpkg`.
- Defence-in-depth independent of GitHub: sign `latest*.yml` with a key embedded in the app and verify it
  in a custom `verifyUpdateCodeSignature` or a pre-download hook. Until signing is in place, set
  `autoInstallOnAppQuit = false`.
- Fix `README.md:189` to say that Linux builds also auto-update.

No fix was validated beyond the negative control (adding `publisherName` makes electron-updater run and
enforce the check).

## References
- REPORT.md Finding 15; evidence `/root/tinfoil-security-findings/proxy-desktop-unsigned-autoupdate/`.
- Verifier verdicts: `verification-verdicts-round2.json`, key `local-clients/proxy-desktop-unsigned-autoupdate`
  (2/3 upheld; one Low/hardening).
- electron-updater documentation on Windows code-signature verification (`publisherName`).
