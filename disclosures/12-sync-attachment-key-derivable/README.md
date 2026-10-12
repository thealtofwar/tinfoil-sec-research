# confidential-sync: forked attachment keys are derivable by the control plane from metadata plus a guessed plaintext

| | |
|---|---|
| Component | `github.com/tinfoilsh/confidential-sync`: HEAD `4acbf16` (2026-10-05) |
| Severity | Medium, low end (CVSS 3.1 `AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N` = 4.2 for the primary scenario) |
| Bug class | CWE-330 / CWE-321 (key derived from non-secret, attacker-known inputs; convergent encryption, confirmation-of-file) |
| Attacker position | Tinfoil's control-plane operator (`api.tinfoil.sh`), or anyone with read access to its database or request logs |
| Status | Unfixed at upstream HEAD as of 2026-10-08; not disclosed |

## Summary

The sync enclave derives both the id and the AES-256 key of an attachment with HKDF over
`(idempotency_key, chat_id, clerk_sub, sha256(plaintext))`. No secret is mixed in. When a user
forks ("branches") a synced chat, the enclave copies each attachment and builds the copy's
idempotency key from the fork's idempotency key, the source attachment id and the index. The enclave
sends all of these values to the control plane. The control plane operator can therefore test any
candidate plaintext offline: if the derived id equals the id in its own attachment index, the guess
is correct. The same derivation yields the key, and `POST /v1/attachment/get-public` returns the
plaintext to anyone who presents `(id, key)`, with no authentication. Unguessable, high-entropy
content stays protected; the attack confirms or brute-forces guessable content only.

## Threat model

What the product promises:

- `confidential-sync/README.md:3`: "the enclave seals and unseals data inside the confidential VM and
  stores only ciphertext, so neither Tinfoil nor the storage layer can read chats."
- `confidential-sync/internal/crypto/ophash.go:17-22` treats the control plane as inside the threat
  boundary and rejects exactly this construction for another value: "a plain SHA-256(plaintext)
  would be brute-forceable against low-entropy payloads (profile flags, short prompts, common
  templates). We therefore key the MAC on a subkey derived from the user's CEK that the controlplane
  never sees."

| Deployment mode / attacker | What they must control | Exploitable? | Result |
|---|---|---|---|
| Tinfoil Chat cloud sync, attachment created by **fork** / control-plane operator or CP DB/log reader | Its own records: `X-Idempotency-Key` + `X-Clerk-User-Id` on `PUT /api/sync/blob/chat/{fork}`, and `/api/sync/attachment-index/{id}` rows (id, chat_id). A candidate plaintext. | Yes (reproduced) | Offline confirmation that an attachment equals a candidate; recovery of enumerable content (short text, small option sets) via `get-public` |
| Same, attachment created by **import** (native backup restore) | As above plus the archive-internal path (`attachments/<id>/<fileName>`) | Likely (code reading only, not reproduced) | Same |
| Same, import of ChatGPT/Claude exports | Vendor-random archive file names | Not realistic | None |
| First-time upload from the webapp | Would also need the client `crypto.randomUUID()` attachment id, which never leaves the browser | No (from CP position) | None |
| Legacy attachment promoted to v2 (`rewrap.go`) | Random legacy key is reused | No | None |
| S3 / storage-layer holder alone | Lacks chat id, idempotency key, user id | No | Objects are sealed under the derived key |
| Network intermediary | TLS terminates inside the enclave | No | None |
| Any internet client, after the CP derived `(id, key)` | Nothing; the route is unauthenticated | Yes, as the fetch step | Plaintext bytes |

Preconditions, verified in code:

- `deriveAttachmentMaterials` uses no secret (`internal/server/attachment_ops.go:94-133`; comment at
  `:45` "No CEK material flows on this request").
- Fork copies use `forkAttachmentIdemKey(req.IdempotencyKey, sourceAttachmentID, index)`
  (`internal/server/fork_ops.go:277-281`, `:300-303`).
- The fork's own idempotency key is forwarded verbatim to the CP as `X-Idempotency-Key`
  (`fork_ops.go:124-132` -> `ops.go:157` -> `internal/controlplane/client.go:426-427`).
- The CP receives `(attachment id, chat id, user)` for every attachment (`attachment_ops.go:218-224`,
  `controlplane/client.go:1347-1357`).
- `/v1/attachment/get-public` has no auth middleware (`internal/server/http.go:116-125`) and is listed
  in `tinfoil-config.yml:73` `shim.paths`.
- The webapp sends a random 128-bit fork idempotency key and nothing secret
  (`tinfoil-webapp/src/services/cloud/cloud-sync.ts:806-810`, `src/services/sync-enclave/sync-api.ts:1372-1379`).

Unverified production facts:

- That `api.tinfoil.sh` persists or logs `X-Idempotency-Key` (`ophash.go:17` says the CP stores
  idempotency data in `sync_idempotency_keys`) and keeps the attachment index rows.
- That the deployed enclave matches HEAD. `tinfoil-config.yml` pins an all-zero placeholder image
  digest. The comment at `attachment_ops.go:118` says "The attachment feature has not yet been
  released"; the webapp at `c061681` already uses it. If the feature is not live, this is a
  pre-release design flaw with no current victims.
- The sidecar image digest in `tinfoil-config.yml` was not mapped to commit `b89fcc1`.

Out of scope / not affected: first-time uploads, legacy-promoted attachments, third-party imports
(see table). No integrity or availability impact.

## Severity

- Primary (CP operator as privileged insider, victim must fork, guessable content):
  `CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N` = **4.2**.
- Same, scoring the CP as an outside adversary because the product says Tinfoil cannot read chats:
  `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` = 5.3.
- Confirmation-only (attacker learns only "equal / not equal"):
  `CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N` = 2.0.

Three independent verifiers upheld the finding (confidence 0.7 to 0.9) and all assessed Medium. They
scored between 3.0 and 5.9 depending on how the CP and `C:` are treated. I rate it Medium (low end):
the oracle is cheap (one SHA-256 + HKDF per guess), silent, works across all users, and is the exact
weakness the designers rule out in `ophash.go`. It is not High: nothing leaks about content the
attacker cannot enumerate. Images are re-encoded in the browser before upload, so "known image"
guesses are brittle; text/document payloads (`{"textContent": ...}`) are the realistic target.

## Technical details

`internal/server/attachment_ops.go:94-133` (abridged):

```go
func deriveAttachmentMaterials(idempotencyKey, chatID, clerkSubject string, plaintext []byte) (string, []byte, error) {
	plaintextDigest := sha256.Sum256(plaintext)
	ikm := encodeIKM(idempotencyKey, chatID, clerkSubject, hex.EncodeToString(plaintextDigest[:]))
	idBytes := make([]byte, attachmentIDBytes)
	io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte(attachmentIDInfo)), idBytes)   // "tinfoil-attachment-id-v1"
	key := make([]byte, attKeySize)
	io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte(attachmentKeyInfo)), key)      // "tinfoil-attachment-key-v1"
	return hex.EncodeToString(idBytes), key, nil
}
```

`internal/server/fork_ops.go:300-303`:

```go
func forkAttachmentIdemKey(forkIdemKey, sourceAttachmentID string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("fork-att:%s:%s:%d", forkIdemKey, sourceAttachmentID, index)))
	return hex.EncodeToString(sum[:16])
}
```

For a forked attachment every IKM input except the plaintext is CP-visible:
`forkIdemKey` (header on the fork's chat PUT), `sourceAttachmentID` (attachment index), `index`
(order), `chatID` (fork id in the blob path), `clerkSubject` (`X-Clerk-User-Id`). The derived id is
stored in the CP's own attachment index, so a match confirms the guess without contacting the
enclave. `AttachmentGet` (`attachment_ops.go:267-309`) resolves the owner through the CP and returns
the plaintext to any caller with a matching key via the unauthenticated route.

The import path has the same shape: `import_ops.go:434-437` uses
`sha256("import-att:"+chatID+":"+archiveRef+":"+idx)[:16]` (`import_ops.go:294`, `import_native.go:690-693`).

## Proof of concept

`poc/poc_attachment_key_test.go` is one Go test. `poc/run.sh` exports the unmodified source at
`4acbf16` from the local clone (`git archive`), drops the test into
`internal/localstack/smoke/`, and runs it. Build tree: `/root/tinfoil-review/work/disclosures/12/`.

```
cd poc && ./run.sh
```

What it does:

1. Starts the real enclave handler (`server.NewHandler`), the repo's own stub control plane
   (`localstack.NewStubCP`, which also serves the buckets API) and a JWKS listener, exactly like
   `localstack.Start`. The only addition is a recorder around the stub CP handler, so the test sees
   what a real control plane receives. No enclave code is changed.
2. Victim (random CEK, normal JWT): uploads a document attachment, pushes the chat, forks it with a
   random idempotency key, as the webapp does.
3. Attacker: reads only the recorded CP requests, derives the fork copy's id for each of three
   candidate plaintexts, finds the match offline, then calls `get-public` with no `Authorization`
   header using the derived key.
4. Negative control: the key derived from a wrong candidate is rejected (400).

Output from a run on 2026-10-11 (`poc/expected-output.txt`):

```
CP saw: PUT /api/sync/blob/chat/chat-victim-1-branch X-Idempotency-Key=68d231bac63d4ad7cc1e72b92a116fd4 X-Clerk-User-Id=user_victim; attachment-index src=29d46b94... fork=937bf0b4...
offline guess "{\"textContent\":\"Lab result: HIV negative. Patient: J. Doe\"}" -> id 8161c5a3... match=false
offline guess "{\"textContent\":\"Lab result: HIV positive. Patient: J. Doe\"}" -> id 937bf0b4... match=true
RESULT offline: CP confirmed forked attachment 937bf0b4231d6bc369ad326443de2c3fa1f6 content without any user secret
RESULT get-public (no Authorization header) with CP-derived key: 200 "{\"textContent\":\"Lab result: HIV positive. Patient: J. Doe\"}"
CONTROL wrong-guess key -> 400 {"code":"BAD_REQUEST","message":"attachment key does not match","ok":false}
--- PASS: TestDisclosure12_ForkedAttachmentKeyDerivableByControlPlane
```

Stubs and why they do not change the result:

- Control plane and buckets are the repo's `StubCP`. The attacker only reads request headers and
  paths that the enclave itself sends; the enclave's derivation and the get-public route are shipped
  code.
- The key check in this PoC is done by the stub buckets. The hunter and a verifier repeated the
  attack with the unmodified enclave binary, the real `tinfoil-buckets-sidecar` jar built from
  `b89fcc1` (MULTITENANT=true) and moto S3: `UNAUTHENTICATED get-public: 200 b'\x89PNG known-file-bytes...'`,
  wrong guess 400 `attachment key does not match`. Raw S3 objects were sealed, so the plaintext is
  only reachable through the enclave route.
- The fix was not validated locally.

Full original evidence: `/root/tinfoil-security-findings/sync-attachment-key-derivable/evidence/hunter/`
and the verifier directories under `/root/tinfoil-review/work/verify2/sync-and-storage--sync-attachment-key-derivable-from-cp-metadata--*`.

## Impact

For any chat a user has branched (or restored from a native backup), the control-plane operator, or
anyone who obtains its database or logs, can:

- check offline whether an attachment equals a specific file, across all users, without touching
  the enclave (for example: "who holds this leaked document");
- recover attachments whose content comes from a small set (a short note, a form with a few
  possible values, a known template with a guessable field) and fetch the bytes through the
  enclave with no credential.

This contradicts the README statement that Tinfoil cannot read chats. Attachments with unguessable
content are not exposed.

### Affected downstream packages

- `tinfoil-webapp` (`c061681`): the "branch conversation" action with cloud sync on creates the affected fork-copied attachments
- `tinfoil-buckets-sidecar` (`b89fcc1`) seals objects under the key the enclave supplies, so it inherits the weakness; it is not itself at fault

## Remediation

- Mix a secret the control plane never sees into the attachment IKM. Options: send the user's CEK on
  `/v1/attachment/put` (and use it in fork/import, where it is already present in the request) and set
  the HKDF salt to `HKDF(CEK, info="tinfoil-attachment-salt-v1")`; or use fresh random keys and store
  the key wrapped under the CEK so retries return the existing wrapped key.
- Do not derive attachment ids or keys from idempotency keys that are forwarded to, or reconstructible
  by, the control plane (fork and import).
- Make the attachment id independent of the key material (random id), so the CP index is not an
  offline oracle even if the key derivation changes later.
- Defence in depth: rate-limit `/v1/attachment/get-public`, or require a share capability token
  distinct from the decryption key.

## References

- REPORT.md Finding 12 (`sync-attachment-key-derivable/`).
- `verification-verdicts-round2.json`, key `sync-and-storage/sync-attachment-key-derivable-from-cp-metadata` (3/3 upheld).
- Design rule this violates: `confidential-sync/internal/crypto/ophash.go:17-22`.
