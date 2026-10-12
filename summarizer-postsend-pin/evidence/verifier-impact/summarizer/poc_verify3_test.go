package main

// Verifier PoC (local only, no external network): drives the summarizer's real
// HTTP handler (service.go) and real upstream code (upstream.go) through the
// exact TLS transport that tinfoil-go v0.11.3 / verifier v0.11.2 returns from
// SecureClient.HTTPClient() after a successful Verify():
//
//     &http.Client{Transport: &TLSBoundRoundTripper{groundTruth.TLSPublicKey}}
//
// The interceptor holds a certificate that chains to the process trust store
// (stand-in for a WebPKI cert for the router hostname) but NOT the attested
// key. We record the order of events to show the full request (user content +
// Authorization) is delivered before the client-side pin check fires.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/sirupsen/logrus"
	"github.com/tinfoilsh/verifier/attestation"
	verifierclient "github.com/tinfoilsh/verifier/client"

	"github.com/tinfoilsh/confidential-summarizer/config"
)

var v3CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// localOnlyProxy makes it impossible for anything in this test process that
// uses http.DefaultTransport to reach a non-loopback host.
func localOnlyProxy(req *http.Request) (*url.URL, error) {
	host := req.URL.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil, nil
	}
	return nil, fmt.Errorf("PoC guard: blocked non-local request to %s", req.URL.Host)
}

func TestMain(m *testing.M) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PoC stand-in public CA"},
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
	v3CA.cert, _ = x509.ParseCertificate(der)
	v3CA.key = key
	dir, _ := os.MkdirTemp("", "poc-v3-ca")
	path := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	// System trust store stand-in (read lazily by crypto/x509 on first use).
	os.Setenv("SSL_CERT_FILE", path)
	os.Setenv("SSL_CERT_DIR", dir)
	http.DefaultTransport.(*http.Transport).Proxy = localOnlyProxy
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func v3Leaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "router hostname (interceptor-held, non-attested key)"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, v3CA.cert, &key.PublicKey, v3CA.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type eventLog struct {
	mu     sync.Mutex
	start  time.Time
	events []string
	auth   string
	body   string
	nreq   int
}

func (e *eventLog) add(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, fmt.Sprintf("+%6.2fms  ", float64(time.Since(e.start).Microseconds())/1000)+fmt.Sprintf(format, args...))
}

func TestVerify3_SummarizerEndToEndLeakBeforePinCheck(t *testing.T) {
	ev := &eventLog{start: time.Now()}

	// Attested ("genuine enclave") TLS key: what Verify() would have pinned.
	enclaveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinnedFP := attestation.KeyFP(&enclaveKey.PublicKey)

	interceptor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ev.mu.Lock()
		ev.nreq++
		ev.auth = r.Header.Get("Authorization")
		ev.body = string(b)
		ev.mu.Unlock()
		ev.add("INTERCEPTOR: received complete request %s %s (%d body bytes, Authorization present=%v)", r.Method, r.URL.Path, len(b), r.Header.Get("Authorization") != "")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"Forged title"}}]}`)
	}))
	interceptor.TLS = &tls.Config{Certificates: []tls.Certificate{v3Leaf(t)}}
	interceptor.StartTLS()
	defer interceptor.Close()

	// Same OpenAI client options as production (upstream.go openAIClientOptions)
	// plus what tinfoil-go v0.11.3 createClientFromSecureClient adds.
	httpClient := &http.Client{Transport: &verifierclient.TLSBoundRoundTripper{ExpectedPublicKey: pinnedFP}}
	oc := openai.NewClient(append(openAIClientOptions("sk-SUMMARIZER-TINFOIL-API-KEY"),
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(interceptor.URL+"/v1/"))...)

	var logBuf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logBuf)
	svc := newSummaryService(newOpenAIUpstream(&oc, config.DefaultModel), defaultUpstreamTimeout, logger)

	secret := "My first chat message: I was just diagnosed with early-onset Parkinson's and haven't told my employer"
	reqBody, _ := json.Marshal(map[string]any{"content": secret, "style": "title_summary"})
	rec := httptest.NewRecorder()
	ev.add("CLIENT: POST /summarize to summarizer handler")
	svc.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/summarize", bytes.NewReader(reqBody)))
	ev.add("CLIENT: summarizer returned HTTP %d body=%s", rec.Code, strings.TrimSpace(rec.Body.String()))

	for _, e := range ev.events {
		t.Log(e)
	}
	t.Logf("interceptor saw %d request(s); Authorization=%q", ev.nreq, ev.auth)
	t.Logf("interceptor saw body: %s", ev.body)
	t.Logf("summarizer log: %s", strings.TrimSpace(logBuf.String()))

	if ev.nreq == 0 || !strings.Contains(ev.body, secret) {
		t.Fatalf("NOT REPRODUCED: interceptor did not receive the user content")
	}
	if ev.auth != "Bearer sk-SUMMARIZER-TINFOIL-API-KEY" {
		t.Fatalf("NOT REPRODUCED: interceptor did not receive the API key")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("unexpected: client accepted the forged response")
	}
	t.Log("REPRODUCED: full plaintext request (user content + API key) delivered to a non-attested TLS peer before the pin check rejected the response")
}
