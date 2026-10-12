package tinfoil

// Verifier PoC (local only). Uses the shipped tinfoil-go v0.11.3 transport
// stack exactly as createClientFromSecureClient builds it:
//
//   httpClient := secureClient.HTTPClient()   // &http.Client{Transport: &client.TLSBoundRoundTripper{groundTruth.TLSPublicKey}}
//   httpClient.Transport = &reVerifyingTransport{secureClient, httpClient.Transport}
//
// The only substitution is that the post-Verify() ground-truth TLS key is
// supplied directly (Verify() needs live attestation + Sigstore + GitHub).
// All non-loopback traffic is blocked so the re-verification that
// reVerifyingTransport triggers on ErrCertMismatch fails closed locally.

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
	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/client"
)

var pocCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var blocked struct {
	mu    sync.Mutex
	hosts []string
}

func localOnlyProxy(req *http.Request) (*url.URL, error) {
	host := req.URL.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil, nil
	}
	blocked.mu.Lock()
	blocked.hosts = append(blocked.hosts, req.URL.Host)
	blocked.mu.Unlock()
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
	pocCA.cert, _ = x509.ParseCertificate(der)
	pocCA.key = key
	dir, _ := os.MkdirTemp("", "poc-sdk-ca")
	path := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.Setenv("SSL_CERT_FILE", path)
	os.Setenv("SSL_CERT_DIR", dir)
	http.DefaultTransport.(*http.Transport).Proxy = localOnlyProxy
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func leaf(t *testing.T) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "interceptor"},
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

func TestVerify3_SDKv0113_ReVerifyingStackLeaksBeforePin(t *testing.T) {
	enclaveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinnedFP := attestation.KeyFP(&enclaveKey.PublicKey)

	var mu sync.Mutex
	var bodies []string
	var auths []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"forged"}}]}`)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf(t)}}
	srv.StartTLS()
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	// == createClientFromSecureClient(secureClient, opts...) with groundTruth.TLSPublicKey = pinnedFP
	secureClient := client.NewSecureClient(host, "tinfoilsh/confidential-model-router")
	httpClient := &http.Client{Transport: &client.TLSBoundRoundTripper{ExpectedPublicKey: pinnedFP}}
	httpClient.Transport = &reVerifyingTransport{secureClient: secureClient, transport: httpClient.Transport}
	oc := openai.NewClient(
		option.WithAPIKey("sk-SUMMARIZER-TINFOIL-API-KEY"),
		option.WithMaxRetries(0),
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", host)),
	)
	c := &Client{Client: &oc, secureClient: secureClient, enclave: host, repo: secureClient.Repo()}

	secret := "user secret: my bank PIN is 4417"
	_, err := c.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "llama3-3-70b",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage(secret)},
	})
	t.Logf("client error: %v (errors.Is ErrCertMismatch=%v)", err, errors.Is(err, client.ErrCertMismatch))
	blocked.mu.Lock()
	t.Logf("re-verification attempted (blocked locally) fetches to: %v", blocked.hosts)
	blocked.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	t.Logf("interceptor received %d request(s)", len(bodies))
	for i := range bodies {
		t.Logf("  #%d Authorization=%q body=%s", i+1, auths[i], bodies[i])
	}
	if len(bodies) == 0 || !strings.Contains(bodies[0], secret) || auths[0] != "Bearer sk-SUMMARIZER-TINFOIL-API-KEY" {
		t.Fatal("NOT REPRODUCED")
	}
	if err == nil {
		t.Fatal("unexpected: forged response accepted")
	}
	t.Log("REPRODUCED with the shipped tinfoil-go v0.11.3 reVerifyingTransport + verifier v0.11.2 TLSBoundRoundTripper")
}
