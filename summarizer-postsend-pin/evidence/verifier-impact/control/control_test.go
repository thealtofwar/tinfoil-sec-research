package pocctl

// Control: same interceptor scenario against tinfoil-go's in-tree
// verifier/client.TLSBoundRoundTripper. Run once at v0.12.5 (last version with
// the post-send check) and once at v0.12.6 (first version that checks the pin
// in DialTLSContext "BEFORE any HTTP request data is sent").

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

var ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func localOnlyProxy(req *http.Request) (*url.URL, error) {
	host := req.URL.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil, nil
	}
	return nil, fmt.Errorf("PoC guard: blocked non-local request to %s", req.URL.Host)
}

func TestMain(m *testing.M) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PoC CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca.cert, _ = x509.ParseCertificate(der)
	ca.key = key
	dir, _ := os.MkdirTemp("", "poc-ctl-ca")
	p := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.Setenv("SSL_CERT_FILE", p)
	os.Setenv("SSL_CERT_DIR", dir)
	http.DefaultTransport.(*http.Transport).Proxy = localOnlyProxy
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestControl_InterceptorDelivery(t *testing.T) {
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "interceptor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	ld, _ := x509.CreateCertificate(rand.Reader, lt, ca.cert, &lk.PublicKey, ca.key)

	var mu sync.Mutex
	var got []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.Header.Get("Authorization")+" | "+string(b))
		mu.Unlock()
		io.WriteString(w, "{}")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{ld}, PrivateKey: lk}}}
	srv.StartTLS()
	defer srv.Close()

	enclaveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hc := &http.Client{Transport: &client.TLSBoundRoundTripper{ExpectedPublicKey: attestation.KeyFP(&enclaveKey.PublicKey)}}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", bytes.NewReader([]byte(`{"messages":[{"role":"user","content":"SECRET"}]}`)))
	req.Header.Set("Authorization", "Bearer sk-KEY")
	_, err := hc.Do(req)
	mu.Lock()
	defer mu.Unlock()
	t.Logf("client error: %v", err)
	t.Logf("interceptor received %d request(s): %q", len(got), got)
}
