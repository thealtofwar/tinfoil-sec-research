package pocctl

// Control: identical attacker setup, but the TLSBoundRoundTripper from the
// first fixed SDK (tinfoil-go v0.12.6, pin checked in DialTLSContext before
// any request bytes are written).

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
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	verifierclient "github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const routerHost = "inference.tinfoil.sh"

var ca *x509.Certificate
var caKey *ecdsa.PrivateKey

func TestMain(m *testing.M) {
	caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PoC Public Root CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	ca, _ = x509.ParseCertificate(der)
	dir, _ := os.MkdirTemp("", "poc-ctl-ca")
	p := filepath.Join(dir, "ca.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.Setenv("SSL_CERT_FILE", p)
	os.Setenv("SSL_CERT_DIR", dir)
	installFakeDNS()
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestControlFixedSDK(t *testing.T) {
	enclaveKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinnedFP := attestation.KeyFP(&enclaveKey.PublicKey)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ltmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: routerHost}, DNSNames: []string{routerHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	lder, _ := x509.CreateCertificate(rand.Reader, ltmpl, ca, &key.PublicKey, caKey)
	var mu sync.Mutex
	n := 0
	mitm := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		mu.Lock()
		n++
		mu.Unlock()
		io.WriteString(w, `{}`)
	}))
	l, lerr := net.Listen("tcp", "127.11.22.33:443")
	if lerr != nil {
		t.Fatal(lerr)
	}
	mitm.Listener.Close()
	mitm.Listener = l
	var hs int
	mitm.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateNew {
			mu.Lock()
			hs++
			mu.Unlock()
		}
	}
	mitm.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{lder}, PrivateKey: key}}}
	mitm.StartTLS()
	defer mitm.Close()
	hc := &http.Client{Transport: &verifierclient.TLSBoundRoundTripper{ExpectedPublicKey: pinnedFP}}
	oc := openai.NewClient(option.WithAPIKey("SUMMARIZER-TINFOIL-API-KEY"), option.WithMaxRetries(0), option.WithHTTPClient(hc), option.WithBaseURL("https://"+routerHost+"/v1/"))
	_, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{Model: "llama3-3-70b", Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("I was diagnosed with HIV yesterday")}})
	mu.Lock()
	defer mu.Unlock()
	t.Logf("fixed SDK client error: %v (ErrCertMismatch: %v)", err, errors.Is(err, verifierclient.ErrCertMismatch))
	t.Logf("attacker accepted %d TCP connection(s), saw %d HTTP request(s)", hs, n)
	for _, d := range dnsLogSnapshot() {
		t.Logf("resolver: %s", d)
	}
	if hs == 0 {
		t.Fatal("control invalid: the client never reached the attacker")
	}
	if n != 0 {
		t.Fatalf("fixed SDK leaked %d request(s)", n)
	}
}
