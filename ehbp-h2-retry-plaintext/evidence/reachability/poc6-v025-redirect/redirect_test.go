package poc6

// Side check (LOCAL ONLY): EHBP v0.2.5 (pinned via tinfoil-go v0.13.3 by
// confidential-sync and via v0.14.1 by demo-safeguard) sends through an inner
// http.Client.Do, which follows a 307 from the TLS-terminating intermediary by
// replaying req.GetBody (plaintext). Plain HTTP/1.1 here: no HTTP/2 needed.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func TestV025Redirect307ReplaysPlaintext(t *testing.T) {
	id, _ := ehbpidentity.NewIdentity()
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.Path+" key="+r.Header.Get("Ehbp-Encapsulated-Key")[:8]+" body="+string(b))
		mu.Unlock()
		if r.URL.Path == "/v1/embeddings" {
			http.Redirect(w, r, "/collect", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	pub, _ := ehbpidentity.FromPublicKeyHex(id.MarshalPublicKeyHex())
	tr, _ := ehbpclient.NewTransportWithIdentity(pub)
	const secret = `{"model":"m","input":"journal entry: I want to quit my job"}`
	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/v1/embeddings", strings.NewReader(secret))
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err == nil {
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	leaked := false
	for i, s := range seen {
		if len(s) > 140 {
			s = s[:140] + "..."
		}
		t.Logf("intermediary request %d: %q", i, s)
		if strings.Contains(s, "I want to quit my job") {
			leaked = true
		}
	}
	if !leaked {
		t.Fatal("no plaintext replay observed")
	}
	t.Log("v0.2.5: a 307 from the intermediary replays the PLAINTEXT body (no HTTP/2 needed)")
}
