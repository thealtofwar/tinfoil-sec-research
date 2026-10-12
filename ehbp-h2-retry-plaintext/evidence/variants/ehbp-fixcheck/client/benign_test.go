package client_test

// Benign trigger (local only): an ordinary, unmodified net/http HTTP/2 server
// (think: a load balancer / CDN / gateway front end) that advertises a low
// SETTINGS_MAX_CONCURRENT_STREAMS. Concurrent EHBP requests on a fresh
// connection can exceed the limit before the client has processed the
// server's SETTINGS; the server answers with RST_STREAM(REFUSED_STREAM), the
// Go client replays the request via GetBody, and the replay carries the
// PLAINTEXT body (with the Ehbp-Encapsulated-Key header still set). No
// attacker logic is involved.

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func TestBenign_MaxConcurrentStreamsRefusal(t *testing.T) {
	for _, lim := range []uint32{1, 32, 100} {
		t.Run(fmt.Sprintf("limit=%d", lim), func(t *testing.T) { benignRun(t, lim) })
	}
}

func benignRun(t *testing.T, limit uint32) {
	serverID, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var plaintextSeen, total atomic.Int64
	var mu sync.Mutex
	var sample string
	enclave := serverID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte("ok:" + string(b)))
	}))
	// "Front end": records what it receives, then hands to the EHBP server.
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		total.Add(1)
		if bytes.Contains(b, []byte(secretMarker)) {
			plaintextSeen.Add(1)
			mu.Lock()
			if sample == "" {
				sample = string(b)
			}
			mu.Unlock()
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		enclave.ServeHTTP(w, r)
	})
	srv := httptest.NewUnstartedServer(front)
	srv.EnableHTTP2 = true
	srv.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: int(limit)}
	srv.StartTLS()
	defer srv.Close()

	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	pub, _ := identity.FromPublicKeyHex(serverID.MarshalPublicKeyHex())

	rounds, perRound := 10, 128
	var ok200, non200, errs atomic.Int64
	for round := 0; round < rounds; round++ {
		inner := http.DefaultTransport.(*http.Transport).Clone()
		inner.TLSClientConfig = &tls.Config{RootCAs: pool}
		tr, _ := client.NewTransportWithIdentity(pub, client.WithHTTPClient(&http.Client{Transport: inner}))
		hc := &http.Client{Transport: tr}
		var wg sync.WaitGroup
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				body := fmt.Sprintf(`{"n":%d,"content":"my SSN is %s"}`, i, secretMarker)
				req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(body))
				resp, err := hc.Do(req)
				if err != nil {
					errs.Add(1)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == 200 {
					ok200.Add(1)
				} else {
					non200.Add(1)
				}
			}(i)
		}
		wg.Wait()
		inner.CloseIdleConnections()
	}
	t.Logf("requests=%d front-end received=%d PLAINTEXT bodies at front end=%d; client: 200=%d non-200=%d errors=%d",
		rounds*perRound, total.Load(), plaintextSeen.Load(), ok200.Load(), non200.Load(), errs.Load())
	if sample != "" {
		t.Logf("sample plaintext seen by the front end: %q", sample)
	}
}
