package tinfoil

// Control (local only): over HTTP/1.1, openai-go does not set Idempotency-Key,
// so net/http does not transparently replay a POST whose reused connection is
// dropped after the request was written. openai-go's own retry goes back
// through the full tinfoil-go stack, so the replay is re-sealed (new
// Ehbp-Encapsulated-Key) and no plaintext reaches the intermediary.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/openai/openai-go/v3"
)

func TestVariantSDK_H1_DroppedReusedConn_Control(t *testing.T) {
	sdkSetup(t)
	var saw string
	id, enclave := sdkEnclave(t, &saw)

	var mu sync.Mutex
	var caps []*vCap
	n := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c := &vCap{headers: map[string]string{":path": r.URL.Path, "ehbp-encapsulated-key": r.Header.Get("Ehbp-Encapsulated-Key"), ":method": r.Method}}
		c.body.Write(b)
		mu.Lock()
		i := n
		n++
		caps = append(caps, c)
		mu.Unlock()
		if i == 1 { // second request on the kept-alive connection: drop it
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		}
		up, _ := http.NewRequest(r.Method, enclave.URL+r.URL.Path, bytes.NewReader(b))
		up.Header.Set("Ehbp-Encapsulated-Key", r.Header.Get("Ehbp-Encapsulated-Key"))
		resp, err := http.DefaultClient.Do(up)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		if nonce := resp.Header.Get("Ehbp-Response-Nonce"); nonce != "" {
			w.Header().Set("Ehbp-Response-Nonce", nonce)
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{sdkCert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	defer srv.Close()
	proxyURL := "https://" + ln.Addr().String()
	oc := sdkClient(t, id, proxyURL)

	for i, msg := range []string{"warm-up request", "TOP-SECRET over HTTP/1.1: acquisition of ACME Corp"} {
		resp, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
			Model:    "m",
			Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage(msg)},
		})
		if err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
		t.Logf("call %d ok: %q", i, resp.Choices[0].Message.Content)
	}
	mu.Lock()
	defer mu.Unlock()
	leaked := false
	for i, c := range caps {
		pl := strings.Contains(c.body.String(), "ACME Corp")
		leaked = leaked || pl
		t.Logf("  intermediary capture %d: %s key=%.16s.. plaintext=%v len=%d", i, c.headers[":path"], c.headers["ehbp-encapsulated-key"], pl, c.body.Len())
	}
	if leaked {
		t.Fatal("unexpected plaintext over HTTP/1.1")
	}
	t.Log("CONTROL: no plaintext over HTTP/1.1; openai-go's retry was re-sealed under a fresh encapsulated key")
}
