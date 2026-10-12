package main

// Negative control: the same attacker, the same openai-go request shape, but
// the TLS-pinning transport from tinfoil-go v0.16.1 (latest stable; the pin
// is checked in tls.Config.VerifyConnection, verifier/client/roundtrip.go:49-63;
// upstream HEAD ef79d8e = v0.17.0-rc.1 has the same code in
// enclave/roundtrip.go:49-63).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	vclient "github.com/tinfoilsh/tinfoil-go/verifier/client"
)

func call(pinned string) error {
	hc := &http.Client{Transport: &vclient.TLSBoundRoundTripper{ExpectedPublicKey: pinned}}
	oc := openai.NewClient(option.WithAPIKey("tk_CANARY_SUMMARIZER_API_KEY"), option.WithMaxRetries(0),
		option.WithHTTPClient(hc), option.WithBaseURL("https://"+routerHost+"/v1/"))
	_, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    "m",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("CANARY-USER-SECRET")},
	})
	return err
}

func TestControl_CurrentSDKPinsBeforeSend(t *testing.T) {
	genuine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a := startAttacker(t, false)
	err := call(keyFP(&genuine.PublicKey))
	n := len(a.reqs)
	t.Logf("current SDK error: %v", err)
	t.Logf("attacker: %d TCP connection(s), %d HTTP request(s)", a.conns.Load(), n)
	if a.conns.Load() == 0 {
		t.Fatal("control invalid: client never reached the attacker")
	}
	if err == nil || n != 0 {
		t.Fatalf("current SDK leaked %d request(s)", n)
	}
	t.Log("FIXED: handshake aborted in VerifyConnection; zero request bytes reached the non-attested peer")
}

func TestControl_CurrentSDKHonestPeer(t *testing.T) {
	a := startAttacker(t, false)
	err := call(a.fp)
	t.Logf("pinned key == peer key: error=%v, peer saw %d request(s)", err, len(a.reqs))
	if err != nil {
		t.Fatal(err)
	}
}
