package tinfoil

// verify3 LOCAL PoC against the released tinfoil-go v0.16.1 (module cache
// copy, unmodified except for this _test.go file). Same design as the HEAD
// variant: the client is built by the call NewClientWithOptions ends in
// (ehbp_transport.go:143-144), default options apart from an API key, stock
// http.DefaultTransport; the only seam is SecureClient.verify, which replaces
// the attestation fetch + verification step and returns the genuine enclave
// process's HPKE key.

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func TestVerify3_EHBPResponseForgery_v0161(t *testing.T) {
	mode := os.Getenv("POC_MODE")
	if mode == "" {
		t.Skip("run via run_matrix.sh (POC_MODE unset)")
	}
	pub, err := os.ReadFile(os.Getenv("POC_PUBKEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	hpkeKey := strings.TrimSpace(string(pub))
	const host = "enclave.example.com"

	// Same SecureClient NewClientWithOptions(WithEnclave(host)) creates (ehbp_transport.go:137).
	sc, err := client.NewSecureClient(host, defaultConfigRepo, &client.VerificationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := func() (*client.VerifiedDocumentV3, error) {
		return &client.VerifiedDocumentV3{
			ConfigRepo:  defaultConfigRepo,
			EnclaveHost: host,
			CodeTag:     "v-genuine",
			CryptoMaterial: []document.CryptoMaterialItem{
				{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
				{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hpkeKey},
			},
			FreshnessExpiresAt: time.Now().Add(time.Hour),
		}, nil
	}
	field := reflect.ValueOf(sc).Elem().FieldByName("verify")
	if !field.IsValid() {
		t.Fatal("SecureClient has no verify field")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(f))

	baseURL := ""
	if os.Getenv("POC_TOPOLOGY") == "proxy" {
		baseURL = "https://proxy.example.com/v1/"
	}
	c, err := createClientFromSecureClient(sc, defaultTransportMode, baseURL,
		resolveUserCacheSecret("", false), option.WithAPIKey("sk-poc"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client (v0.16.1) transport=%s enclave=%s verified repo=%s", c.Transport(), c.Enclave(), c.Verification().ConfigRepo)

	params := openai.ChatCompletionNewParams{
		Model:    "llama3-3-70b",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("my secret prompt")},
	}
	resp, err := c.Chat.Completions.New(context.Background(), params)
	var content string
	if err != nil {
		t.Logf("RESULT non-streaming: error: %v", err)
	} else {
		content = resp.Choices[0].Message.Content
		t.Logf("RESULT non-streaming: err=nil content=%q", content)
	}
	var streamed string
	stream := c.Chat.Completions.NewStreaming(context.Background(), params)
	for stream.Next() {
		for _, ch := range stream.Current().Choices {
			streamed += ch.Delta.Content
		}
	}
	streamErr := stream.Err()
	stream.Close()
	t.Logf("RESULT streaming:     err=%v content=%q", streamErr, streamed)

	forged := func(s string) bool { return strings.HasPrefix(s, "FORGED BY INTERMEDIARY") }
	switch mode {
	case "honest":
		if err != nil || content != "REAL ENCLAVE ANSWER" || streamErr != nil || streamed != "REAL ENCLAVE STREAM" {
			t.Fatalf("honest path broken")
		}
	case "forge-200", "forge-404":
		if err == nil || streamErr == nil {
			t.Fatalf("control: expected errors")
		}
	default:
		if err != nil || !forged(content) || streamErr != nil || !forged(streamed) {
			t.Fatalf("forgery not accepted: err=%v content=%q streamErr=%v streamed=%q", err, content, streamErr, streamed)
		}
		t.Logf("VERDICT: attacker-written plaintext accepted as the verified enclave's answer (streaming and non-streaming)")
	}
}
