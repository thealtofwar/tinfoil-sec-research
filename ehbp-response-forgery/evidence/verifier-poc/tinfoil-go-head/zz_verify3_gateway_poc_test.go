package tinfoil

// verify3 LOCAL PoC, Gateway topology (NewGateway). The gateway is a
// TLS-terminating intermediary by design (its catalog is documented as
// untrusted, gateway_catalog.go:25). NewGateway is called unmodified with a
// static catalog; the only change is that the per-replica build closure is
// replaced by a line-for-line copy of gateway.go:74-91 that additionally sets
// the Handle.verify seam (attestation cannot be produced offline).

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestVerify3_GatewayResponseForgery(t *testing.T) {
	mode := os.Getenv("POC_MODE")
	if mode == "" {
		t.Skip("run via run_matrix.sh (POC_MODE unset)")
	}
	pub, err := os.ReadFile(os.Getenv("POC_PUBKEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	hpkeKey := strings.TrimSpace(string(pub))
	const baseURL = "https://gateway.example.com/v1/"
	catalog := Catalog{"llama3-3-70b": {Repo: "tinfoilsh/confidential-llama3-3-70b", Hosts: []string{"replica.example.com"}}}

	gw, err := NewGateway(baseURL, func() Catalog { return catalog },
		GatewayOptions{ClientOptions: []ClientOption{WithOpenAIOptions(option.WithAPIKey("sk-poc"))}})
	if err != nil {
		t.Fatal(err)
	}
	policy := gw.seal.policy
	base := "gateway.example.com"
	gw.seal.build = func(r replica) (http.RoundTripper, error) { // copy of gateway.go:74-91
		secure, pinned := policy.pins[r.model]
		var err error
		if pinned {
			secure = secure.ForEnclave(r.host)
		} else if secure, err = enclave.NewHandle(r.host, r.ref, &policy.defaults); err != nil {
			return nil, err
		}
		secure = secure.ViaRelay(base)
		verify3SetSeam(t, secure, func() (*verify.Verification, error) { // <- the only addition
			return &verify.Verification{
				ConfigRepo: r.ref,
				CryptoMaterial: []document.CryptoMaterialItem{
					{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
					{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hpkeKey},
				},
				FreshnessExpiresAt: time.Now().Add(time.Hour),
			}, nil
		})
		httpClient, err := ehbpHTTPClient(secure, r.host, baseURL)
		if err != nil {
			return nil, err
		}
		return &verifiedReplicaTransport{
			recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
			verification:      secure.Verification,
		}, nil
	}

	params := openai.ChatCompletionNewParams{
		Model:    "llama3-3-70b",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("my secret prompt")},
	}
	resp, err := gw.Chat.Completions.New(context.Background(), params)
	var content string
	if err != nil {
		t.Logf("RESULT gateway non-streaming: error: %v", err)
	} else {
		content = resp.Choices[0].Message.Content
		t.Logf("RESULT gateway non-streaming: err=nil content=%q", content)
	}
	for _, v := range gw.Verifications() {
		t.Logf("gateway verifications: host=%s ref=%s models=%v", v.Host, v.Reference, v.Models)
	}
	switch mode {
	case "honest":
		if err != nil || content != "REAL ENCLAVE ANSWER" {
			t.Fatalf("honest path broken: %v", err)
		}
	case "forge-200", "forge-404", "redirect-303":
		if err == nil {
			t.Fatalf("expected error, got %q", content)
		}
	default:
		if err != nil || !strings.HasPrefix(content, "FORGED BY INTERMEDIARY") {
			t.Fatalf("forgery not accepted: err=%v content=%q", err, content)
		}
		t.Logf("VERDICT: gateway-written plaintext accepted as the verified replica's answer")
	}
}
