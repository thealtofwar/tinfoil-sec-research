package tinfoil

// verify3: the documented escape hatch client.HTTPClient() (client.go:130-137)
// under the 303 redirect: a caller who checks resp.StatusCode == 200 still
// receives an unauthenticated body.

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestVerify3_HTTPClientRedirect(t *testing.T) {
	if os.Getenv("POC_MODE") == "" {
		t.Skip("run via run_matrix.sh")
	}
	pub, err := os.ReadFile(os.Getenv("POC_PUBKEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	hpkeKey := strings.TrimSpace(string(pub))
	handle, err := enclave.NewHandle("enclave.example.com", defaultConfigRepo, &enclave.Options{})
	if err != nil {
		t.Fatal(err)
	}
	verify3SetSeam(t, handle, func() (*verify.Verification, error) {
		return &verify.Verification{ConfigRepo: defaultConfigRepo, CryptoMaterial: []document.CryptoMaterialItem{
			{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
			{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hpkeKey},
		}, FreshnessExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	c, err := createClientFromHandle(handle, defaultTransportMode, "", resolveUserCacheSecret("", false))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://enclave.example.com/v1/chat/completions",
		strings.NewReader(`{"model":"llama3-3-70b","messages":[{"role":"user","content":"my secret prompt"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		t.Logf("RESULT HTTPClient(): error: %v", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("RESULT HTTPClient(): final request=%s %s status=%d Ehbp-Response-Nonce=%q body=%.90s...",
		resp.Request.Method, resp.Request.URL, resp.StatusCode, resp.Header.Get("Ehbp-Response-Nonce"), body)
}
