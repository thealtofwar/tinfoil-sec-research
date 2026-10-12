package tinfoil

// Verifier-written end-to-end check through the SHIPPED NewGateway pipeline:
// a loopback "gateway" serves an attacker-chosen catalog and relays a v3
// attestation document naming the public dev-box release. The real client
// (FetchCatalog -> resolve -> build -> enclave.NewHandle -> fetch.Document via
// relay -> VerifyV3) must pass the reference-values layer for the catalog repo
// and fail only at the hardware-quote layer (placeholder quote, no AMD
// collateral). Control: the same document with the router repo in the catalog
// must be rejected at the reference-values layer.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

const e2ePublicDir = "/root/tinfoil-review/work/verify/go-verifier-provenance--gateway-catalog-any-tinfoilsh-repo--poc/poc/public"

func e2eRead(t *testing.T, parts ...string) []byte {
	b, err := os.ReadFile(filepath.Join(append([]string{e2ePublicDir}, parts...)...))
	require.NoError(t, err)
	return b
}

func e2eSigstoreEntry(t *testing.T, id, format, repo, tag, digest string, bundle []byte) collateral.Entry {
	data, err := json.Marshal(map[string]any{"repo": repo, "tag": tag, "digest": digest, "sigstore_bundle": json.RawMessage(bundle)})
	require.NoError(t, err)
	return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: format, Data: data}
}

func e2eFreshnessEntry(t *testing.T, id string, bundle []byte) collateral.Entry {
	data, err := json.Marshal(map[string]any{"sigstore_bundle": json.RawMessage(bundle)})
	require.NoError(t, err)
	return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: collateral.SigstoreFreshnessV1Format, Data: data}
}

// devBoxDocument is what a dev-box CVM's shim would answer for nonce, minus a
// genuine hardware quote (placeholder) and AMD collateral.
func devBoxDocument(t *testing.T, nonce []byte) []byte {
	const codeRepo, codeTag, codeDigest = "tinfoilsh/confidential-ubuntu-tinfoil-config", "v0.1.1", "785cbc0aef32452706de012de4e8baf0df6033a57f692d798746086eaf618822"
	const platTag, platDigest = "v0.0.17", "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64"
	entries := []collateral.Entry{
		e2eSigstoreEntry(t, "code", collateral.SigstoreCodeV1Format, codeRepo, codeTag, codeDigest, e2eRead(t, "confidential-ubuntu-tinfoil-config", codeTag, "code-bundle.json")),
		e2eFreshnessEntry(t, collateral.FreshnessIDCode, e2eRead(t, "confidential-ubuntu-tinfoil-config", codeTag, "freshness-bundle.json")),
		e2eSigstoreEntry(t, "platform", collateral.SigstorePlatformV1Format, "tinfoilsh/platform-endorsements", "", platDigest, e2eRead(t, "platform-endorsements", platTag, "platform-bundle.json")),
		e2eFreshnessEntry(t, collateral.FreshnessIDPlatform, e2eRead(t, "platform-endorsements", platTag, "freshness-bundle.json")),
	}
	docBytes, err := document.Build(document.BuildInput{
		Nonce: nonce,
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("11", 32)},
			{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: strings.Repeat("22", 32)},
		},
		Collateral: entries,
	}, func(reportData [64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("placeholder-quote"), nil })
	require.NoError(t, err)
	return docBytes
}

func TestVerifier_E2E_NewGatewayAcceptsDevBoxReferenceValues(t *testing.T) {
	const model = "llama3-3-70b"
	const devHost = "devbox.attacker.internal"
	for _, tc := range []struct {
		name, catalogRepo, wantLayer string
	}{
		{"dev-box repo in catalog", "tinfoilsh/confidential-ubuntu-tinfoil-config", "quote"},
		{"control: router repo in catalog", "tinfoilsh/confidential-model-router", "provenance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var relayed, posted int
			gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/catalog":
					_ = json.NewEncoder(w).Encode(map[string]any{model: map[string]any{"repo": tc.catalogRepo, "hosts": []string{devHost}}})
				case "/.well-known/tinfoil-attestation":
					relayed++
					require.Equal(t, devHost, r.URL.Query().Get("enclave"), "relay must be asked for the catalog host")
					nonce, err := hex.DecodeString(r.URL.Query().Get("nonce"))
					require.NoError(t, err)
					w.Header().Set("Content-Type", "application/json")
					w.Write(devBoxDocument(t, nonce))
				default:
					posted++
					http.Error(w, "should not be reached: verification must fail at the quote layer", http.StatusTeapot)
				}
			}))
			defer gateway.Close()

			pool := x509.NewCertPool()
			pool.AddCert(gateway.Certificate())
			dt := http.DefaultTransport.(*http.Transport)
			saved := dt.TLSClientConfig
			dt.TLSClientConfig = &tls.Config{RootCAs: pool}
			defer func() { dt.TLSClientConfig = saved }()

			// Exactly how tinfoil-proxy (no --pin) and confidential-openai-adapter build it.
			gw, err := NewGateway(gateway.URL+"/v1/", nil, GatewayOptions{})
			require.NoError(t, err)
			require.True(t, gw.Serves(model))

			body, _ := json.Marshal(map[string]any{"model": model, "messages": []map[string]string{{"role": "user", "content": "secret prompt"}}})
			req, _ := http.NewRequest(http.MethodPost, gateway.URL+"/v1/chat/completions", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := gw.HTTPClient().Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			require.Error(t, err)
			t.Logf("relayed attestation fetches=%d, requests forwarded=%d", relayed, posted)
			t.Logf("NewGateway round trip error: %v", err)
			switch tc.wantLayer {
			case "quote":
				require.NotContains(t, err.Error(), "reference values", "reference-values layer must have been PASSED for the dev-box repo")
				require.Contains(t, err.Error(), "amd-vcek", "only the hardware-quote layer (placeholder quote) may reject")
				t.Logf("RESULT: shipped NewGateway pipeline accepted code provenance + freshness for %q from the catalog; only the hardware quote is missing", tc.catalogRepo)
			case "provenance":
				require.Contains(t, err.Error(), "reference values")
				require.Contains(t, err.Error(), "expected SAN value to match regex")
				t.Logf("RESULT: with the router repo in the catalog the same document is rejected at the reference-values layer")
			}
			require.Greater(t, relayed, 0)
			require.Equal(t, 0, posted)
		})
	}
}
