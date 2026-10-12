package verify

// Independent verifier check: run the production verifyV3 entry point on a
// document carrying the PUBLIC dev-box release collateral, with the repo string
// a gateway catalog would supply. Every layer before the hardware quote must
// pass; the only rejection must come from layerQuote (placeholder quote).

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestVerify_DevBoxDocumentFailsOnlyAtQuoteLayer(t *testing.T) {
	const pub = "/root/tinfoil-review/work/go-verifier-provenance/poc/public"
	read := func(parts ...string) []byte {
		b, err := os.ReadFile(filepath.Join(append([]string{pub}, parts...)...))
		require.NoError(t, err)
		return b
	}
	sig := func(id, format, repo, tag, digest string, bundle []byte) collateral.Entry {
		data, err := json.Marshal(map[string]any{"repo": repo, "tag": tag, "digest": digest, "sigstore_bundle": json.RawMessage(bundle)})
		require.NoError(t, err)
		return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: format, Data: data}
	}
	fresh := func(id string, bundle []byte) collateral.Entry {
		data, err := json.Marshal(map[string]any{"sigstore_bundle": json.RawMessage(bundle)})
		require.NoError(t, err)
		return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: collateral.SigstoreFreshnessV1Format, Data: data}
	}
	const repo = "tinfoilsh/confidential-ubuntu-tinfoil-config"
	entries := []collateral.Entry{
		sig("code", collateral.SigstoreCodeV1Format, repo, "v0.1.1", "785cbc0aef32452706de012de4e8baf0df6033a57f692d798746086eaf618822", read("confidential-ubuntu-tinfoil-config", "v0.1.1", "code-bundle.json")),
		fresh(collateral.FreshnessIDCode, read("confidential-ubuntu-tinfoil-config", "v0.1.1", "freshness-bundle.json")),
		sig("platform", collateral.SigstorePlatformV1Format, "tinfoilsh/platform-endorsements", "", "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64", read("platform-endorsements", "v0.0.17", "platform-bundle.json")),
		fresh(collateral.FreshnessIDPlatform, read("platform-endorsements", "v0.0.17", "freshness-bundle.json")),
	}
	nonce := make([]byte, document.NonceSize)
	_, _ = rand.Read(nonce)
	docBytes, err := document.Build(document.BuildInput{
		Nonce:          nonce,
		CryptoMaterial: []document.CryptoMaterialItem{{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}},
		Collateral:     entries,
	}, func(reportData [64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("placeholder-quote"), nil })
	require.NoError(t, err)

	v, err := NewVerifier()
	require.NoError(t, err)
	_, layer, err := v.verifyV3(docBytes, nonce, repo)
	require.Error(t, err)
	t.Logf("catalog repo %q: verifyV3 rejected at layer=%q err=%v", repo, layer, err)
	require.Equal(t, layerQuote, layer, "all pre-quote layers (envelope, code provenance, platform endorsements, both freshness witnesses) must pass for the dev-box release")

	// Control: the inference router repo string rejects the same document at the provenance layer.
	_, layer, err = v.verifyV3(docBytes, nonce, "tinfoilsh/confidential-model-router")
	require.Error(t, err)
	t.Logf("control repo router: rejected at layer=%q", layer)
	require.Equal(t, layerProvenance, layer)
}
