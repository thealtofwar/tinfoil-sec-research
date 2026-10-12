package verify

// Finding 7, test C (drop into tinfoil-go/verify/).
// A nonce-bound v3 document carrying the PUBLIC dev-box code bundle, the public
// platform-endorsements v0.0.17 bundle and both public freshness witnesses is
// run through the shipped verifyV3 with the repo string a gateway catalog
// would supply. Code provenance, platform endorsements and both freshness
// checks accept it; it stops only at the hardware-quote layer, because the
// quote here is a placeholder (a genuine SEV-SNP/TDX quote can only come from
// the dev-box CVM itself; that layer checks machine policy, chip id, launch
// measurement, VM shape and REPORT_DATA, none of which depend on the repo).
// Control: the identical document with repo=confidential-model-router is
// rejected at the provenance layer.

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func poc07Read(t *testing.T, parts ...string) []byte {
	b, err := os.ReadFile(filepath.Join(append([]string{os.Getenv("POC_DATA")}, parts...)...))
	require.NoError(t, err)
	return b
}

func poc07Entry(t *testing.T, id, format string, fields map[string]any) collateral.Entry {
	data, err := json.Marshal(fields)
	require.NoError(t, err)
	return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: format, Data: data}
}

func TestPoC07_C_VerifyV3AcceptsDevBoxUpToQuoteLayer(t *testing.T) {
	const devBox = "tinfoilsh/confidential-ubuntu-tinfoil-config" // from the gateway catalog
	const codeTag, codeDigest = "v0.1.1", "785cbc0aef32452706de012de4e8baf0df6033a57f692d798746086eaf618822"
	const platDigest = "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64"
	now, err := time.Parse(time.RFC3339, os.Getenv("POC_NOW"))
	require.NoError(t, err, "set POC_NOW (RFC3339)")

	entries := []collateral.Entry{
		poc07Entry(t, "code", collateral.SigstoreCodeV1Format, map[string]any{"repo": devBox, "tag": codeTag, "digest": codeDigest,
			"sigstore_bundle": json.RawMessage(poc07Read(t, "confidential-ubuntu-tinfoil-config", codeTag, "code-bundle.json"))}),
		poc07Entry(t, collateral.FreshnessIDCode, collateral.SigstoreFreshnessV1Format, map[string]any{
			"sigstore_bundle": json.RawMessage(poc07Read(t, "confidential-ubuntu-tinfoil-config", codeTag, "freshness-bundle.json"))}),
		poc07Entry(t, "platform", collateral.SigstorePlatformV1Format, map[string]any{"repo": "tinfoilsh/platform-endorsements", "tag": "", "digest": platDigest,
			"sigstore_bundle": json.RawMessage(poc07Read(t, "platform-endorsements", "v0.0.17", "platform-bundle.json"))}),
		poc07Entry(t, collateral.FreshnessIDPlatform, collateral.SigstoreFreshnessV1Format, map[string]any{
			"sigstore_bundle": json.RawMessage(poc07Read(t, "platform-endorsements", "v0.0.17", "freshness-bundle.json"))}),
	}
	nonce := make([]byte, document.NonceSize)
	_, _ = rand.Read(nonce)
	docBytes, err := document.Build(document.BuildInput{
		Nonce:          nonce,
		CryptoMaterial: []document.CryptoMaterialItem{{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}},
		Collateral:     entries,
	}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("placeholder-quote"), nil })
	require.NoError(t, err)

	v, err := NewVerifier()
	require.NoError(t, err)
	v.now = func() time.Time { return now } // pin the clock: witnesses are only valid for 7 days

	doc, err := document.Parse(docBytes, nonce)
	require.NoError(t, err)
	code, end, exp, err := v.authenticateReferenceValues(doc, devBox, now)
	require.NoError(t, err)
	t.Logf("reference values ACCEPTED for repo=%s tag=%s commit=%s; platform-endorsements %s (%d machines); FreshnessExpiresAt=%s",
		code.Repo, code.Tag, code.Commit, end.Tag, len(end.Artifact.Machines), exp.UTC().Format(time.RFC3339))

	_, l, err := v.verifyV3(docBytes, nonce, devBox)
	require.Error(t, err)
	require.Equal(t, layerQuote, l)
	t.Logf("verifyV3(repo=%s): rejected only at layer=%q (placeholder quote): %v", devBox, l, err)

	_, l, err = v.verifyV3(docBytes, nonce, "tinfoilsh/confidential-model-router")
	require.Error(t, err)
	require.Equal(t, layerProvenance, l)
	t.Logf("  control verifyV3(repo=tinfoilsh/confidential-model-router): rejected at layer=%q: %v", l, err)
}
