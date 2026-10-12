package verify

// PoC (local only): the complete reference-values layer of VerifyV3 (code
// provenance + platform endorsements + both freshness witnesses) accepts a
// document that names Tinfoil's cvm_admin/SSH dev-box release when the trusted
// repo string comes from the gateway catalog. Only the hardware-quote layer is
// left, which the real dev-box CVM supplies when it answers /.well-known/tinfoil-attestation.

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

const pocPublicDir = "/root/tinfoil-review/work/verify/go-verifier-provenance--gateway-catalog-any-tinfoilsh-repo--poc/poc/public"

func sigstoreEntry(t *testing.T, id, format, repo, tag, digest string, bundle []byte) collateral.Entry {
	data, err := json.Marshal(map[string]any{"repo": repo, "tag": tag, "digest": digest, "sigstore_bundle": json.RawMessage(bundle)})
	require.NoError(t, err)
	return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: format, Data: data}
}

func freshnessEntry(t *testing.T, id string, bundle []byte) collateral.Entry {
	data, err := json.Marshal(map[string]any{"sigstore_bundle": json.RawMessage(bundle)})
	require.NoError(t, err)
	return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: collateral.SigstoreFreshnessV1Format, Data: data}
}

func mustRead(t *testing.T, parts ...string) []byte {
	b, err := os.ReadFile(filepath.Join(append([]string{pocPublicDir}, parts...)...))
	require.NoError(t, err)
	return b
}

func TestPoC_ReferenceValuesAcceptDevBoxRelease(t *testing.T) {
	const catalogRepo = "tinfoilsh/confidential-ubuntu-tinfoil-config" // chosen by the gateway catalog
	const codeTag, codeDigest = "v0.1.1", "785cbc0aef32452706de012de4e8baf0df6033a57f692d798746086eaf618822"
	const platTag, platDigest = "v0.0.17", "0cba58535ac96b734d02f9ebd5db6e90f51c193e9d27c4432c8fc5a363f83d64"

	entries := []collateral.Entry{
		sigstoreEntry(t, "code", collateral.SigstoreCodeV1Format, catalogRepo, codeTag, codeDigest, mustRead(t, "confidential-ubuntu-tinfoil-config", codeTag, "code-bundle.json")),
		freshnessEntry(t, collateral.FreshnessIDCode, mustRead(t, "confidential-ubuntu-tinfoil-config", codeTag, "freshness-bundle.json")),
		sigstoreEntry(t, "platform", collateral.SigstorePlatformV1Format, "tinfoilsh/platform-endorsements", "", platDigest, mustRead(t, "platform-endorsements", platTag, "platform-bundle.json")),
		freshnessEntry(t, collateral.FreshnessIDPlatform, mustRead(t, "platform-endorsements", platTag, "freshness-bundle.json")),
	}
	nonce := make([]byte, document.NonceSize)
	_, _ = rand.Read(nonce)
	// The quote itself is not under test here: a placeholder report stands in
	// for the dev box's genuine SEV-SNP/TDX quote.
	docBytes, err := document.Build(document.BuildInput{
		Nonce:          nonce,
		CryptoMaterial: []document.CryptoMaterialItem{{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}},
		Collateral:     entries,
	}, func(reportData [64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("placeholder-quote"), nil })
	require.NoError(t, err)

	v, err := NewVerifier()
	require.NoError(t, err)
	doc, err := document.Parse(docBytes, nonce)
	require.NoError(t, err)
	now := time.Now()
	code, endorsements, expiresAt, err := v.authenticateReferenceValues(doc, catalogRepo, now)
	require.NoError(t, err, "reference-values layer must accept the dev-box release")
	t.Logf("ACCEPTED reference values for repo=%s: code tag=%s commit=%s digest=%s", code.Repo, code.Tag, code.Commit, code.Digest)
	t.Logf("  expected enclave measurement (SNP/RTMR1/RTMR2): %v", code.Measurement.Registers)
	t.Logf("  platform endorsements: tag=%s machines=%d policies=%d", endorsements.Tag, len(endorsements.Artifact.Machines), len(endorsements.Artifact.Policies))
	t.Logf("  FreshnessExpiresAt=%s (now %s)", expiresAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))

	// Sanity: the same document is rejected when the caller's trusted repo is
	// the inference router, i.e. the repo string is the only thing standing
	// between the dev box and a "verified" result.
	_, _, _, err = v.authenticateReferenceValues(doc, "tinfoilsh/confidential-model-router", now)
	require.Error(t, err)
	t.Logf("  control: with repo=tinfoilsh/confidential-model-router the same document is rejected: %v", err)
}
