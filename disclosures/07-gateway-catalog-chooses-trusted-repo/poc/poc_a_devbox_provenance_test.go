package provenance

// Finding 7, test A (drop into tinfoil-go/verify/internal/provenance/).
// The public, Tinfoil-signed release of the cvm_admin/SSH dev-box config
// tinfoilsh/confidential-ubuntu-tinfoil-config v0.1.1 passes code provenance
// and the 7-day freshness witness when the trusted repo string is that repo
// (which, in gateway mode, comes from the unauthenticated catalog).
// Inputs: public GitHub release attestations in $POC_DATA. Clock: $POC_NOW.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPoC07_A_DevBoxReleasePassesProvenanceAndFreshness(t *testing.T) {
	const repo, tag = "tinfoilsh/confidential-ubuntu-tinfoil-config", "v0.1.1"
	const digest = "785cbc0aef32452706de012de4e8baf0df6033a57f692d798746086eaf618822"
	now, err := time.Parse(time.RFC3339, os.Getenv("POC_NOW"))
	require.NoError(t, err, "set POC_NOW (RFC3339)")
	dir := filepath.Join(os.Getenv("POC_DATA"), "confidential-ubuntu-tinfoil-config", tag)
	bundle, err := os.ReadFile(filepath.Join(dir, "code-bundle.json"))
	require.NoError(t, err)
	witness, err := os.ReadFile(filepath.Join(dir, "freshness-bundle.json"))
	require.NoError(t, err)

	client, err := NewDefaultClient() // embedded Sigstore trust root, no network
	require.NoError(t, err)

	code, err := client.AuthenticateCode(bundle, repo, "", digest)
	require.NoError(t, err)
	t.Logf("ACCEPTED code artifact: repo=%s tag=%s commit=%s", code.Repo, code.Tag, code.Commit)

	// Print the measured config carried inside the signed predicate.
	id, err := signingIdentity(repo)
	require.NoError(t, err)
	res, _, err := client.verifyBundleWithIdentity(bundle, id, digest)
	require.NoError(t, err)
	cfg, err := base64.StdEncoding.DecodeString(res.Statement.Predicate.GetFields()["config"].GetStringValue())
	require.NoError(t, err)
	for _, line := range strings.Split(string(cfg), "\n") {
		for _, k := range []string{"cvm_admin", "\"22:22\"", "upstream-port", "authenticated:"} {
			if strings.Contains(line, k) {
				t.Logf("  signed measured config: %s", strings.TrimSpace(line))
			}
		}
	}

	at, err := client.AuthenticateFreshness(witness, &code.AuthenticatedArtifact, now, MaxFreshnessAge)
	require.NoError(t, err)
	t.Logf("  freshness witness ACCEPTED: witnessed %s, valid until %s, POC_NOW %s",
		at.UTC().Format(time.RFC3339), at.Add(MaxFreshnessAge).UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))

	// Control: the same bundle is rejected when the trusted repo is an inference service.
	_, err = client.AuthenticateCode(bundle, "tinfoilsh/confidential-model-router", "", digest)
	require.Error(t, err)
	t.Logf("  control: repo=tinfoilsh/confidential-model-router REJECTED: %v", err)
}
