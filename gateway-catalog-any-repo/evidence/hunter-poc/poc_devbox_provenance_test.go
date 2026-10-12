package provenance

// PoC (local only): the provenance layer accepts PUBLIC releases of Tinfoil's
// cvm_admin/SSH "dev box" repositories as valid, FRESH code artifacts whenever
// the (untrusted) gateway catalog names that repository for a model.
// Bundles were downloaded from api.github.com (public metadata), see
// /root/tinfoil-review/work/go-verifier-provenance/poc/public.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const pocPublicDir = "/root/tinfoil-review/work/go-verifier-provenance/poc/public"

func TestPoC_DevBoxReleasesPassCodeProvenanceAndFreshness(t *testing.T) {
	client, err := NewDefaultClient()
	require.NoError(t, err)
	now := time.Now()
	for _, tc := range []struct{ repo, tag, digest string }{
		{"tinfoilsh/confidential-ubuntu-tinfoil-config", "v0.1.1", "785cbc0aef32452706de012de4e8baf0df6033a57f692d798746086eaf618822"},
		{"tinfoilsh/confidential-ubuntu-config", "v0.1.2", "86767950dcda83df3887c922d55e9a8268fdb0661164cafed50b0861c62bb203"},
		{"tinfoilsh/confidential-sandbox-gpu", "v0.1.1", "fdb40dc4490dcfb78a4c5755e9c7a9768f0cb9fda7447c7418b05142974d3299"},
		{"tinfoilsh/confidential-model-router", "v0.0.155", "ad95d02b2e27b3c1d5c327f2ee9616634f841e4b2ed5a48f404e4e9f595a4876"},
	} {
		t.Run(tc.repo, func(t *testing.T) {
			dir := filepath.Join(pocPublicDir, strings.TrimPrefix(tc.repo, "tinfoilsh/"), tc.tag)
			bundle, err := os.ReadFile(filepath.Join(dir, "code-bundle.json"))
			require.NoError(t, err)
			witness, err := os.ReadFile(filepath.Join(dir, "freshness-bundle.json"))
			require.NoError(t, err)

			// Exactly what enclave.NewHandle(host, catalogEntry.Repo).Verify() does
			// for the code layer: repo comes from the gateway catalog, tag/digest
			// hints come from the (enclave-supplied) attestation document.
			code, err := client.AuthenticateCode(bundle, tc.repo, "", tc.digest)
			require.NoError(t, err, "code provenance must verify")
			t.Logf("ACCEPTED code artifact: repo=%s tag=%s commit=%s subject=%s", code.Repo, code.Tag, code.Commit, code.SubjectName)
			t.Logf("  measurement: SNP=%s RTMR1=%s RTMR2=%s shape=%+v gpus=%d", code.Measurement.Registers[0][:16]+"...", code.Measurement.Registers[1][:16]+"...", code.Measurement.Registers[2][:16]+"...", *code.Shape, *code.Shape.GPUs)

			// Show what the signed predicate says this enclave runs.
			result, payload, err := client.verifyBundleWithIdentity(bundle, mustIdentity(t, tc.repo), tc.digest)
			require.NoError(t, err)
			_ = payload
			cfgB64 := result.Statement.Predicate.GetFields()["config"].GetStringValue()
			cfg, err := base64.StdEncoding.DecodeString(cfgB64)
			require.NoError(t, err)
			for _, line := range strings.Split(string(cfg), "\n") {
				if strings.Contains(line, "cvm_admin") || strings.Contains(line, "22:22") || strings.Contains(line, "upstream-port") || strings.Contains(line, "authenticated:") || strings.Contains(line, "inbound-ports") {
					t.Logf("  measured config: %s", strings.TrimSpace(line))
				}
			}

			witnessedAt, err := client.AuthenticateFreshness(witness, &code.AuthenticatedArtifact, now, MaxFreshnessAge)
			if err != nil {
				t.Logf("  freshness witness: REJECTED (%v)", err)
				return
			}
			t.Logf("  freshness witness: ACCEPTED, witnessed at %s (expires %s, now %s)", witnessedAt.UTC().Format(time.RFC3339), witnessedAt.Add(MaxFreshnessAge).UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		})
	}
}

func mustIdentity(t *testing.T, repo string) string {
	id, err := signingIdentity(repo)
	require.NoError(t, err)
	return id
}
