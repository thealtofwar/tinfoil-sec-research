package tinfoil

// Finding 7, test B (drop into tinfoil-go/ root package).
// A loopback HTTPS "gateway" serves a catalog mapping an inference model to the
// dev-box repo. FetchCatalog keeps it, the default (unpinned) gateway policy
// resolves the model to it, and NewGateway accepts it. Controls: a non-tinfoilsh
// repo is dropped; a client with a ModelPin rejects the substitution.

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

func TestPoC07_B_GatewayCatalogSelectsDevBoxRepo(t *testing.T) {
	const model = "llama3-3-70b"
	const devBox = "tinfoilsh/confidential-ubuntu-tinfoil-config"
	const host = "devbox.example.internal"

	gw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/catalog" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			model:          map[string]any{"repo": devBox, "hosts": []string{host}},
			"control-evil": map[string]any{"repo": "someone-else/evil", "hosts": []string{host}},
		})
	}))
	defer gw.Close()
	// FetchCatalog uses WebPKI via http.DefaultTransport; trust the loopback cert
	// (stands in for the real gateway's public certificate).
	pool := x509.NewCertPool()
	pool.AddCert(gw.Certificate())
	dt := http.DefaultTransport.(*http.Transport)
	saved := dt.TLSClientConfig
	dt.TLSClientConfig = &tls.Config{RootCAs: pool}
	defer func() { dt.TLSClientConfig = saved }()

	catalog, err := FetchCatalog(gw.Listener.Addr().String())
	require.NoError(t, err)
	entry, ok := catalog[model]
	require.True(t, ok)
	t.Logf("FetchCatalog kept %s -> repo=%s hosts=%v", model, entry.Repo, entry.Hosts)
	_, kept := catalog["control-evil"]
	require.False(t, kept)
	t.Logf("  control: non-tinfoilsh repo dropped by FetchCatalog (only the org prefix is checked)")

	policy, err := newGatewayPolicy(GatewayOptions{}, enclave.Options{})
	require.NoError(t, err)
	_, rep, err := policy.resolve(model, catalog)
	require.NoError(t, err)
	require.Equal(t, devBox, rep.ref)
	t.Logf("default policy resolve(%s): replica.ref=%q (the repo VerifyV3 will trust)", model, rep.ref)

	g, err := NewGateway(gw.URL+"/v1/", nil, GatewayOptions{})
	require.NoError(t, err)
	require.True(t, g.Serves(model))
	h, err := enclave.NewHandle(host, rep.ref, &policy.defaults)
	require.NoError(t, err)
	t.Logf("NewGateway accepted catalog; Serves(%s)=true; enclave handle host=%s repo=%s", model, h.Enclave(), h.Repo())

	pinned, err := newGatewayPolicy(GatewayOptions{ModelPins: map[string]ModelPin{model: {Repo: "tinfoilsh/confidential-model-router"}}}, enclave.Options{})
	require.NoError(t, err)
	_, _, err = pinned.resolve(model, catalog)
	require.Error(t, err)
	t.Logf("  control: with a ModelPin the substitution is REJECTED: %v", err)
}
