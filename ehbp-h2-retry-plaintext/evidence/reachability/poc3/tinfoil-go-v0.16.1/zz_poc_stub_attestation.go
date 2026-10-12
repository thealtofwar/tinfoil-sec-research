package tinfoil

// PoC-ONLY hook (added in a local copy of tinfoil-go v0.16.1, the version
// tinfoil-proxy pins). It is a verbatim copy of NewGateway (seal_transport.go)
// with exactly one substitution: the replica's attestation handle
// (client.NewSecureClient(...).ViaRelay(gateway)) is replaced by a stub that
// hands the real ehbpHTTPClient builder a VerifiedDocumentV3 carrying the
// enclave's HPKE key, exactly as a successful verification would. Every other
// layer (hostBoundRoundTripper, sealTransport.prepare/setGatewayBody,
// verifiedReplicaTransport, recoveryTransport, enclaveURLHeaderTransport,
// EHBP v0.3.2 client.Transport over http.DefaultTransport) is the shipped code.

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

type pocStubVerifier struct {
	host       string
	hpkeKeyHex string
}

// NewTransport mirrors SecureClient.NewTransport's contract minus the
// admission layer (which only gates on verification state and passes the
// request through unchanged).
func (s pocStubVerifier) NewTransport(build func(*client.VerifiedDocumentV3) (http.RoundTripper, error), _ func(error) bool) (http.RoundTripper, error) {
	return build(&client.VerifiedDocumentV3{
		EnclaveHost: s.host,
		CryptoMaterial: []document.CryptoMaterialItem{{
			ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: s.hpkeKeyHex,
		}},
	})
}

// PoCNewGatewayStubbedAttestation == NewGateway with attestation stubbed.
func PoCNewGatewayStubbedAttestation(baseURL string, catalog func() Catalog, opts GatewayOptions, hpkeKeyHex string) (*Gateway, error) {
	cfg := &clientConfig{}
	for _, opt := range opts.ClientOptions {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.enclave != "" || cfg.repo != "" || cmp.Or(cfg.transport, TransportEHBP) != TransportEHBP || cfg.baseURLSet {
		return nil, &ConfigurationError{Err: fmt.Errorf("a gateway takes its enclaves and repositories from its catalog and uses the EHBP transport")}
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	policy, err := newGatewayPolicy(opts, cfg.verification)
	if err != nil {
		return nil, &ConfigurationError{Err: err}
	}
	if catalog == nil {
		fetched, err := FetchCatalog(base.Host)
		if err != nil {
			return nil, err
		}
		catalog = func() Catalog { return fetched }
	}
	seal := &sealTransport{
		catalog: catalog,
		policy:  policy,
		secret:  resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet),
		build: func(r replica) (http.RoundTripper, error) {
			// --- only substitution: stubbed attestation handle ---
			secure := pocStubVerifier{host: r.host, hpkeKeyHex: hpkeKeyHex}
			// ------------------------------------------------------
			httpClient, err := ehbpHTTPClient(secure, baseURL)
			if err != nil {
				return nil, err
			}
			return &verifiedReplicaTransport{
				recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
				verification:      func() *client.VerifiedDocumentV3 { return nil },
			}, nil
		},
	}
	httpClient, err := boundHTTPClient(&http.Client{Transport: seal}, "", baseURL, "")
	if err != nil {
		return nil, err
	}
	openaiClient := openai.NewClient(append(cfg.openaiOpts, option.WithHTTPClient(httpClient), option.WithBaseURL(baseURL))...)
	return &Gateway{Client: &openaiClient, httpClient: httpClient, seal: seal}, nil
}
