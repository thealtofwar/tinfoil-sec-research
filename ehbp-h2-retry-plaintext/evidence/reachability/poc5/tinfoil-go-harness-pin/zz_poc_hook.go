package tinfoil

// PoC-ONLY hook: NewClientWithOptions (ehbp_transport.go) verbatim for the
// WithEnclave branch, except that the SecureClient's verified ground truth is
// preset with the replica's HPKE key instead of being fetched and verified.

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

func PoCNewClientWithOptionsPresetHPKE(hpkeKeyHex string, opts ...ClientOption) (*Client, error) {
	cfg := &clientConfig{
		repo:      defaultConfigRepo,
		transport: defaultTransportMode,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.transport == "" {
		cfg.transport = defaultTransportMode
	}
	if cfg.repo == "" {
		cfg.repo = defaultConfigRepo
	}
	if cfg.baseURLSet {
		if _, err := originOf(cfg.baseURL); err != nil {
			return nil, fmt.Errorf("invalid base URL: %w", err)
		}
	}
	if cfg.enclave == "" {
		return nil, fmt.Errorf("PoC hook requires WithEnclave")
	}
	secureClient := client.NewSecureClient(cfg.enclave, cfg.repo)
	client.PoCPresetGroundTruth(secureClient, &client.GroundTruth{EnclaveHost: cfg.enclave, HPKEPublicKey: hpkeKeyHex})
	return createClientFromSecureClient(secureClient, cfg.transport, cfg.baseURL, cfg.attestationBundleURL,
		resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet), cfg.openaiOpts...)
}
