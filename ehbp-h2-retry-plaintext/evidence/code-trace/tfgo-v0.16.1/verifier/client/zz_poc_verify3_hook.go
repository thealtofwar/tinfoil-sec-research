package client

// LOCAL PoC-only hook (not shipped): same SecureClient as NewSecureClient, but
// the attestation fetch+verification step is replaced by f.
func NewSecureClientWithVerifyForPoC(enclave, repo string, f func() (*VerifiedDocumentV3, error)) *SecureClient {
	return &SecureClient{enclave: enclave, repo: repo, verify: f}
}
