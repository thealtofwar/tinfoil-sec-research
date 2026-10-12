package enclave

import "github.com/tinfoilsh/tinfoil-go/verify"

// NewHandleWithVerifyForPoC is a LOCAL PoC-only hook (not in the shipped SDK).
// It builds the same *Handle that NewHandle builds, except that the attestation
// fetch+verification step (fetchVerification) is replaced by f, which returns
// what a successful verification of the genuine enclave would return (its HPKE
// key). Everything downstream of verification - Handle.NewTransport,
// clientTransport admission, refresh, and every wrapper the SDK composes - is
// the shipped code.
func NewHandleWithVerifyForPoC(enclaveHost, repo string, f func() (*verify.Verification, error)) *Handle {
	return &Handle{enclave: enclaveHost, repo: repo, verify: f}
}
