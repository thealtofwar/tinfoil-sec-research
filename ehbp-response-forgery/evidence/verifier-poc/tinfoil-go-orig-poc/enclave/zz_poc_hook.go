package enclave

import "github.com/tinfoilsh/tinfoil-go/verify"

// PoCHandleWithVerification is a LOCAL-PoC-ONLY constructor. It builds a real
// Handle (real admission, refresh, invalidation and transport plumbing) whose
// attestation fetch+VerifyV3 step is replaced by f, exactly like the
// package's own tests do through the unexported verify hook. Nothing else in
// the SDK is modified.
func PoCHandleWithVerification(host, repo string, f func() (*verify.Verification, error)) (*Handle, error) {
	h, err := NewHandle(host, repo, nil)
	if err != nil {
		return nil, err
	}
	h.verify = f
	return h, nil
}
