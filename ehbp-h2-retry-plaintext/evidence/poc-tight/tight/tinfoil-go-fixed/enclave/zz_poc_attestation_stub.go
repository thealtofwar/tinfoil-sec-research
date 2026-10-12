package enclave

import "github.com/tinfoilsh/tinfoil-go/verify"

// PoCAttestationStub is a LOCAL-TEST-ONLY seam added for the security PoC.
// When non-nil it replaces exactly the attestation step of fetchVerification
// (fetch.Document + VerifyV3 + validateTransportKeys), returning what a
// successful verification of the genuine enclave would return. Nothing on the
// request path is changed: Handle, NewTransport, clientTransport, refresh and
// every tinfoil-go / EHBP / net/http layer run unmodified.
var PoCAttestationStub func(enclaveHost string) (*verify.Verification, error)
