package tinfoil

import (
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// PoCReplaceGatewayAttestation is a LOCAL PoC-only hook (not shipped). It
// re-installs the shipped seal.build closure from NewGateway with one change:
// the replica's attestation fetch+verify (NewSecureClient(...).ViaRelay(...))
// is replaced by f, which returns the genuine replica's HPKE key.
func PoCReplaceGatewayAttestation(g *Gateway, baseURL string, f func(host string) func() (*client.VerifiedDocumentV3, error)) {
	g.seal.build = func(r replica) (http.RoundTripper, error) {
		secure := client.NewSecureClientWithVerifyForPoC(r.host, r.ref, f(r.host))
		httpClient, err := ehbpHTTPClient(secure, baseURL)
		if err != nil {
			return nil, err
		}
		return &verifiedReplicaTransport{
			recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
			verification:      secure.Verification,
		}, nil
	}
}
