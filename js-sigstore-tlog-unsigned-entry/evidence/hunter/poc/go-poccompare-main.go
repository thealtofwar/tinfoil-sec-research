// Cross-SDK reference: run the same Sigstore bundle through tinfoil-go's provenance client
// (sigstore-go v1.2.2) with the vector's trust root. Usage: go run ./verify/poccompare <vector input.json>...
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
)

type input struct {
	BundleB64    string `json:"bundle_b64"`
	Digest       string `json:"expected_digest_sha256_hex"`
	Repo         string `json:"repo"`
	TrustRootB64 string `json:"trust_root_b64"`
}

func main() {
	for _, p := range os.Args[1:] {
		raw, err := os.ReadFile(p)
		if err != nil {
			panic(err)
		}
		var in input
		if err := json.Unmarshal(raw, &in); err != nil {
			panic(err)
		}
		root, _ := base64.StdEncoding.DecodeString(in.TrustRootB64)
		bundle, _ := base64.StdEncoding.DecodeString(in.BundleB64)
		client, err := provenance.NewClientFromJSON(root)
		if err != nil {
			fmt.Printf("%s: trust root error: %v\n", p, err)
			continue
		}
		code, err := client.AuthenticateCode(bundle, in.Repo, "", in.Digest)
		if err != nil {
			fmt.Printf("%s\n  tinfoil-go: REJECTED: %v\n", p, err)
			continue
		}
		fmt.Printf("%s\n  tinfoil-go: ACCEPTED tag=%s measurement=%v\n", p, code.Tag, code.Measurement)
	}
}
