// Stage 2: google/go-tdx-guest enforces TCB Info / QE Identity values taken from
// an UNSIGNED member whose name differs from the signed member only in case.
//
// Material (all genuine, nothing synthetic):
//   - quote: Intel's production SPR quote shipped as go-tdx-guest testdata
//     (testing/testdata.RawQuote), PCK chain valid until 2029;
//   - collateral: Intel PCS responses for FMSPC 50806f000000 (TCB Info, QE Identity,
//     platform PCK CRL, Root CA CRL) with their issuer-chain headers, fetched from
//     api.trustedservices.intel.com on 2026-10-08 (valid until 2026-11-06);
//   - trust anchor: go-tdx-guest's embedded Intel SGX Root CA; clock: time.Now().
// The Getter replays the captured responses (stand-in for whoever supplies them).
package gotdxcasefold

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/go-tdx-guest/verify"
)

const (
	tcbURL    = "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
	qeidURL   = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	pckcrlURL = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der"
	rootURL   = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
)

type resp struct {
	headers map[string][]string
	body    []byte
}

type replay map[string]resp

func (g replay) Get(url string) (map[string][]string, []byte, error) {
	r, ok := g[url]
	if !ok {
		return nil, nil, fmt.Errorf("no captured response for %s", url)
	}
	return r.headers, bytes.Clone(r.body), nil
}

func load(t *testing.T, name string) resp {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name+".body"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", name+".headers"))
	if err != nil {
		t.Fatal(err)
	}
	h := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.HasPrefix(k, "HTTP/") {
			continue
		}
		ck := textproto.CanonicalMIMEHeaderKey(k)
		h[ck] = append(h[ck], strings.TrimSpace(v))
	}
	return resp{headers: h, body: body}
}

func genuine(t *testing.T) replay {
	return replay{tcbURL: load(t, "tcb"), qeidURL: load(t, "qeid"), pckcrlURL: load(t, "pckcrl"), rootURL: load(t, "rootcrl")}
}

// caseVariant keeps the signed member and the signature byte-for-byte and inserts an
// unsigned member whose name differs only in case. Nothing signed is modified.
func caseVariant(t *testing.T, body []byte, signedKey, variantKey string, override any) []byte {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	ov, _ := json.Marshal(override)
	return []byte(`{"` + signedKey + `":` + string(top[signedKey]) + `,"` + variantKey + `":` + string(ov) +
		`,"signature":` + string(top["signature"]) + `}`)
}

func verifyQuote(t *testing.T, g replay) error {
	q, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	opts := &verify.Options{Getter: g, GetCollateral: true, CheckRevocations: true} // TrustedRoots nil = embedded Intel root
	setNow(opts)
	return verify.TdxQuote(q, opts)
}

func zeros() []map[string]any {
	z := make([]map[string]any, 16)
	for i := range z {
		z[i] = map[string]any{"svn": 0}
	}
	return z
}

// Attacker-chosen TCB Info: a single "UpToDate" level at SVN 0, and a TDX module identity at ISVSVN 0.
func forgedTcb() map[string]any {
	lvl := map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}
	return map[string]any{
		"tcbLevels": []any{map[string]any{"tcb": map[string]any{"sgxtcbcomponents": zeros(), "pcesvn": 0, "tdxtcbcomponents": zeros()},
			"tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}},
		"tdxModuleIdentities": []any{map[string]any{"id": "TDX_00", "mrsigner": strings.Repeat("0", 96),
			"attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF", "tcbLevels": []any{lvl}}},
	}
}

func forgedQe(extra map[string]any) map[string]any {
	m := map[string]any{"tcbLevels": []any{map[string]any{"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate"}}}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestA_Control_GenuineCollateralRejected(t *testing.T) {
	err := verifyQuote(t, genuine(t))
	t.Logf("genuine Intel collateral: err=%v", err)
	if err == nil {
		t.Fatal("expected rejection: the 2023 platform is below Intel's current TCB levels")
	}
}

func TestB_CaseVariantMembersAccepted(t *testing.T) {
	g := genuine(t)
	r := g[tcbURL]
	r.body = caseVariant(t, r.body, "tcbInfo", "tcbinfo", forgedTcb())
	g[tcbURL] = r
	r = g[qeidURL]
	r.body = caseVariant(t, r.body, "enclaveIdentity", "enclaveidentity", forgedQe(nil))
	g[qeidURL] = r
	err := verifyQuote(t, g)
	t.Logf("+ unsigned \"tcbinfo\"/\"enclaveidentity\" members: err=%v", err)
	if err != nil {
		t.Fatalf("expected acceptance, got %v", err)
	}
}

func TestC_UnsignedQeMrsignerIsEnforced(t *testing.T) {
	g := genuine(t)
	r := g[tcbURL]
	r.body = caseVariant(t, r.body, "tcbInfo", "tcbinfo", forgedTcb())
	g[tcbURL] = r
	r = g[qeidURL]
	r.body = caseVariant(t, r.body, "enclaveIdentity", "enclaveidentity", forgedQe(map[string]any{"mrsigner": strings.Repeat("ab", 32)}))
	g[qeidURL] = r
	err := verifyQuote(t, g)
	t.Logf("+ unsigned enclaveidentity.mrsigner=abab..: err=%.200v", err)
	if err == nil || !strings.Contains(err.Error(), "MRSIGNER") {
		t.Fatalf("expected the QE MRSIGNER check to use the unsigned value, got %v", err)
	}
}

func TestD_Control_ExactDuplicateKeyRejected(t *testing.T) {
	g := genuine(t)
	r := g[tcbURL]
	var top map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &top); err != nil {
		t.Fatal(err)
	}
	forged := strings.ReplaceAll(string(top["tcbInfo"]), `"tcbStatus":"OutOfDate"`, `"tcbStatus":"UpToDate"`)
	r.body = []byte(`{"tcbInfo":` + string(top["tcbInfo"]) + `,"tcbInfo":` + forged + `,"signature":` + string(top["signature"]) + `}`)
	g[tcbURL] = r
	err := verifyQuote(t, g)
	t.Logf("exact duplicate \"tcbInfo\" (last wins for both decodes): err=%v", err)
	if err == nil || !strings.Contains(err.Error(), "verification failure") {
		t.Fatalf("expected a signature failure, got %v", err)
	}
}
