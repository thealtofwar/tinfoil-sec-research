package poc1

import (
	"encoding/json"
	"strings"
	"testing"
)

// Control: an EXACT duplicate "tcbInfo" member (the tinfoil-python finding's
// mechanism) is NOT exploitable in Go: encoding/json v1 applies "last wins" to
// both the enforced struct and the raw map, so signature and enforcement stay
// consistent and the forged copy fails signature verification.
func TestControl_ExactDuplicateKeyIsRejectedInGo(t *testing.T) {
	r := genuine(t)
	tcb := r[tcbURL]
	var top map[string]json.RawMessage
	if err := json.Unmarshal(tcb.body, &top); err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(top["tcbInfo"]), `"tcbStatus":"OutOfDate"`, `"tcbStatus":"UpToDate"`, -1)
	body := []byte(`{"tcbInfo":` + string(top["tcbInfo"]) + `,"tcbInfo":` + forged + `,"signature":` + string(top["signature"]) + `}`)
	tcb.body = body
	r[tcbURL] = tcb
	err := run(t, r)
	t.Logf("exact duplicate tcbInfo (genuine first, forged last): err=%v", err)
	if err == nil || !strings.Contains(err.Error(), "verification failure") {
		t.Fatalf("expected a signature failure for the exact-duplicate variant, got %v", err)
	}
}
