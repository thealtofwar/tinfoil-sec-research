// Stage 1: the two decodes go-tdx-guest performs on one PCS body, in isolation.
//
//   enforced: json.Unmarshal(body, &struct)          (encoding/json v1: member names match
//             case-insensitively; a later matching member is decoded INTO the same field)
//   signed:   map[string]json.RawMessage, then m["tcbInfo"]   (exact key)
package casefoldcheck

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"testing"
)

type Level struct {
	Status string `json:"tcbStatus"`
}
type TcbInfo struct {
	Fmspc      string  `json:"fmspc"`
	NextUpdate string  `json:"nextUpdate"`
	Levels     []Level `json:"tcbLevels"`
}
type Resp struct {
	TcbInfo   TcbInfo `json:"tcbInfo"`
	Signature string  `json:"signature"`
}

const genuine = `{"fmspc":"genuine","nextUpdate":"2024-01-01","tcbLevels":[{"tcbStatus":"OutOfDate"}]}`

var body = []byte(`{"tcbInfo":` + genuine + `,` +
	`"tcbinfo":{"nextUpdate":"2099-01-01","tcbLevels":[{"tcbStatus":"UpToDate"}]},` +
	`"signature":"sig-over-genuine"}`)

func TestV1CaseFoldMergeVsExactKeyRaw(t *testing.T) {
	var r Resp
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	t.Logf("enforced (v1 struct):     fmspc=%q nextUpdate=%q levels=%+v", r.TcbInfo.Fmspc, r.TcbInfo.NextUpdate, r.TcbInfo.Levels)
	t.Logf("signed (exact-key raw):   %s", raw["tcbInfo"])
	if r.TcbInfo.Fmspc != "genuine" || r.TcbInfo.NextUpdate != "2099-01-01" || r.TcbInfo.Levels[0].Status != "UpToDate" {
		t.Fatalf("unexpected v1 semantics")
	}
	if string(raw["tcbInfo"]) != genuine {
		t.Fatalf("unexpected raw extraction")
	}
}

// A v1 decoder with DisallowUnknownFields does not help: "tcbinfo" is not unknown to v1.
func TestV1DisallowUnknownFieldsDoesNotReject(t *testing.T) {
	var r Resp
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	err := dec.Decode(&r)
	t.Logf("v1 DisallowUnknownFields: err=%v levels=%+v", err, r.TcbInfo.Levels)
	if err != nil || r.TcbInfo.Levels[0].Status != "UpToDate" {
		t.Fatalf("expected v1 to accept and merge")
	}
}

// encoding/json/v2 (case-sensitive by default) decodes only the exact "tcbInfo"
// member; with RejectUnknownMembers it rejects the body.
func TestV2CaseSensitive(t *testing.T) {
	var r Resp
	err := jsonv2.Unmarshal(body, &r)
	t.Logf("v2 default:               err=%v levels=%+v", err, r.TcbInfo.Levels)
	if err != nil || r.TcbInfo.Levels[0].Status != "OutOfDate" {
		t.Fatalf("expected v2 to ignore the case variant")
	}
	err = jsonv2.Unmarshal(body, &r, jsonv2.RejectUnknownMembers(true))
	t.Logf("v2 RejectUnknownMembers:  err=%v", err)
	if err == nil {
		t.Fatalf("expected v2 RejectUnknownMembers to reject")
	}
}
