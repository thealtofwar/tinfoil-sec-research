package main

import (
	"encoding/json"
	"testing"
)

type Level struct {
	Status string `json:"tcbStatus"`
}
type TcbInfo struct {
	Fmspc     string  `json:"fmspc"`
	NextUpdate string `json:"nextUpdate"`
	Levels    []Level `json:"tcbLevels"`
}
type Resp struct {
	TcbInfo   TcbInfo `json:"tcbInfo"`
	Signature string  `json:"signature"`
}

// Mirrors go-tdx-guest: struct decode (case-insensitive) vs raw exact-key extraction.
func TestCaseFold(t *testing.T) {
	body := []byte(`{"tcbInfo":{"fmspc":"genuine","nextUpdate":"2024-01-01","tcbLevels":[{"tcbStatus":"OutOfDate"}]},` +
		`"tcbinfo":{"nextUpdate":"2099-01-01","tcbLevels":[{"tcbStatus":"UpToDate"}]},` +
		`"signature":"sig-over-genuine"}`)
	var r Resp
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	t.Logf("struct (enforced): fmspc=%q nextUpdate=%q levels=%+v", r.TcbInfo.Fmspc, r.TcbInfo.NextUpdate, r.TcbInfo.Levels)
	t.Logf("raw exact-key (signed bytes): %s", raw["tcbInfo"])
	if r.TcbInfo.NextUpdate != "2099-01-01" || r.TcbInfo.Levels[0].Status != "UpToDate" || r.TcbInfo.Fmspc != "genuine" {
		t.Fatalf("unexpected merge semantics")
	}
	if string(raw["tcbInfo"]) != `{"fmspc":"genuine","nextUpdate":"2024-01-01","tcbLevels":[{"tcbStatus":"OutOfDate"}]}` {
		t.Fatalf("raw extraction changed")
	}
}
