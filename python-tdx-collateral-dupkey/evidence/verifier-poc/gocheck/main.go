package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	body := []byte(`{"tcbInfo":{"v":"GENUINE"},"signature":"s","tcbInfo":{"v":"FORGED"}}`)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(body, &raw)
	var st struct {
		TcbInfo struct{ V string `json:"v"` } `json:"tcbInfo"`
	}
	_ = json.Unmarshal(body, &st)
	fmt.Printf("go map[string]RawMessage (signed bytes in go-tdx-guest): %s\n", raw["tcbInfo"])
	fmt.Printf("go struct (parsed value in go-tdx-guest):              %s\n", st.TcbInfo.V)
}
