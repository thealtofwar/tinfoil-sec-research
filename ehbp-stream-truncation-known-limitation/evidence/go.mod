module poc

go 1.27.1

replace github.com/tinfoilsh/encrypted-http-body-protocol => ../encrypted-http-body-protocol

require (
	github.com/openai/openai-go/v3 v3.73.0
	github.com/tinfoilsh/encrypted-http-body-protocol v0.0.0-00010101000000-000000000000
)

require (
	github.com/coder/websocket v1.8.15 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/tidwall/gjson v1.19.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
