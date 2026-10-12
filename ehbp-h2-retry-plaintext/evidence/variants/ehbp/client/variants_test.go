package client_test

// Variant analysis for the "GetBody replays plaintext" finding. Everything runs
// on 127.0.0.1. A TLS-terminating attacker ("proxy") sits in front of a normal
// EHBP server ("enclave"). The client is the shipped EHBP Go transport built
// the way tinfoil-go builds it (NewTransportWithIdentity, no options), except
// that the inner net/http Transport is a Clone() of http.DefaultTransport with
// a test trust root, so tests do not share connection pools.
//
// Triggers exercised:
//   H2 GOAWAY(NO_ERROR, last=0) on the first stream           -> retry w/ GetBody
//   H2 GOAWAY(ENHANCE_YOUR_CALM, last=1) on a reused conn       -> retry w/ GetBody
//   H2 RST_STREAM(REFUSED_STREAM) before any DATA is read       -> retry w/ GetBody
//   H2 RST_STREAM(PROTOCOL_ERROR)                               -> (control) no retry on Go 1.27
//   H1 server closes a reused conn after reading the request:
//        with Idempotency-Key header                            -> retry w/ GetBody
//        without (openai-go default)                            -> (control) no transport retry

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

const secretMarker = "078-05-1120"

type vCapture struct {
	conn    int
	stream  uint32
	headers map[string]string
	body    bytes.Buffer
}

// action decides what the attacker does with a fully received request.
type action int

const (
	actRelay action = iota
	actRefuse
	actGoAwayNoError
	actGoAwayCalm
	actRSTProtocol
)

type h2Attacker struct {
	upstream string
	// decide is called per complete request: (connection index, request index across all conns).
	decide func(conn, n int, c *vCapture) action
	// onHeaders, if set, can act as soon as HEADERS arrive (before DATA).
	onHeaders func(conn, n int, c *vCapture) action

	mu       sync.Mutex
	conns    int
	reqs     int
	hdrs     int
	captures []*vCapture
	held     map[string][]byte // encapsulated key -> genuine ciphertext
}

func (a *h2Attacker) relay(t *testing.T, fr *http2.Framer, enc *hpack.Encoder, hbuf *bytes.Buffer, c *vCapture) {
	key := c.headers["ehbp-encapsulated-key"]
	body := c.body.Bytes()
	a.mu.Lock()
	if ct, ok := a.held[key]; ok {
		// The client re-sent this exchange (same encapsulated key). Forward the
		// genuine ciphertext captured earlier so the reply decrypts normally.
		body = ct
	}
	a.mu.Unlock()
	up, _ := http.NewRequest(http.MethodPost, a.upstream+c.headers[":path"], bytes.NewReader(body))
	if key != "" {
		up.Header.Set(protocol.EncapsulatedKeyHeader, key)
	}
	resp, err := http.DefaultClient.Do(up)
	if err != nil {
		t.Errorf("upstream: %v", err)
		return
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	hbuf.Reset()
	enc.WriteField(hpack.HeaderField{Name: ":status", Value: fmt.Sprint(resp.StatusCode)})
	if n := resp.Header.Get(protocol.ResponseNonceHeader); n != "" {
		enc.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: n})
	}
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: c.stream, BlockFragment: hbuf.Bytes(), EndHeaders: true})
	fr.WriteData(c.stream, true, rb)
}

func (a *h2Attacker) serveConn(t *testing.T, nc net.Conn) {
	defer nc.Close()
	a.mu.Lock()
	connIdx := a.conns
	a.conns++
	a.mu.Unlock()

	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(nc, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(nc, nc)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	streams := map[uint32]*vCapture{}
	var lastGood uint32
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
			c := &vCapture{conn: connIdx, stream: f.StreamID, headers: map[string]string{}}
			for _, hf := range fields {
				c.headers[hf.Name] = hf.Value
			}
			streams[f.StreamID] = c
			if a.onHeaders != nil {
				a.mu.Lock()
				n := a.hdrs
				a.hdrs++
				a.mu.Unlock()
				if a.onHeaders(connIdx, n, c) == actRefuse {
					fr.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream)
					delete(streams, f.StreamID)
					continue
				}
			}
			if f.StreamEnded() {
				ended = f.StreamID
			}
		case *http2.DataFrame:
			c := streams[f.StreamID]
			if c == nil {
				continue
			}
			c.body.Write(f.Data())
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
		c := streams[ended]
		a.mu.Lock()
		n := a.reqs
		a.reqs++
		a.captures = append(a.captures, c)
		a.mu.Unlock()
		act := actRelay
		if a.decide != nil {
			act = a.decide(connIdx, n, c)
		}
		hold := func() {
			a.mu.Lock()
			a.held[c.headers["ehbp-encapsulated-key"]] = append([]byte(nil), c.body.Bytes()...)
			a.mu.Unlock()
		}
		switch act {
		case actRelay:
			a.relay(t, fr, enc, &hbuf, c)
			lastGood = ended
		case actRefuse:
			hold()
			fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
		case actRSTProtocol:
			hold()
			fr.WriteRSTStream(ended, http2.ErrCodeProtocol)
		case actGoAwayNoError:
			// Graceful shutdown that says "I processed nothing after lastGood".
			hold()
			fr.WriteGoAway(lastGood, http2.ErrCodeNo, nil)
		case actGoAwayCalm:
			hold()
			fr.WriteGoAway(lastGood, http2.ErrCodeEnhanceYourCalm, []byte("too many requests"))
		}
	}
}

func startEnclave(t *testing.T) (*identity.Identity, *httptest.Server) {
	t.Helper()
	serverID, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(serverID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte("enclave answer to: " + string(b)))
	})))
	t.Cleanup(srv.Close)
	return serverID, srv
}

// newEHBPClient mirrors tinfoil-go buildEHBPTransport: NewTransportWithIdentity
// from the attested key. The inner transport is http.DefaultTransport's
// configuration (ForceAttemptHTTP2) with a test root CA.
func newEHBPClient(t *testing.T, serverID *identity.Identity, pool *x509.CertPool) (*http.Client, *http.Transport) {
	t.Helper()
	inner := http.DefaultTransport.(*http.Transport).Clone()
	inner.TLSClientConfig = &tls.Config{RootCAs: pool}
	pub, err := identity.FromPublicKeyHex(serverID.MarshalPublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	tr, err := client.NewTransportWithIdentity(pub, client.WithHTTPClient(&http.Client{Transport: inner}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inner.CloseIdleConnections)
	return &http.Client{Transport: tr}, inner
}

func listenH2(t *testing.T, a *h2Attacker, protos []string) (string, *x509.CertPool) {
	t.Helper()
	cert, pool := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: protos})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.serveConn(t, c)
		}
	}()
	return "https://" + ln.Addr().String(), pool
}

func secretRequest(t *testing.T, base string) *http.Request {
	body := `{"model":"m","messages":[{"role":"user","content":"TOP-SECRET prompt: my SSN is ` + secretMarker + `"}]}`
	// bytes.Buffer like openai-go's JSON bodies; NewRequest sets GetBody.
	req, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func warmup(t *testing.T, hc *http.Client, base string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/warmup", strings.NewReader(`{"warm":"up"}`))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("warmup: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func report(t *testing.T, caps []*vCapture) bool {
	leaked := false
	for i, c := range caps {
		b := c.body.String()
		if len(b) > 100 {
			b = b[:100] + "..."
		}
		plain := strings.Contains(c.body.String(), secretMarker)
		if plain {
			leaked = true
		}
		k := c.headers["ehbp-encapsulated-key"]
		if len(k) > 16 {
			k = k[:16] + ".."
		}
		t.Logf("  capture %d: conn=%d stream=%d %s ehbp-encapsulated-key=%s plaintext=%v body=%q", i, c.conn, c.stream, c.headers[":path"], k, plain, b)
	}
	return leaked
}

func runH2Variant(t *testing.T, a *h2Attacker, doWarmup bool) {
	serverID, enclave := startEnclave(t)
	a.upstream = enclave.URL
	a.held = map[string][]byte{}
	base, pool := listenH2(t, a, []string{"h2"})
	hc, _ := newEHBPClient(t, serverID, pool)
	if doWarmup {
		warmup(t, hc, base)
	}
	resp, err := hc.Do(secretRequest(t, base))
	var got []byte
	if err == nil {
		got, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("client result: status=%d proto=%s body=%q", resp.StatusCode, resp.Proto, got)
	} else {
		t.Logf("client result: error=%v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	leaked := report(t, a.captures)
	if leaked {
		t.Logf("RESULT: plaintext body reached the TLS-terminating attacker (client err=%v)", err)
	} else {
		t.Logf("RESULT: no plaintext observed by the attacker")
	}
	t.Cleanup(func() {})
	vResults.Store(t.Name(), fmt.Sprintf("leaked=%v clientErr=%v clientOK=%v", leaked, err != nil, err == nil && strings.Contains(string(got), secretMarker)))
}

var vResults sync.Map

func TestVariant_H2_GoAwayNoError_FirstStream(t *testing.T) {
	a := &h2Attacker{decide: func(conn, n int, c *vCapture) action {
		if n == 0 {
			return actGoAwayNoError // GOAWAY last_stream_id=0, NO_ERROR
		}
		return actRelay
	}}
	runH2Variant(t, a, false)
}

func TestVariant_H2_GoAwayEnhanceYourCalm_ReusedConn(t *testing.T) {
	a := &h2Attacker{decide: func(conn, n int, c *vCapture) action {
		if n == 1 { // the secret request, stream 3 on the reused connection
			return actGoAwayCalm // GOAWAY last_stream_id=1, ENHANCE_YOUR_CALM
		}
		return actRelay
	}}
	runH2Variant(t, a, true)
}

func TestVariant_H2_RefusedStreamOnHeaders_NoDataRead(t *testing.T) {
	// Refuse as soon as HEADERS arrive: the attacker never even needs the
	// ciphertext; the client still re-sends the plaintext. (No successful
	// relay possible here since nothing was held; this only shows the leak.)
	a := &h2Attacker{onHeaders: func(conn, n int, c *vCapture) action {
		if n == 0 {
			return actRefuse
		}
		return actRelay
	}}
	runH2Variant(t, a, false)
}

func TestVariant_H2_RSTProtocolError_Control(t *testing.T) {
	a := &h2Attacker{decide: func(conn, n int, c *vCapture) action {
		if n == 0 {
			return actRSTProtocol
		}
		return actRelay
	}}
	runH2Variant(t, a, false)
}

// ---- HTTP/1.1 ----

type h1Attacker struct {
	upstream string
	mu       sync.Mutex
	n        int
	captures []*vCapture
	held     map[string][]byte
	conns    map[net.Conn]int
}

func (a *h1Attacker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c := &vCapture{headers: map[string]string{":path": r.URL.Path, "ehbp-encapsulated-key": r.Header.Get(protocol.EncapsulatedKeyHeader)}}
	c.body.Write(body)
	a.mu.Lock()
	n := a.n
	a.n++
	a.captures = append(a.captures, c)
	key := r.Header.Get(protocol.EncapsulatedKeyHeader)
	fwd := body
	if ct, ok := a.held[key]; ok {
		fwd = ct
	}
	a.mu.Unlock()
	if n == 1 {
		// Second request on the kept-alive connection: keep the ciphertext and
		// drop the connection without answering.
		a.mu.Lock()
		a.held[key] = body
		a.mu.Unlock()
		hj, _ := w.(http.Hijacker)
		conn, _, err := hj.Hijack()
		if err == nil {
			conn.Close()
		}
		return
	}
	up, _ := http.NewRequest(http.MethodPost, a.upstream+r.URL.Path, bytes.NewReader(fwd))
	if key != "" {
		up.Header.Set(protocol.EncapsulatedKeyHeader, key)
	}
	resp, err := http.DefaultClient.Do(up)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	if nonce := resp.Header.Get(protocol.ResponseNonceHeader); nonce != "" {
		w.Header().Set(protocol.ResponseNonceHeader, nonce)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func runH1Variant(t *testing.T, idempotencyKey bool) {
	serverID, enclave := startEnclave(t)
	a := &h1Attacker{upstream: enclave.URL, held: map[string][]byte{}}
	srv := httptest.NewUnstartedServer(a)
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	hc, _ := newEHBPClient(t, serverID, pool)
	warmup(t, hc, srv.URL)
	req := secretRequest(t, srv.URL)
	if idempotencyKey {
		req.Header.Set("Idempotency-Key", "abc123")
	}
	resp, err := hc.Do(req)
	var got []byte
	if err == nil {
		got, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("client result: status=%d proto=%s body=%q", resp.StatusCode, resp.Proto, got)
	} else {
		t.Logf("client result: error=%v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	leaked := report(t, a.captures)
	if leaked {
		t.Logf("RESULT: plaintext body reached the TLS-terminating attacker over HTTP/1.1 (client err=%v)", err)
	} else {
		t.Logf("RESULT: no plaintext observed by the attacker")
	}
	vResults.Store(t.Name(), fmt.Sprintf("leaked=%v clientErr=%v clientOK=%v", leaked, err != nil, err == nil && strings.Contains(string(got), secretMarker)))
}

func TestVariant_H1_ReusedConnDropped_WithIdempotencyKey(t *testing.T) {
	runH1Variant(t, true)
}

func TestVariant_H1_ReusedConnDropped_NoIdempotencyKey_Control(t *testing.T) {
	runH1Variant(t, false)
}

func TestVariant_Summary(t *testing.T) {
	vResults.Range(func(k, v any) bool {
		t.Logf("%-60s %s", k, v)
		return true
	})
}
