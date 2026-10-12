// Standalone local HTTP/2 attacker: refuses (or GOAWAYs) the first N complete
// requests, answers later ones with a 200 (no EHBP nonce), and logs every
// received body to stdout as JSON lines. Listens on 127.0.0.1 only.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	mode  = flag.String("mode", "refuse", "refuse|goaway")
	count = flag.Int("count", 1, "how many requests to refuse")
	caOut = flag.String("ca", "ca.pem", "write cert PEM here")
	mu    sync.Mutex
	seen  int
)

func main() {
	flag.Parse()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "attacker.local"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	os.WriteFile(*caOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h2"}})
	if err != nil {
		panic(err)
	}
	fmt.Printf("{\"listen\":%q}\n", ln.Addr().String())
	os.Stdout.Sync()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(c)
	}
}

type st struct {
	h    map[string]string
	body bytes.Buffer
}

func serve(nc net.Conn) {
	defer nc.Close()
	pre := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(nc, pre); err != nil || string(pre) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(nc, nc)
	fr.WriteSettings()
	dec := hpack.NewDecoder(4096, nil)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	streams := map[uint32]*st{}
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
			fields, _ := dec.DecodeFull(f.HeaderBlockFragment())
			s := &st{h: map[string]string{}}
			for _, hf := range fields {
				s.h[hf.Name] = hf.Value
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
		mu.Lock()
		i := seen
		seen++
		mu.Unlock()
		line, _ := json.Marshal(map[string]any{"n": i, "stream": ended, "path": s.h[":path"], "ehbp_key": s.h["ehbp-encapsulated-key"], "body": s.body.String()})
		fmt.Println(string(line))
		os.Stdout.Sync()
		if i < *count {
			if *mode == "goaway" {
				fr.WriteGoAway(0, http2.ErrCodeNo, nil)
			} else {
				fr.WriteRSTStream(ended, http2.ErrCodeRefusedStream)
			}
			continue
		}
		hb.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "503"})
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: ended, BlockFragment: hb.Bytes(), EndHeaders: true})
		fr.WriteData(ended, true, []byte("unavailable"))
	}
}
