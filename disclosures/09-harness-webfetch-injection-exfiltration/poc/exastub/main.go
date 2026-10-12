// exastub is a loopback stand-in for the two third-party HTTPS services the
// shipped confidential-websearch binary talks to: api.exa.ai (search and
// contents) and api.cloudflare.com (the Radar top-500k domain list).
//
// The websearch process reaches it through HTTPS_PROXY (CONNECT); exastub
// terminates TLS for those hostnames with certificates issued by a throwaway CA
// that the websearch process trusts through SSL_CERT_FILE. No shipped source is
// modified.
//
// Exa "livecrawl" is emulated faithfully for the purpose of the PoC: every URL
// passed to POST /contents is fetched over HTTP from the address that -crawl-map
// names for its host (the attacker's web server), with the original Host header,
// which is what Exa's crawler does for a URL it has not cached.
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
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	listen   = flag.String("listen", "127.0.0.1:20312", "proxy listen address")
	caOut    = flag.String("ca-out", "ca.pem", "where to write the CA certificate (PEM)")
	logPath  = flag.String("log", "exastub.log", "request log (JSON lines)")
	crawlMap = flag.String("crawl-map", "", "comma separated host=addr pairs the emulated crawler fetches from")
	topList  = flag.String("top-domains", "github.com,githubusercontent.com,medium.com,reddit.com,substack.com,wordpress.com,notion.site", "domains served as the Cloudflare Radar top bucket")
)

var (
	logMu   sync.Mutex
	logFile *os.File
)

func record(kind string, fields map[string]any) {
	fields["t"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["kind"] = kind
	b, _ := json.Marshal(fields)
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		logFile.Write(append(b, '\n'))
	}
	log.Printf("%s", b)
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	mu   sync.Mutex
	leaf map[string]*tls.Certificate
}

func newCA() (*ca, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tinfoil-review PoC CA (throwaway)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &ca{cert: cert, key: key, leaf: map[string]*tls.Certificate{}}, nil
}

func (c *ca) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

func (c *ca) certFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf := c.leaf[host]; leaf != nil {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}
	c.leaf[host] = leaf
	return leaf, nil
}

// oneConn hands a single hijacked connection to http.Server.Serve.
type oneConn struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.conn.LocalAddr() }

type stub struct {
	ca      *ca
	crawl   map[string]string
	top     []string
	crawler *http.Client
}

// ServeHTTP is the proxy entry point: CONNECT tunnels are terminated here.
func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "exastub only serves CONNECT", http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	record("connect", map[string]any{"host": r.Host})
	leaf, err := s.ca.certFor(host)
	if err != nil {
		conn.Close()
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	l := &oneConn{conn: tlsConn, done: make(chan struct{})}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.upstream(host, w, r) })}
	go func() {
		srv.Serve(l)
	}()
	// The server returns from Serve only when Accept fails; keep the listener
	// alive while the hijacked connection is used, then release it.
	go func() {
		time.Sleep(10 * time.Minute)
		close(l.done)
	}()
}

type contentsRequest struct {
	URLs        []string `json:"urls"`
	Text        bool     `json:"text"`
	MaxAgeHours int      `json:"maxAgeHours"`
}

func (s *stub) upstream(host string, w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	record("upstream-request", map[string]any{"host": host, "method": r.Method, "path": r.URL.Path, "x-api-key-present": r.Header.Get("x-api-key") != "", "authorization-present": r.Header.Get("Authorization") != "", "body": string(body)})
	switch {
	case host == "api.exa.ai" && r.URL.Path == "/contents":
		var req contentsRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		type result struct {
			URL  string `json:"url"`
			Text string `json:"text"`
		}
		results := []result{}
		for _, u := range req.URLs {
			results = append(results, result{URL: u, Text: s.livecrawl(u)})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	case host == "api.exa.ai" && r.URL.Path == "/search":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"title": "attacker notes", "url": "https://github.com/attacker/notes", "text": "release notes"}}})
	case host == "api.cloudflare.com" && strings.HasPrefix(r.URL.Path, "/client/v4/radar/datasets/"):
		w.Header().Set("Content-Type", "text/csv")
		fmt.Fprintln(w, "domain")
		for _, d := range s.top {
			fmt.Fprintln(w, d)
		}
	default:
		http.Error(w, "exastub: unknown upstream "+host+r.URL.Path, 404)
	}
}

// livecrawl fetches the URL the way a crawler that has never seen it would.
func (s *stub) livecrawl(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	addr := s.crawl[strings.ToLower(u.Hostname())]
	if addr == "" {
		record("crawl-skipped", map[string]any{"url": raw, "reason": "host not in -crawl-map"})
		return ""
	}
	target := "http://" + addr + u.RequestURI()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return ""
	}
	req.Host = u.Host
	req.Header.Set("User-Agent", "exastub-livecrawl/1.0 (emulating Exa)")
	resp, err := s.crawler.Do(req)
	if err != nil {
		record("crawl-error", map[string]any{"url": raw, "error": err.Error()})
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	record("crawl", map[string]any{"url": raw, "fetched_from": target, "status": resp.StatusCode, "bytes": len(b)})
	return string(bytes.TrimSpace(b))
}

func main() {
	flag.Parse()
	var err error
	logFile, err = os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	authority, err := newCA()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caOut, authority.pem(), 0o644); err != nil {
		log.Fatal(err)
	}
	s := &stub{ca: authority, crawl: map[string]string{}, crawler: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}}
	for _, pair := range strings.Split(*crawlMap, ",") {
		if host, addr, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
			s.crawl[strings.ToLower(host)] = addr
		}
	}
	for _, d := range strings.Split(*topList, ",") {
		if d = strings.TrimSpace(d); d != "" {
			s.top = append(s.top, d)
		}
	}
	log.Printf("exastub listening on %s (CA written to %s); crawl map %v", *listen, *caOut, s.crawl)
	log.Fatal(http.ListenAndServe(*listen, s))
}
