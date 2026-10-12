// gencerts writes an attacker-controlled CA plus a leaf certificate for the
// enclave hostname the router polls. The CA stands in for any WebPKI CA that
// would issue a certificate for the enclave's DNS name (e.g. via ACME HTTP-01
// answered by the host operator). Output: certs/ca.pem, certs/leaf.pem,
// certs/leaf-key.pem (all ECDSA P-256).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := os.Args[1]
	host := os.Args[2]

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PoC WebPKI stand-in CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	check(err)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	check(err)
	leafKeyDER, _ := x509.MarshalECPrivateKey(leafKey)

	write(filepath.Join(out, "ca.pem"), "CERTIFICATE", caDER)
	write(filepath.Join(out, "leaf.pem"), "CERTIFICATE", leafDER)
	write(filepath.Join(out, "leaf-key.pem"), "EC PRIVATE KEY", leafKeyDER)
	fmt.Printf("wrote CA and leaf for %s into %s\n", host, out)
}

func write(path, typ string, der []byte) {
	check(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
