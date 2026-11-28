package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert writes a self-signed localhost certificate and key, returning their paths and the cert.
func writeCert(t *testing.T) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	return certFile, keyFile, cert
}

func TestLoadTLS(t *testing.T) {
	certFile, keyFile, _ := writeCert(t)

	if c, err := loadTLS("", ""); c != nil || err != nil {
		t.Fatalf("neither: got (%v, %v), want plain HTTP", c, err)
	}
	if _, err := loadTLS(certFile, ""); err == nil {
		t.Fatal("cert without key: want an error")
	}
	if _, err := loadTLS("", keyFile); err == nil {
		t.Fatal("key without cert: want an error")
	}
	if _, err := loadTLS(certFile, filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("missing key file: want an error")
	}
	c, err := loadTLS(certFile, keyFile)
	if err != nil || len(c.Certificates) != 1 || c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("both: got (%+v, %v)", c, err)
	}
}

func TestLoadTLSServesHTTPS(t *testing.T) {
	certFile, keyFile, cert := writeCert(t)
	conf, err := loadTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = conf
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused TLS 1.1 handshake logs noise
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("https request: %v", err)
	}
	resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("want TLS 1.2+, got %+v", resp.TLS)
	}

	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS11}}}
	if _, err := old.Get(srv.URL); err == nil {
		t.Fatal("TLS 1.1 client: want handshake failure")
	}
}
