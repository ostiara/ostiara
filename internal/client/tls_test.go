package client

import (
	"context"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// tlsBroker is an HTTPS broker with its own self-signed CA; it returns the server and that CA as a PEM file.
func tlsBroker(t *testing.T) (*httptest.Server, string, *http.Header) {
	t.Helper()
	var got http.Header
	upgrader := websocket.Upgrader{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		if strings.HasSuffix(r.URL.Path, "/attach") {
			if ws, err := upgrader.Upgrade(w, r, nil); err == nil {
				ws.Close()
			}
			return
		}
		w.Write([]byte("[]"))
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the untrusted-client case logs a handshake error
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, caFile, &got
}

func TestUntrustedBrokerIsRefused(t *testing.T) {
	srv, _, _ := tlsBroker(t)
	c := New(srv.URL, "alice")
	if _, err := c.ListSessions(context.Background(), ""); err == nil {
		t.Fatal("broker with an unknown CA: want a certificate error")
	}
	if _, err := c.Attach(context.Background(), "s1"); err == nil {
		t.Fatal("websocket to a broker with an unknown CA: want a certificate error")
	}
}

func TestTrustCA(t *testing.T) {
	srv, caFile, got := tlsBroker(t)
	c := New(srv.URL, "alice")
	c.Token = staticToken("abc123")
	if err := c.TrustCA(caFile); err != nil {
		t.Fatal(err)
	}

	if _, err := c.ListSessions(context.Background(), ""); err != nil {
		t.Fatalf("https: %v", err)
	}
	if auth := got.Get("Authorization"); auth != "Bearer abc123" {
		t.Fatalf("https Authorization = %q", auth)
	}

	conn, err := c.Attach(context.Background(), "s1")
	if err != nil {
		t.Fatalf("wss: %v", err)
	}
	conn.Close()
	if auth := got.Get("Authorization"); auth != "Bearer abc123" {
		t.Fatalf("wss Authorization = %q", auth)
	}
}

func TestTrustCABadFiles(t *testing.T) {
	c := New("https://broker.example", "alice")
	if err := c.TrustCA(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing file: want an error")
	}
	notPEM := filepath.Join(t.TempDir(), "junk.pem")
	os.WriteFile(notPEM, []byte("not a certificate"), 0o600)
	if err := c.TrustCA(notPEM); err == nil {
		t.Fatal("file without certificates: want an error")
	}
}
