package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/ostiara/ostiara/internal/api"
)

func staticToken(token string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return token, nil }
}

// recordingBroker answers every request and remembers the last Authorization and user headers.
func recordingBroker(t *testing.T) (*httptest.Server, *http.Header) {
	t.Helper()
	var got http.Header
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		if strings.HasSuffix(r.URL.Path, "/attach") {
			if ws, err := upgrader.Upgrade(w, r, nil); err == nil {
				ws.Close()
			}
			return
		}
		w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestSendsBearerToken(t *testing.T) {
	srv, got := recordingBroker(t)
	c := New(srv.URL, "alice")
	c.Token = staticToken("abc123")

	if _, err := c.ListSessions(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if auth := got.Get("Authorization"); auth != "Bearer abc123" {
		t.Fatalf("http Authorization = %q", auth)
	}
	if user := got.Get(api.UserHeader); user != "alice" {
		t.Fatalf("http %s = %q", api.UserHeader, user)
	}

	conn, err := c.Attach(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if auth := got.Get("Authorization"); auth != "Bearer abc123" {
		t.Fatalf("websocket Authorization = %q", auth)
	}
}

func TestNoTokenSendsNoAuthorization(t *testing.T) {
	srv, got := recordingBroker(t)
	for name, token := range map[string]func(context.Context) (string, error){
		"nil source":  nil,
		"empty token": staticToken(""),
	} {
		t.Run(name, func(t *testing.T) {
			c := New(srv.URL, "alice")
			c.Token = token
			if _, err := c.ListSessions(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
			if auth := got.Get("Authorization"); auth != "" {
				t.Fatalf("Authorization = %q, want none", auth)
			}
		})
	}
}

func TestRefusesTokenOverPlainHTTP(t *testing.T) {
	c := New("http://broker.example.com", "alice")
	c.Token = staticToken("abc123")
	_, err := c.ListSessions(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v, want a refusal before any request", err)
	}
}

func TestSafeForToken(t *testing.T) {
	cases := map[string]bool{
		"https://ostiara.example.com": true,
		"http://localhost:8080":       true,
		"http://127.0.0.1:8080":       true,
		"http://[::1]:8080":           true,
		"http://ostiara.example.com":  false,
		"http://10.0.0.5:8080":        false,
		"ftp://localhost":             false,
	}
	for u, want := range cases {
		if got := safeForToken(u); got != want {
			t.Errorf("safeForToken(%q) = %v, want %v", u, got, want)
		}
	}
}
