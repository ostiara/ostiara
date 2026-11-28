package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/ostiara/ostiara/internal/wire"
)

// forwardBroker echoes bytes back on /forward, then ends the stream the way the broker does at window end.
func forwardBroker(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/forward") {
			http.NotFound(w, r)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		raw := wire.NewRaw(ws)
		buf := make([]byte, 5)
		if _, err := io.ReadFull(raw, buf); err == nil {
			raw.Write(buf)
		}
		raw.CloseWith(websocket.ClosePolicyViolation, "approval window ended")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestForwardCarriesBytes(t *testing.T) {
	srv := forwardBroker(t)
	conn, err := New(srv.URL, "alice").Forward(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Two writes become two messages; the broker reads them as one stream.
	conn.Write([]byte("hel"))
	conn.Write([]byte("lo"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
		t.Fatalf("echo = %q, %v", got, err)
	}

	_, err = conn.Read(make([]byte, 1))
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.ClosePolicyViolation || ce.Text != "approval window ended" {
		t.Fatalf("after window end: err = %v, want the broker's close reason", err)
	}
}
