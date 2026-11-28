package broker

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/ostiara/ostiara/internal/api"
)

func TestAttachRefusesBrowserOrigins(t *testing.T) {
	store := NewStore()
	sess, _ := store.Create("alice", api.CreateSessionRequest{Namespace: "demo", Pod: "p", Command: []string{"sh"}})
	if _, err := store.Decide(sess.ID, "bob", true); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(store, HeaderAuth{}, nil, nil, slog.New(slog.DiscardHandler), nil).Handler())
	defer srv.Close()

	header := http.Header{}
	header.Set(api.UserHeader, "alice")
	header.Set("Origin", "https://evil.example")
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/sessions/" + sess.ID + "/attach"
	ws, resp, err := websocket.DefaultDialer.Dial(url, header)
	if err == nil {
		ws.Close()
		t.Fatal("websocket from a browser origin: want refused")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %v", resp)
	}
	if got, _ := store.Get(sess.ID); got.Status != api.StatusApproved {
		t.Fatalf("refused attempt used up the approval: status %s", got.Status)
	}
}
