package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

var execSession = api.Session{
	ID: "2cd09933", Requester: "alice",
	CreateSessionRequest: api.CreateSessionRequest{Kind: api.KindExec, Namespace: "prod", Pod: "api-7f9c",
		Command: []string{"sh"}, Reason: "<!channel> see <http://evil.example|this>"},
}

// catcher records the JSON bodies posted to it.
func catcher(t *testing.T, status int) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestSlackRequestedMessage(t *testing.T) {
	srv, got := catcher(t, http.StatusOK)
	if err := (Slack{URL: srv.URL}).Send(context.Background(), Event{Kind: Requested, Session: execSession}); err != nil {
		t.Fatal(err)
	}
	text := (*got)[0]["text"].(string)
	for _, want := range []string{"alice", "prod/api-7f9c", "exec: sh", "ostiara approve 2cd09933"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "<!channel>") || strings.Contains(text, "<http://evil") {
		t.Errorf("reason wasn't escaped, so it could ping or link:\n%s", text)
	}
}

func TestTeamsCardEscapesMarkdown(t *testing.T) {
	srv, got := catcher(t, http.StatusAccepted)
	sess := execSession
	sess.Reason = "[click here](http://evil.example)"
	if err := (Teams{URL: srv.URL}).Send(context.Background(), Event{Kind: Requested, Session: sess}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal((*got)[0])
	card := string(raw)
	if !strings.Contains(card, `"AdaptiveCard"`) || !strings.Contains(card, "ostiara approve 2cd09933") {
		t.Fatalf("not the expected card: %s", card)
	}
	if strings.Contains(card, "[click here](http") || !strings.Contains(card, "[click here] (http") {
		t.Fatalf("reason became a Markdown link: %s", card)
	}
	if strings.Contains(card, `\\(`) {
		t.Fatalf("card shows backslash escapes: %s", card)
	}
}

func TestApprovedPortForwardSaysUntilWhen(t *testing.T) {
	sess := api.Session{ID: "s1", Requester: "alice", Approver: "bob",
		ExpiresAt: time.Date(2026, 11, 28, 14, 30, 0, 0, time.UTC),
		CreateSessionRequest: api.CreateSessionRequest{Kind: api.KindPortForward, Namespace: "demo", Pod: "db-0",
			Port: 5432, WindowSeconds: 1800}}
	text := slackText(summarize(Event{Kind: Approved, Session: sess}))
	for _, want := range []string{"bob approved alice", "demo/db-0:5432", "until 14:30 UTC", "port-forward for 30m0s"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}

func TestPostRetriesOnlyWhenWorthIt(t *testing.T) {
	var calls atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer flaky.Close()
	if err := post(context.Background(), http.DefaultClient, flaky.URL, map[string]string{}); err != nil || calls.Load() != 2 {
		t.Fatalf("503 then 200: err=%v calls=%d, want success after one retry", err, calls.Load())
	}

	calls.Store(0)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()
	if err := post(context.Background(), http.DefaultClient, bad.URL, map[string]string{}); err == nil || calls.Load() != 1 {
		t.Fatalf("404: err=%v calls=%d, want one failed call", err, calls.Load())
	}
}

func TestErrorsDontLeakTheWebhookURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	secretURL := srv.URL + "/services/T000/B000/s3cr3t-token"
	srv.Close() // nothing listens now, so the request fails
	err := post(context.Background(), &http.Client{Timeout: time.Second}, secretURL, map[string]string{})
	if err == nil || strings.Contains(err.Error(), "s3cr3t-token") {
		t.Fatalf("err = %v: want an error that doesn't contain the URL path", err)
	}
}

// stuckSender never finishes until released, like a chat service that hangs.
type stuckSender struct{ release chan struct{} }

func (stuckSender) Name() string { return "stuck" }
func (s stuckSender) Send(ctx context.Context, _ Event) error {
	<-s.release
	return nil
}

func TestDispatcherNeverBlocks(t *testing.T) {
	stuck := stuckSender{release: make(chan struct{})}
	d := NewDispatcher(slog.New(slog.NewTextHandler(io.Discard, nil)), stuck)

	start := time.Now()
	for range 500 { // far more than the queue holds
		d.Notify(Event{Kind: Requested, Session: execSession})
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("Notify blocked on a stuck chat service for %s", time.Since(start))
	}
	close(stuck.release)
	d.Close()
}
