package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

func TestRecordWritesTaggedJSONLines(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.now = func() time.Time { return time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC) }

	sess := api.Session{ID: "s1", Requester: "alice", Approver: "bob",
		CreateSessionRequest: api.CreateSessionRequest{Namespace: "demo", Pod: "p", Command: []string{"sh"}}}
	e := ForSession(Approved, sess)
	e.Actor = "bob"
	if err := l.Record(e); err != nil {
		t.Fatal(err)
	}
	code := 7
	if err := l.Record(Event{Kind: Ended, Session: "s1", Actor: "alice", ExitCode: &code}); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", buf.String())
	}
	var got Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got.Stream != Stream || got.Kind != Approved || got.Actor != "bob" || got.Requester != "alice" ||
		got.Pod != "p" || !got.Time.Equal(l.now()) {
		t.Fatalf("first line = %+v", got)
	}
	if !strings.Contains(lines[1], `"exitCode":7`) {
		t.Fatalf("second line lacks exitCode: %s", lines[1])
	}
}

func TestNilLogDiscards(t *testing.T) {
	var l *Log
	if err := l.Record(Event{Kind: Requested}); err != nil {
		t.Fatal(err)
	}
}
