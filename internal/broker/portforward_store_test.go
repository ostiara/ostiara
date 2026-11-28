package broker

import (
	"errors"
	"testing"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

var forwardRequest = api.CreateSessionRequest{Kind: api.KindPortForward, Namespace: "demo", Pod: "db-0", Port: 5432, WindowSeconds: 600}

func TestPortForwardLastsForItsWindow(t *testing.T) {
	s, advance := newTestStore()
	sess, _ := s.Create("alice", forwardRequest)
	approved, err := s.Decide(sess.ID, "bob", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := approved.DecidedAt.Add(10 * time.Minute); !approved.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", approved.ExpiresAt, want)
	}

	for i := range 3 { // many connections, same approval
		if _, err := s.ClaimForward(sess.ID, "alice"); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		advance(3 * time.Minute)
	}
	advance(2 * time.Minute) // 11 minutes in
	if _, err := s.ClaimForward(sess.ID, "alice"); !errors.Is(err, ErrNotAttachable) {
		t.Fatalf("after the window: err = %v, want ErrNotAttachable", err)
	}
	if got, _ := s.Get(sess.ID); got.Status != api.StatusExpired {
		t.Fatalf("status = %s, want expired", got.Status)
	}
}

func TestPortForwardRules(t *testing.T) {
	s, _ := newTestStore()
	fwd, _ := s.Create("alice", forwardRequest)
	exec, _ := s.Create("alice", demoRequest)
	s.Decide(fwd.ID, "bob", true)
	s.Decide(exec.ID, "bob", true)

	if _, err := s.ClaimForward(fwd.ID, "bob"); !errors.Is(err, ErrNotRequester) {
		t.Fatalf("someone else's port-forward: err = %v", err)
	}
	if _, err := s.Claim(fwd.ID, "alice"); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("exec on a port-forward session: err = %v", err)
	}
	if _, err := s.ClaimForward(exec.ID, "alice"); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("port-forward on an exec session: err = %v", err)
	}
	pending, _ := s.Create("alice", forwardRequest)
	if _, err := s.ClaimForward(pending.ID, "alice"); !errors.Is(err, ErrNotAttachable) {
		t.Fatalf("unapproved port-forward: err = %v", err)
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name string
		req  api.CreateSessionRequest
		ok   bool
		want api.CreateSessionRequest
	}{
		{"exec defaults", api.CreateSessionRequest{}, true, api.CreateSessionRequest{Kind: api.KindExec, Command: []string{"sh"}}},
		{"exec with a port", api.CreateSessionRequest{Port: 80}, false, api.CreateSessionRequest{}},
		{"forward default window", api.CreateSessionRequest{Kind: api.KindPortForward, Port: 80}, true,
			api.CreateSessionRequest{Kind: api.KindPortForward, Port: 80, WindowSeconds: 900}},
		{"forward without a port", api.CreateSessionRequest{Kind: api.KindPortForward}, false, api.CreateSessionRequest{}},
		{"forward port too big", api.CreateSessionRequest{Kind: api.KindPortForward, Port: 70000}, false, api.CreateSessionRequest{}},
		{"forward window too long", api.CreateSessionRequest{Kind: api.KindPortForward, Port: 80, WindowSeconds: 7200}, false, api.CreateSessionRequest{}},
		{"forward with a command", api.CreateSessionRequest{Kind: api.KindPortForward, Port: 80, Command: []string{"sh"}}, false, api.CreateSessionRequest{}},
		{"unknown kind", api.CreateSessionRequest{Kind: "attach"}, false, api.CreateSessionRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			err := normalize(&req)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && (req.Kind != tc.want.Kind || req.Port != tc.want.Port ||
				req.WindowSeconds != tc.want.WindowSeconds || len(req.Command) != len(tc.want.Command)) {
				t.Fatalf("got %+v, want %+v", req, tc.want)
			}
		})
	}
}
