package broker

import (
	"errors"
	"testing"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

// newTestStore returns a store with a controllable clock.
func newTestStore() (*Store, func(time.Duration)) {
	s := NewStore()
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	advance := func(d time.Duration) { now = now.Add(d) }
	return s, advance
}

var demoRequest = api.CreateSessionRequest{Namespace: "demo", Pod: "demo-pod", Command: []string{"sh"}}

func TestHappyPath(t *testing.T) {
	s, _ := newTestStore()
	sess, err := s.Create("alice", demoRequest)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.Status != api.StatusPending {
		t.Fatalf("new session status = %s, want pending", sess.Status)
	}
	if _, err := s.Decide(sess.ID, "bob", true); err != nil {
		t.Fatalf("bob approving: %v", err)
	}
	got, err := s.Claim(sess.ID, "alice")
	if err != nil {
		t.Fatalf("alice claiming: %v", err)
	}
	if got.Status != api.StatusUsed || got.Approver != "bob" {
		t.Fatalf("after claim: status=%s approver=%s, want used/bob", got.Status, got.Approver)
	}
}

func TestRules(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(s *Store, advance func(time.Duration), id string) error
		wantErr error
	}{
		{
			name: "requester can't approve own session",
			setup: func(s *Store, _ func(time.Duration), id string) error {
				_, err := s.Decide(id, "alice", true)
				return err
			},
			wantErr: ErrSelfApproval,
		},
		{
			name: "can't connect before approval",
			setup: func(s *Store, _ func(time.Duration), id string) error {
				_, err := s.Claim(id, "alice")
				return err
			},
			wantErr: ErrNotAttachable,
		},
		{
			name: "someone else can't use alice's approval",
			setup: func(s *Store, _ func(time.Duration), id string) error {
				s.Decide(id, "bob", true)
				_, err := s.Claim(id, "mallory")
				return err
			},
			wantErr: ErrNotRequester,
		},
		{
			name: "an approval works only once",
			setup: func(s *Store, _ func(time.Duration), id string) error {
				s.Decide(id, "bob", true)
				s.Claim(id, "alice")
				_, err := s.Claim(id, "alice")
				return err
			},
			wantErr: ErrNotAttachable,
		},
		{
			name: "denied session can't be used",
			setup: func(s *Store, _ func(time.Duration), id string) error {
				s.Decide(id, "bob", false)
				_, err := s.Claim(id, "alice")
				return err
			},
			wantErr: ErrNotAttachable,
		},
		{
			name: "can't approve after a decision",
			setup: func(s *Store, _ func(time.Duration), id string) error {
				s.Decide(id, "bob", false)
				_, err := s.Decide(id, "carol", true)
				return err
			},
			wantErr: ErrNotPending,
		},
		{
			name: "pending request expires",
			setup: func(s *Store, advance func(time.Duration), id string) error {
				advance(16 * time.Minute)
				_, err := s.Decide(id, "bob", true)
				return err
			},
			wantErr: ErrNotPending,
		},
		{
			name: "approval expires if not used in time",
			setup: func(s *Store, advance func(time.Duration), id string) error {
				s.Decide(id, "bob", true)
				advance(6 * time.Minute)
				_, err := s.Claim(id, "alice")
				return err
			},
			wantErr: ErrNotAttachable,
		},
		{
			name: "unknown session",
			setup: func(s *Store, _ func(time.Duration), _ string) error {
				_, err := s.Get("nope")
				return err
			},
			wantErr: ErrNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, advance := newTestStore()
			sess, _ := s.Create("alice", demoRequest)
			if err := tc.setup(s, advance, sess.ID); !errors.Is(err, tc.wantErr) {
				t.Fatalf("got error %v, want %v", err, tc.wantErr)
			}
		})
	}
}
