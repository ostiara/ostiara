// Package broker holds exec rights and uses them only after a teammate approves.
package broker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

var (
	ErrNotFound      = errors.New("session not found")
	ErrSelfApproval  = errors.New("you can't approve or deny your own session: ask a teammate")
	ErrNotPending    = errors.New("session is no longer pending")
	ErrNotRequester  = errors.New("only the person who requested this session can use it")
	ErrNotAttachable = errors.New("session isn't approved, was already used, or has expired")
	ErrWrongKind     = errors.New("this session is for a different kind of access")
)

// Store keeps sessions in memory and enforces the approval rules.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*api.Session

	pendingTTL time.Duration
	attachTTL  time.Duration
	now        func() time.Time // swapped for a fake clock in tests
}

func NewStore() *Store {
	return &Store{
		sessions:   make(map[string]*api.Session),
		pendingTTL: 15 * time.Minute,
		attachTTL:  5 * time.Minute,
		now:        time.Now,
	}
}

// Create records a new pending session.
func (s *Store) Create(requester string, req api.CreateSessionRequest) (api.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.newIDLocked()
	if err != nil {
		return api.Session{}, err
	}
	if req.Kind == "" {
		req.Kind = api.KindExec
	}
	sess := &api.Session{
		ID:                   id,
		Requester:            requester,
		CreateSessionRequest: req,
		Status:               api.StatusPending,
		CreatedAt:            s.now(),
	}
	s.sessions[id] = sess
	return snapshot(sess), nil
}

func (s *Store) Get(id string) (api.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return api.Session{}, ErrNotFound
	}
	s.expireLocked(sess)
	return snapshot(sess), nil
}

// List returns sessions newest first; an empty status returns all.
func (s *Store) List(status api.Status) []api.Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []api.Session
	for _, sess := range s.sessions {
		s.expireLocked(sess)
		if status == "" || sess.Status == status {
			out = append(out, snapshot(sess))
		}
	}
	slices.SortFunc(out, func(a, b api.Session) int {
		return b.CreatedAt.Compare(a.CreatedAt)
	})
	return out
}

// Decide approves or denies a pending session. The requester can't decide their own.
func (s *Store) Decide(id, decider string, approve bool) (api.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return api.Session{}, ErrNotFound
	}
	s.expireLocked(sess)

	if sess.Requester == decider {
		return api.Session{}, ErrSelfApproval
	}
	if sess.Status != api.StatusPending {
		return api.Session{}, ErrNotPending
	}

	if approve {
		sess.Status = api.StatusApproved
	} else {
		sess.Status = api.StatusDenied
	}
	sess.Approver = decider
	sess.DecidedAt = s.now()
	if approve {
		sess.ExpiresAt = sess.DecidedAt.Add(s.attachTTL)
		if sess.Kind == api.KindPortForward {
			sess.ExpiresAt = sess.DecidedAt.Add(time.Duration(sess.WindowSeconds) * time.Second)
		}
	}
	return snapshot(sess), nil
}

// Claim marks an approved session as used: one approval, one connection.
func (s *Store) Claim(id, user string) (api.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return api.Session{}, ErrNotFound
	}
	s.expireLocked(sess)

	if sess.Requester != user {
		return api.Session{}, ErrNotRequester
	}
	if sess.Kind != api.KindExec {
		return api.Session{}, ErrWrongKind
	}
	if sess.Status != api.StatusApproved {
		return api.Session{}, ErrNotAttachable
	}
	sess.Status = api.StatusUsed
	return snapshot(sess), nil
}

// ClaimForward lets the requester open one more connection of an approved port-forward.
// Unlike Claim it doesn't use the session up: it lasts until ExpiresAt.
func (s *Store) ClaimForward(id, user string) (api.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return api.Session{}, ErrNotFound
	}
	s.expireLocked(sess)

	if sess.Requester != user {
		return api.Session{}, ErrNotRequester
	}
	if sess.Kind != api.KindPortForward {
		return api.Session{}, ErrWrongKind
	}
	if sess.Status != api.StatusApproved {
		return api.Session{}, ErrNotAttachable
	}
	return snapshot(sess), nil
}

// expireLocked expires a session whose time ran out. Caller holds s.mu.
func (s *Store) expireLocked(sess *api.Session) {
	now := s.now()
	switch sess.Status {
	case api.StatusPending:
		if now.Sub(sess.CreatedAt) > s.pendingTTL {
			sess.Status = api.StatusExpired
		}
	case api.StatusApproved:
		if now.After(sess.ExpiresAt) {
			sess.Status = api.StatusExpired
		}
	}
}

func (s *Store) newIDLocked() (string, error) {
	for {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		id := hex.EncodeToString(b)
		if _, taken := s.sessions[id]; !taken {
			return id, nil
		}
	}
}

// snapshot copies a session so callers can't modify the stored one.
func snapshot(sess *api.Session) api.Session {
	c := *sess
	c.Command = slices.Clone(sess.Command)
	return c
}
