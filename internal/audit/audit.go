// Package audit writes ostiara's security events as JSON lines and checks them against Kubernetes' own audit log.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/recording"
)

// Stream tags every line so log collectors can route ostiara's audit events.
const Stream = "ostiara.audit"

// Event kinds.
const (
	Requested = "session.requested"
	Approved  = "session.approved"
	Denied    = "session.denied"
	Attached  = "session.attached"
	Ended     = "session.ended"
	Refused   = "session.refused" // e.g. self-approval or someone else's session

	ApprovalAdded = "session.approval_added" // one of several approvals a session needs

	ForwardOpened = "forward.opened" // one connection of an approved port-forward
	ForwardClosed = "forward.closed"

	RecordingViewed = "recording.viewed"
)

// Event is one line of the audit log.
type Event struct {
	Stream    string    `json:"stream"`
	Chain     string    `json:"chain,omitempty"` // one per broker run
	Seq       int64     `json:"seq,omitempty"`   // 1, 2, 3… within the chain
	Prev      string    `json:"prev,omitempty"`  // hash of the line before, empty for seq 1
	Time      time.Time `json:"time"`
	Kind      string    `json:"event"`
	Session   string    `json:"session"`
	Access    string    `json:"access,omitempty"` // exec or port-forward
	Action    string    `json:"action,omitempty"` // the predefined action, if one was used
	Actor     string    `json:"actor"`            // who did this: requester, approver, or the refused caller
	Requester string    `json:"requester,omitempty"`
	Approver  string    `json:"approver,omitempty"`
	Approvers []string  `json:"approvers,omitempty"`
	Required  int       `json:"requiredApprovals,omitempty"`
	Self      bool      `json:"selfApproved,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Pod       string    `json:"pod,omitempty"`
	Container string    `json:"container,omitempty"`
	Command   []string  `json:"command,omitempty"`
	Port      int       `json:"port,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	ExitCode  *int      `json:"exitCode,omitempty"`
	Duration  string    `json:"duration,omitempty"`
	Error     string    `json:"error,omitempty"`

	Recording *recording.Result `json:"recording,omitempty"` // session.ended: where it is and its sha256
	BytesIn   int64             `json:"bytesIn,omitempty"`   // forward.closed: client → pod
	BytesOut  int64             `json:"bytesOut,omitempty"`  // forward.closed: pod → client
}

// ForSession fills an event from a session; the caller sets Actor and any result fields.
func ForSession(kind string, s api.Session) Event {
	return Event{
		Kind:      kind,
		Session:   s.ID,
		Access:    string(s.Kind),
		Action:    s.Action,
		Requester: s.Requester,
		Approver:  s.Approver,
		Approvers: s.Approvers,
		Required:  s.RequiredApprovals,
		Self:      s.SelfApproved,
		Namespace: s.Namespace,
		Pod:       s.Pod,
		Container: s.Container,
		Command:   s.Command,
		Port:      s.Port,
		Reason:    s.Reason,
	}
}

// Log appends events to a writer, one JSON object per line, each chained to the one before
// by a hash (an HMAC when a key is set). A nil *Log discards.
type Log struct {
	mu    sync.Mutex
	w     io.Writer
	now   func() time.Time
	key   []byte
	chain string
	seq   int64
	prev  string
}

func New(w io.Writer) *Log {
	return &Log{w: w, now: time.Now, chain: newChainID()}
}

// WithKey signs every line with HMAC-SHA256, so whoever can only edit the stored log can't
// rewrite it undetected. Keep the key away from where the log is stored.
func (l *Log) WithKey(key []byte) *Log {
	l.key = key
	return l
}

// Record writes e, stamping the stream name, time and chain position.
func (l *Log) Record(e Event) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Stream = Stream
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	l.seq++
	e.Chain, e.Seq, e.Prev = l.chain, l.seq, l.prev
	line, hash, err := seal(e, l.key)
	if err != nil {
		l.seq--
		return err
	}
	if _, err := l.w.Write(append(line, '\n')); err != nil {
		l.seq--
		return err
	}
	l.prev = hash
	return nil
}

func newChainID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
