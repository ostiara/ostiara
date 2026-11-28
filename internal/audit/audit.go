// Package audit writes ostiara's security events as JSON lines and checks them against Kubernetes' own audit log.
package audit

import (
	"encoding/json"
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

// Log appends events to a writer, one JSON object per line. A nil *Log discards.
type Log struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

func New(w io.Writer) *Log {
	return &Log{w: w, now: time.Now}
}

// Record writes e, stamping the stream name and time.
func (l *Log) Record(e Event) error {
	if l == nil {
		return nil
	}
	e.Stream = Stream
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.w.Write(append(line, '\n'))
	return err
}
