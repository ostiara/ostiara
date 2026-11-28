// Package api holds the JSON types shared by the CLI and the broker.
package api

import "time"

// Status is the lifecycle state of a session.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusUsed     Status = "used"
	StatusExpired  Status = "expired"
)

// Kind is what a session grants.
type Kind string

const (
	KindExec        Kind = "exec"         // one command or shell, one connection
	KindPortForward Kind = "port-forward" // one pod port, any number of connections until it expires
)

// UserHeader carries the caller's identity. DEV ONLY: not authenticated yet.
const UserHeader = "X-Ostiara-User"

// CreateSessionRequest is what `ostiara exec` or `ostiara port-forward` sends to ask for access.
type CreateSessionRequest struct {
	Kind      Kind     `json:"kind,omitempty"`   // empty means exec
	Action    string   `json:"action,omitempty"` // a predefined command from the broker's catalog
	Namespace string   `json:"namespace"`
	Pod       string   `json:"pod"`
	Container string   `json:"container,omitempty"`
	Command   []string `json:"command"`
	TTY       bool     `json:"tty"`
	Reason    string   `json:"reason,omitempty"`

	Port          int `json:"port,omitempty"`          // port-forward: the pod's port
	WindowSeconds int `json:"windowSeconds,omitempty"` // port-forward: how long the approval lasts

	Redact string `json:"-"` // set by the broker from the action, never by the caller
}

// Session is one access request and its current state.
type Session struct {
	ID        string `json:"id"`
	Requester string `json:"requester"`
	CreateSessionRequest

	Status    Status    `json:"status"`
	Approver  string    `json:"approver,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	DecidedAt time.Time `json:"decidedAt,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"` // set on approval: deadline to attach, or end of a port-forward

	RequiredApprovals int      `json:"requiredApprovals,omitempty"` // distinct approvers needed
	Approvers         []string `json:"approvers,omitempty"`         // who has approved so far
	SelfApproved      bool     `json:"selfApproved,omitempty"`      // the requester approved alone (solo on-call)
}

// ErrorResponse is the body the broker returns on failure.
type ErrorResponse struct {
	Error string `json:"error"`
}
