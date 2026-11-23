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

// UserHeader carries the caller's identity. DEV ONLY: not authenticated yet.
const UserHeader = "X-Ostiara-User"

// CreateSessionRequest is what `ostiara exec` sends to ask for access.
type CreateSessionRequest struct {
	Namespace string   `json:"namespace"`
	Pod       string   `json:"pod"`
	Container string   `json:"container,omitempty"`
	Command   []string `json:"command"`
	TTY       bool     `json:"tty"`
	Reason    string   `json:"reason,omitempty"`
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
}

// ErrorResponse is the body the broker returns on failure.
type ErrorResponse struct {
	Error string `json:"error"`
}
