package broker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ostiara/ostiara/internal/audit"
	"github.com/ostiara/ostiara/internal/kube"
	"github.com/ostiara/ostiara/internal/wire"
)

// forward carries one TCP connection of an approved port-forward: CLI ⇄ WebSocket ⇄ broker ⇄ pod port.
// The CLI opens one of these per local connection, until the approval window ends.
func (s *Server) forward(w http.ResponseWriter, r *http.Request) {
	if !upgrader.CheckOrigin(r) {
		writeError(w, http.StatusForbidden, "port-forward is only for the ostiara CLI, not browsers")
		return
	}
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	sess, err := s.store.ClaimForward(r.PathValue("id"), user)
	if err != nil {
		s.recordRefusal(r.PathValue("id"), user, err)
		writeStoreError(w, err)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("websocket upgrade failed", "id", sess.ID, "err", err)
		return
	}
	conn := wire.NewRaw(ws)

	opened := audit.ForSession(audit.ForwardOpened, sess)
	opened.Actor = user
	if err := s.record(opened); err != nil {
		conn.CloseWith(websocket.CloseInternalServerErr, "audit log unavailable; refusing an unlogged connection")
		return
	}

	// The approval window is a hard limit: connections still open when it ends are cut.
	ctx, cancel := context.WithDeadline(context.Background(), sess.ExpiresAt)
	defer cancel()
	start := time.Now()
	counted := &countingConn{rw: conn}
	err = kube.Forward(ctx, s.clientset, s.config, sess.Namespace, sess.Pod, sess.Port, counted)

	closed := audit.ForSession(audit.ForwardClosed, sess)
	closed.Actor = user
	closed.Duration = time.Since(start).Round(time.Millisecond).String()
	closed.BytesIn, closed.BytesOut = counted.in.Load(), counted.out.Load()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		closed.Error = "approval window ended"
		conn.CloseWith(websocket.ClosePolicyViolation, closed.Error)
	case err != nil:
		closed.Error = err.Error()
		conn.CloseWith(websocket.CloseInternalServerErr, closed.Error)
	default:
		conn.Close()
	}
	s.record(closed)
}

// countingConn counts bytes each way, for the audit log.
type countingConn struct {
	rw      io.ReadWriter
	in, out atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.rw.Read(p)
	c.in.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.rw.Write(p)
	c.out.Add(int64(n))
	return n, err
}
