package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"

	"github.com/ostiara/ostiara/internal/audit"
	"github.com/ostiara/ostiara/internal/kube"
	"github.com/ostiara/ostiara/internal/wire"
)

// attach proxies an approved session: CLI ⇄ WebSocket ⇄ broker ⇄ exec ⇄ container.
func (s *Server) attach(w http.ResponseWriter, r *http.Request) {
	if !upgrader.CheckOrigin(r) {
		writeError(w, http.StatusForbidden, "attach is only for the ostiara CLI, not browsers")
		return // before Claim, so a refused attempt doesn't use up the approval
	}
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	sess, err := s.store.Claim(r.PathValue("id"), user)
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
	conn := wire.New(ws)
	defer conn.Close()

	// Cancelled when the CLI disconnects, which tears down the exec stream.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stdinR, stdinW := io.Pipe()
	sizes := newSizeQueue()

	// Read loop: route incoming messages by channel.
	go func() {
		defer cancel()
		defer stdinW.Close()
		defer sizes.close()
		for {
			channel, data, err := conn.Receive()
			if err != nil {
				return
			}
			switch channel {
			case wire.ChanStdin:
				if _, err := stdinW.Write(data); err != nil {
					return
				}
			case wire.ChanStdinClose:
				stdinW.Close()
			case wire.ChanResize:
				var sz wire.Resize
				if json.Unmarshal(data, &sz) == nil {
					sizes.push(remotecommand.TerminalSize{Width: sz.Width, Height: sz.Height})
				}
			}
		}
	}()

	streams := kube.Streams{
		Stdin:  stdinR,
		Stdout: conn.Writer(wire.ChanStdout),
	}
	if sess.TTY {
		streams.SizeQueue = sizes
	} else {
		streams.Stderr = conn.Writer(wire.ChanStderr)
	}

	attached := audit.ForSession(audit.Attached, sess)
	attached.Actor = user
	if err := s.record(attached); err != nil {
		_ = conn.SendJSON(wire.ChanExit, wire.Exit{Code: 1, Error: "audit log unavailable; refusing to open an unlogged session"})
		return
	}
	start := time.Now()

	err = kube.Stream(ctx, s.clientset, s.config, kube.Target{
		Namespace: sess.Namespace,
		Pod:       sess.Pod,
		Container: sess.Container,
		Command:   sess.Command,
		TTY:       sess.TTY,
	}, streams)

	// Report the exit code back to the CLI.
	var exit wire.Exit
	var exitErr utilexec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		exit.Code = exitErr.ExitStatus()
	default:
		exit.Code = 1
		exit.Error = err.Error()
	}

	ended := audit.ForSession(audit.Ended, sess)
	ended.Actor = user
	ended.ExitCode = &exit.Code
	ended.Duration = time.Since(start).Round(time.Millisecond).String()
	ended.Error = exit.Error
	s.record(ended)
	_ = conn.SendJSON(wire.ChanExit, exit)
}

// sizeQueue hands terminal sizes to the exec stream, keeping only the newest.
type sizeQueue struct {
	mu     sync.Mutex
	ch     chan remotecommand.TerminalSize
	closed bool
}

func newSizeQueue() *sizeQueue {
	return &sizeQueue{ch: make(chan remotecommand.TerminalSize, 1)}
}

func (q *sizeQueue) push(size remotecommand.TerminalSize) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	select {
	case <-q.ch: // drop a stale size
	default:
	}
	q.ch <- size
}

func (q *sizeQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.ch)
	}
}

// Next implements remotecommand.TerminalSizeQueue.
func (q *sizeQueue) Next() *remotecommand.TerminalSize {
	size, ok := <-q.ch
	if !ok {
		return nil
	}
	return &size
}
