package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/client"
)

// runPortForward requests a port-forward, waits for approval, then forwards local connections until it expires.
func runPortForward(args []string) error {
	fs := flag.NewFlagSet("port-forward", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	namespace := fs.String("n", "default", "namespace of the pod")
	reason := fs.String("reason", "", "why you need access (shown to the approver)")
	window := fs.Duration("for", 15*time.Minute, "how long the approval should last (1m to 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return errors.New("usage: ostiara port-forward [-n namespace] [-for 15m] POD [LOCAL:]REMOTE")
	}
	pod := fs.Arg(0)
	localPort, remotePort, err := parsePorts(fs.Arg(1))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c, err := newClient()
	if err != nil {
		return err
	}
	sess, err := c.CreateSession(ctx, api.CreateSessionRequest{
		Kind:          api.KindPortForward,
		Namespace:     *namespace,
		Pod:           pod,
		Port:          remotePort,
		WindowSeconds: int(window.Seconds()),
		Reason:        *reason,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "🗝️  Session %s requested: %s/%s port %d for %s\n", sess.ID, sess.Namespace, sess.Pod, sess.Port,
		time.Duration(sess.WindowSeconds)*time.Second)
	fmt.Fprintf(os.Stderr, "   Waiting for a teammate to approve. They can run:\n\n     ostiara approve %s\n\n", sess.ID)

	sess, err = waitForDecision(ctx, c, sess.ID)
	if err != nil {
		return err
	}
	switch sess.Status {
	case api.StatusApproved:
	case api.StatusDenied:
		return fmt.Errorf("session %s was denied by %s", sess.ID, sess.Approver)
	default:
		return fmt.Errorf("session %s is %s", sess.ID, sess.Status)
	}

	// Loopback only: the approval is for you, not for your network.
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, sess.ExpiresAt)
	defer cancel()
	go func() { <-ctx.Done(); ln.Close() }()

	fmt.Fprintf(os.Stderr, "✅ Approved by %s. Forwarding %s → %s/%s:%d until %s (Ctrl-C to stop)\n",
		sess.Approver, ln.Addr(), sess.Namespace, sess.Pod, sess.Port, sess.ExpiresAt.Local().Format("15:04"))

	for {
		local, err := ln.Accept()
		if err != nil {
			break
		}
		go forwardOne(ctx, c, sess.ID, local)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		fmt.Fprintln(os.Stderr, "⏱️  The approval window has ended. Request again if you still need access.")
	}
	return nil
}

// forwardOne carries one local connection through the broker to the pod.
func forwardOne(ctx context.Context, c *client.Client, id string, local net.Conn) {
	defer local.Close()
	remote, err := c.Forward(ctx, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "   connection refused: %v\n", err)
		return
	}
	defer remote.Close()

	done := make(chan error, 2)
	go func() { _, err := io.Copy(remote, local); done <- err }()
	go func() { _, err := io.Copy(local, remote); done <- err }()
	select {
	case err := <-done:
		var ce *websocket.CloseError
		if errors.As(err, &ce) && ce.Code != websocket.CloseNormalClosure {
			fmt.Fprintf(os.Stderr, "   connection closed by the broker: %s\n", ce.Text)
		}
	case <-ctx.Done():
	}
}

// parsePorts reads "5432" or "15432:5432" as local and remote ports.
func parsePorts(spec string) (local, remote int, err error) {
	l, r, found := strings.Cut(spec, ":")
	if !found {
		r = l
	}
	if local, err = parsePort(l); err != nil {
		return 0, 0, err
	}
	if remote, err = parsePort(r); err != nil {
		return 0, 0, err
	}
	return local, remote, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port %q: want a number from 1 to 65535", s)
	}
	return n, nil
}
