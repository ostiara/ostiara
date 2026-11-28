package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/client"
)

// runExec requests a session, waits for approval, then connects.
func runExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	namespace := fs.String("n", "default", "namespace of the pod")
	container := fs.String("c", "", "container name (default: the pod's default container)")
	reason := fs.String("reason", "", "why you need access (shown to the approver)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return errors.New("missing POD name")
	}
	pod, command := rest[0], rest[1:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		command = []string{"sh"}
	}
	tty := term.IsTerminal(int(os.Stdin.Fd()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c, err := newClient()
	if err != nil {
		return err
	}
	return requestAndAttach(ctx, c, api.CreateSessionRequest{
		Namespace: *namespace,
		Pod:       pod,
		Container: *container,
		Command:   command,
		TTY:       tty,
		Reason:    *reason,
	}, tty)
}

// requestAndAttach asks for a session, waits for approval unless it's already given, then connects.
func requestAndAttach(ctx context.Context, c *client.Client, req api.CreateSessionRequest, tty bool) error {
	sess, err := c.CreateSession(ctx, req)
	if err != nil {
		return err
	}
	what := strings.Join(sess.Command, " ")
	if sess.Action != "" {
		what = "action " + sess.Action
	}
	fmt.Fprintf(os.Stderr, "🗝️  Session %s requested: %s/%s → %s\n", sess.ID, sess.Namespace, sess.Pod, what)
	if sess.Status == api.StatusPending {
		fmt.Fprintf(os.Stderr, "   Waiting for a teammate to approve. They can run:\n\n     ostiara approve %s\n\n", sess.ID)
		if sess, err = waitForDecision(ctx, c, sess.ID); err != nil {
			return err
		}
	}
	switch sess.Status {
	case api.StatusApproved:
		fmt.Fprintf(os.Stderr, "✅ Approved by %s. Connecting...\n", sess.Approver)
	case api.StatusDenied:
		return fmt.Errorf("session %s was denied by %s", sess.ID, sess.Approver)
	default:
		return fmt.Errorf("session %s is %s", sess.ID, sess.Status)
	}

	conn, err := c.Attach(ctx, sess.ID)
	if err != nil {
		return err
	}
	defer conn.Close()

	code, err := runTerminal(ctx, conn, tty)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

// waitForDecision polls every 2s until the session is no longer pending.
func waitForDecision(ctx context.Context, c *client.Client, id string) (api.Session, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return api.Session{}, errors.New("stopped waiting for approval (the request will expire)")
		case <-ticker.C:
		}

		sess, err := c.GetSession(ctx, id)
		if err != nil {
			return api.Session{}, err
		}
		if sess.Status != api.StatusPending {
			return sess, nil
		}
	}
}
