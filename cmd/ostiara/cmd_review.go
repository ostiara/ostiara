package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "show every session, not only pending ones")
	if err := fs.Parse(args); err != nil {
		return err
	}

	status := api.StatusPending
	if *all {
		status = ""
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	sessions, err := c.ListSessions(context.Background(), status)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		fmt.Println("No sessions waiting for approval.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tREQUESTER\tPOD\tACCESS\tREASON\tSTATUS\tAGE")
	for _, s := range sessions {
		reason := s.Reason
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s/%s\t%s\t%s\t%s\t%s\n",
			s.ID, s.Requester, s.Namespace, s.Pod, describeAccess(s),
			reason, statusText(s), time.Since(s.CreatedAt).Round(time.Second))
	}
	return tw.Flush()
}

func runDecide(args []string, approve bool) error {
	if len(args) != 1 {
		return errors.New("usage: ostiara approve|deny SESSION_ID")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	sess, err := c.Decide(context.Background(), args[0], approve)
	if err != nil {
		return err
	}
	switch {
	case approve && sess.Status == api.StatusPending:
		fmt.Printf("👍 Your approval is in (%d of %d). Session %s needs %d more teammate(s).\n",
			len(sess.Approvers), sess.RequiredApprovals, sess.ID, sess.RequiredApprovals-len(sess.Approvers))
	case approve && sess.SelfApproved:
		fmt.Printf("🚨 You approved your own session %s (solo on-call). It's flagged for review.\n", sess.ID)
	case approve && sess.Kind == api.KindPortForward:
		fmt.Printf("✅ Approved session %s: %s can now forward to %s/%s:%d until %s.\n",
			sess.ID, sess.Requester, sess.Namespace, sess.Pod, sess.Port, sess.ExpiresAt.Local().Format("15:04"))
	case approve:
		fmt.Printf("✅ Approved session %s: %s can now open %s/%s (within 5 minutes, once).\n",
			sess.ID, sess.Requester, sess.Namespace, sess.Pod)
	default:
		fmt.Printf("⛔ Denied session %s for %s.\n", sess.ID, sess.Requester)
	}
	return nil
}

// describeAccess says what a reviewer is approving: the command, or the port and for how long.
func describeAccess(s api.Session) string {
	if s.Kind == api.KindPortForward {
		return fmt.Sprintf("port-forward :%d for %s", s.Port, time.Duration(s.WindowSeconds)*time.Second)
	}
	if s.Action != "" {
		return "action: " + s.Action
	}
	return "exec: " + strings.Join(s.Command, " ")
}

// statusText adds progress for sessions that need several approvals, and flags self-approval.
func statusText(s api.Session) string {
	switch {
	case s.Status == api.StatusPending && s.RequiredApprovals > 1:
		return fmt.Sprintf("pending %d/%d", len(s.Approvers), s.RequiredApprovals)
	case s.SelfApproved:
		return string(s.Status) + " (self-approved)"
	}
	return string(s.Status)
}
