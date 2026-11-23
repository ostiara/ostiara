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
	sessions, err := newClient().ListSessions(context.Background(), status)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		fmt.Println("No sessions waiting for approval.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tREQUESTER\tPOD\tCOMMAND\tREASON\tSTATUS\tAGE")
	for _, s := range sessions {
		reason := s.Reason
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s/%s\t%s\t%s\t%s\t%s\n",
			s.ID, s.Requester, s.Namespace, s.Pod, strings.Join(s.Command, " "),
			reason, s.Status, time.Since(s.CreatedAt).Round(time.Second))
	}
	return tw.Flush()
}

func runDecide(args []string, approve bool) error {
	if len(args) != 1 {
		return errors.New("usage: ostiara approve|deny SESSION_ID")
	}
	sess, err := newClient().Decide(context.Background(), args[0], approve)
	if err != nil {
		return err
	}
	if approve {
		fmt.Printf("✅ Approved session %s: %s can now open %s/%s (within 5 minutes, once).\n",
			sess.ID, sess.Requester, sess.Namespace, sess.Pod)
	} else {
		fmt.Printf("⛔ Denied session %s for %s.\n", sess.ID, sess.Requester)
	}
	return nil
}
