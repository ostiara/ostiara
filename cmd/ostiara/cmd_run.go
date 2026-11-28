package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"

	"github.com/ostiara/ostiara/internal/api"
)

// runAction runs a predefined action from the broker's catalog: no shell, and no approval
// wait when the catalog says auto.
func runAction(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	namespace := fs.String("n", "default", "namespace of the pod")
	container := fs.String("c", "", "container name (default: the pod's default container)")
	reason := fs.String("reason", "", "why you need it (shown to the approver)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: ostiara run [-n namespace] [-c container] POD ACTION   (ostiara actions lists them)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := newClient()
	if err != nil {
		return err
	}
	return requestAndAttach(ctx, c, api.CreateSessionRequest{
		Namespace: *namespace,
		Pod:       fs.Arg(0),
		Container: *container,
		Action:    fs.Arg(1),
		Reason:    *reason,
	}, false)
}

// listActions shows the predefined actions offered in a namespace.
func listActions(args []string) error {
	fs := flag.NewFlagSet("actions", flag.ContinueOnError)
	namespace := fs.String("n", "default", "namespace to list actions for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	list, err := c.Actions(context.Background(), *namespace)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Printf("No actions are offered in %s.\n", *namespace)
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACTION\tAPPROVAL\tDESCRIPTION")
	for _, a := range list {
		approval := "teammate"
		if a.Approval == "auto" {
			approval = "none (logged)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", a.Name, approval, a.Description)
	}
	return tw.Flush()
}
