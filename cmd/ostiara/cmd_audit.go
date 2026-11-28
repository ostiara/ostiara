package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/ostiara/ostiara/internal/audit"
)

// errFindings makes `ostiara audit check` exit non-zero, so cron jobs and CI can alert on it.
var errFindings = errors.New("found pod access that needs review")

// runAudit dispatches `ostiara audit <subcommand>`.
func runAudit(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: ostiara audit check -k8s FILE -ostiara FILE [-window 10s] [-broker-user NAME]")
	}
	return runAuditCheck(args[1:], os.Stdout)
}

func runAuditCheck(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit check", flag.ContinueOnError)
	k8sPath := fs.String("k8s", "", "Kubernetes API audit log (JSON lines)")
	ostiaraPath := fs.String("ostiara", "", "ostiara broker audit log (JSON lines, e.g. kubectl logs of the broker)")
	window := fs.Duration("window", 10*time.Second, "max gap between an approved attach and its exec")
	brokerUser := fs.String("broker-user", "system:serviceaccount:ostiara-system:ostiara-broker", "the broker's Kubernetes username")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *k8sPath == "" || *ostiaraPath == "" {
		return errors.New("both -k8s and -ostiara are required")
	}

	k8sLog, err := os.Open(*k8sPath)
	if err != nil {
		return err
	}
	defer k8sLog.Close()
	ostiaraLog, err := os.Open(*ostiaraPath)
	if err != nil {
		return err
	}
	defer ostiaraLog.Close()

	findings, err := audit.Check(k8sLog, ostiaraLog, audit.CheckOptions{BrokerUser: *brokerUser, Window: *window})
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		fmt.Fprintln(out, "✅ Every pod exec, attach and port-forward matches an ostiara approval.")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FINDING\tTIME\tUSER\tPOD\tACCESS\tAUDIT ID")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s\t%s\n",
			f.Kind, f.Time.Format(time.RFC3339), f.User, f.Namespace, f.Pod, f.Subresource, f.AuditID)
	}
	tw.Flush()
	return errFindings
}
