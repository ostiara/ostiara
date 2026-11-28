package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ostiara/ostiara/internal/audit"
	"github.com/ostiara/ostiara/internal/notify"
)

// errFindings makes `ostiara audit check` exit non-zero, so cron jobs and CI can alert on it.
var errFindings = errors.New("found pod access that needs review")

// runAudit dispatches `ostiara audit <subcommand>`.
func runAudit(args []string) error {
	switch {
	case len(args) > 0 && args[0] == "check":
		return runAuditCheck(args[1:], os.Stdout)
	case len(args) > 0 && args[0] == "verify":
		return runAuditVerify(args[1:], os.Stdout)
	}
	return errors.New("usage: ostiara audit check -k8s FILE -ostiara FILE | ostiara audit verify FILE")
}

var errTampered = errors.New("the audit log's chain is broken")

// runAuditVerify checks the hash chain of an ostiara audit log. Set OSTIARA_AUDIT_KEY if the
// broker signs its log.
func runAuditVerify(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: ostiara audit verify FILE   (OSTIARA_AUDIT_KEY if the broker signs its log)")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	chains, err := audit.Verify(f, []byte(os.Getenv("OSTIARA_AUDIT_KEY")))
	if err != nil {
		return err
	}
	if len(chains) == 0 {
		return errors.New("no ostiara audit events found")
	}
	broken := false
	for _, c := range chains {
		if len(c.Problems) == 0 {
			fmt.Fprintf(out, "✅ chain %s: seq %d to %d, intact\n", c.Chain, c.First, c.Last)
			continue
		}
		broken = true
		fmt.Fprintf(out, "⚠️  chain %s: seq %d to %d, %d problem(s)\n", c.Chain, c.First, c.Last, len(c.Problems))
		for _, p := range c.Problems {
			fmt.Fprintf(out, "     %s\n", p)
		}
	}
	fmt.Fprintln(out, "Each chain is one broker run. A cut-off end can't be seen from the file alone: compare the last seq with your shipped copy.")
	if broken {
		return errTampered
	}
	return nil
}

func runAuditCheck(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit check", flag.ContinueOnError)
	k8sPath := fs.String("k8s", "", "Kubernetes API audit log (JSON lines)")
	ostiaraPath := fs.String("ostiara", "", "ostiara broker audit log (JSON lines, e.g. kubectl logs of the broker)")
	window := fs.Duration("window", 10*time.Second, "max gap between an approved attach and its exec")
	notifyChat := fs.Bool("notify", false, "also post a summary of the findings to Slack/Teams (OSTIARA_SLACK_WEBHOOK_URL, OSTIARA_TEAMS_WEBHOOK_URL)")
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
	if *notifyChat && len(findings) > 0 {
		if err := postFindings(findings); err != nil {
			return err
		}
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

// postFindings sends one summary message; details stay in the report, not in chat.
func postFindings(findings []audit.Finding) error {
	d, err := newNotifier(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})), "full")
	if err != nil {
		return err
	}
	if d == nil {
		return errors.New("-notify needs OSTIARA_SLACK_WEBHOOK_URL or OSTIARA_TEAMS_WEBHOOK_URL")
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Kind]++
	}
	var parts []string
	for _, k := range []string{audit.UnapprovedBrokerExec, audit.DirectAccess, audit.SelfApproved} {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
		}
	}
	icon := "🔎"
	if counts[audit.UnapprovedBrokerExec] > 0 {
		icon = "🚨"
	}
	d.Notify(notify.Event{Kind: notify.Text, Text: fmt.Sprintf("%s ostiara audit check: %s. Run ostiara audit check for details.", icon, strings.Join(parts, ", "))})
	d.Close()
	return nil
}
