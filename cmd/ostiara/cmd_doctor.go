package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ostiara/ostiara/internal/doctor"
	"github.com/ostiara/ostiara/internal/kube"
)

var errDoctorWarnings = errors.New("doctor found ways around ostiara")

// runDoctor reports RBAC and setup that let people get around ostiara.
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	all := fs.Bool("all", false, "also list Kubernetes and platform system components")
	strict := fs.Bool("strict", false, "exit 1 when anything needs attention, for CI")
	brokerUser := fs.String("broker-user", "system:serviceaccount:ostiara-system:ostiara-broker", "the broker's Kubernetes username")
	if err := fs.Parse(args); err != nil {
		return err
	}
	clientset, _, err := kube.NewClient(*kubeconfig)
	if err != nil {
		return err
	}
	snap, err := doctor.Load(context.Background(), clientset, *brokerUser)
	if err != nil {
		return err
	}
	report := doctor.Analyze(snap)
	printReport(os.Stdout, report, *all)
	if *strict && report.Warnings() > 0 {
		return errDoctorWarnings
	}
	return nil
}

var sections = []struct {
	cap   doctor.Capability
	title string
	why   string
}{
	{doctor.PodAccess, "Direct pod access (exec, attach, port-forward, debug)", "bypasses ostiara unless the admission policy blocks it"},
	{doctor.Secrets, "Read Secrets directly", "reaches the same passwords and keys a shell would, with no shell"},
	{doctor.Workloads, "Create or change workloads", "a new or edited pod can mount Secrets or run any command"},
	{doctor.Escalation, "Grant themselves more", "can turn into any of the above"},
}

func printReport(w io.Writer, r doctor.Report, all bool) {
	fmt.Fprintln(w, "Enforcement")
	for _, c := range r.Enforcement {
		mark := "⚠️ "
		if c.OK {
			mark = "✅"
		}
		fmt.Fprintf(w, "  %s %s\n", mark, c.Text)
	}

	for _, sec := range sections {
		var shown []doctor.Grant
		hidden := 0
		for _, g := range r.Grants {
			if g.Capability != sec.cap {
				continue
			}
			if g.System && !all {
				hidden++
				continue
			}
			shown = append(shown, g)
		}
		fmt.Fprintf(w, "\n%s: %s\n", sec.title, sec.why)
		if len(shown) == 0 {
			fmt.Fprintln(w, "  ✅ nobody besides system components")
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, g := range shown {
			mark := "⚠️ "
			switch {
			case g.Blocked == "yes":
				mark = "🛡️ "
			case g.System:
				mark = "· "
			}
			what := strings.Join(g.What, ", ")
			if g.Limited {
				what += " (named resources only)"
			}
			note := ""
			if g.Blocked != "" {
				note = "blocked by ostiara " + strings.TrimPrefix(g.Blocked, "yes")
				note = strings.TrimSpace(note)
			}
			fmt.Fprintf(tw, "  %s %s\t%s\t%s\t%s\t%s\n", mark, g.Subject, what, g.Scope, g.Via, note)
		}
		tw.Flush()
		if hidden > 0 {
			fmt.Fprintf(w, "  (+%d system components; -all lists them)\n", hidden)
		}
	}

	fmt.Fprintln(w, "\nNot visible to doctor")
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  - %s\n", n)
	}
	if n := r.Warnings(); n > 0 {
		fmt.Fprintf(w, "\n%d finding(s) need attention.\n", n)
	} else {
		fmt.Fprintln(w, "\nNothing gets around ostiara that doctor can see.")
	}
}
