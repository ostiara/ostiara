// Package policy holds the approval rules: per namespace, who may approve, how many approvals
// a session needs, whether a ticket is required, and when the requester may approve alone.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// DefaultTicketPattern accepts references like INC-123, JIRA-4567 or a URL.
const DefaultTicketPattern = `[A-Z][A-Z0-9]+-[0-9]+|https?://\S+`

// Rule is what applies to the namespaces it names.
type Rule struct {
	Namespaces []string `json:"namespaces,omitempty"` // globs, e.g. prod-*; empty only in default

	Approvals      int      `json:"approvals,omitempty"`     // distinct approvers needed (default 1)
	ApproverUsers  []string `json:"approverUsers,omitempty"` // who may approve; both empty means anyone but the requester
	ApproverGroups []string `json:"approverGroups,omitempty"`

	// ApproverExtra requires these values in the approver's identity, as the API server reports
	// them (e.g. an "amr" claim mapped to mfa by your OIDC setup). "*" means any value.
	ApproverExtra map[string][]string `json:"approverExtra,omitempty"`

	RequireTicket bool   `json:"requireTicket,omitempty"` // the reason must contain a ticket reference
	TicketPattern string `json:"ticketPattern,omitempty"` // default DefaultTicketPattern

	// SelfApproval lets the requester approve alone, for solo on-call. It needs a ticket, is
	// announced loudly, and shows up in `ostiara audit check` for review afterwards.
	SelfApproval bool `json:"selfApproval,omitempty"`

	MaxWindow string `json:"maxWindow,omitempty"` // port-forward cap here, e.g. 30m (default 1h)

	ticket *regexp.Regexp
	window time.Duration
}

// Policy is the default rule plus namespace rules; the first matching rule wins.
type Policy struct {
	Default Rule   `json:"default"`
	Rules   []Rule `json:"rules,omitempty"`
}

// Identity is the parts of a caller the rules look at.
type Identity struct {
	Name   string
	Groups []string
	Extra  map[string][]string
}

// Load reads a YAML or JSON policy; a missing file means one approval from anyone else.
func Load(file string) (Policy, error) {
	var p Policy
	if file != "" {
		data, err := os.ReadFile(file)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return Policy{}, err
		default:
			if err := yaml.UnmarshalStrict(data, &p); err != nil {
				return Policy{}, fmt.Errorf("approval policy %s: %w", file, err)
			}
		}
	}
	return p, p.prepare()
}

func (p *Policy) prepare() error {
	if len(p.Default.Namespaces) > 0 {
		return errors.New("default rule can't name namespaces")
	}
	if err := p.Default.prepare("default"); err != nil {
		return err
	}
	for i := range p.Rules {
		if len(p.Rules[i].Namespaces) == 0 {
			return fmt.Errorf("rule %d names no namespaces", i)
		}
		for _, g := range p.Rules[i].Namespaces {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("rule %d: bad namespace pattern %q", i, g)
			}
		}
		if err := p.Rules[i].prepare(fmt.Sprintf("rule %d", i)); err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) prepare(name string) error {
	if r.Approvals == 0 {
		r.Approvals = 1
	}
	if r.Approvals < 1 || r.Approvals > 5 {
		return fmt.Errorf("%s: approvals must be 1 to 5", name)
	}
	if r.SelfApproval && r.Approvals != 1 {
		return fmt.Errorf("%s: selfApproval only makes sense with one approval", name)
	}
	pattern := r.TicketPattern
	if pattern == "" {
		pattern = DefaultTicketPattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%s: ticketPattern: %w", name, err)
	}
	r.ticket = re
	r.window = time.Hour
	if r.MaxWindow != "" {
		d, err := time.ParseDuration(r.MaxWindow)
		if err != nil || d < time.Minute || d > time.Hour {
			return fmt.Errorf("%s: maxWindow must be between 1m and 1h", name)
		}
		r.window = d
	}
	return nil
}

// For returns the rule for a namespace.
func (p Policy) For(namespace string) Rule {
	for _, r := range p.Rules {
		for _, g := range r.Namespaces {
			if ok, _ := path.Match(g, namespace); ok {
				return r
			}
		}
	}
	return p.Default
}

// MaxWindowDuration is the longest port-forward this rule allows.
func (r Rule) MaxWindowDuration() time.Duration { return r.window }

// CheckRequest enforces what a request must carry, such as a ticket reference.
func (r Rule) CheckRequest(reason string) error {
	if (r.RequireTicket || r.SelfApproval) && !r.ticket.MatchString(reason) {
		return fmt.Errorf("this namespace needs a ticket or incident reference in -reason (matching %s)", r.ticket)
	}
	return nil
}

// CheckApprover says whether id may approve or deny a session that requester asked for.
func (r Rule) CheckApprover(id Identity, requester string) error {
	if id.Name == requester && !r.SelfApproval {
		return ErrSelf
	}
	if len(r.ApproverUsers) > 0 || len(r.ApproverGroups) > 0 {
		inGroup := slices.ContainsFunc(id.Groups, func(g string) bool { return slices.Contains(r.ApproverGroups, g) })
		if !slices.Contains(r.ApproverUsers, id.Name) && !inGroup {
			return fmt.Errorf("%w: approvers here are users [%s] and groups [%s]", ErrNotApprover,
				strings.Join(r.ApproverUsers, ", "), strings.Join(r.ApproverGroups, ", "))
		}
	}
	for key, want := range r.ApproverExtra {
		have := id.Extra[key]
		ok := slices.ContainsFunc(have, func(v string) bool { return slices.Contains(want, v) || (slices.Contains(want, "*") && v != "") })
		if !ok {
			return fmt.Errorf("%w: your login must carry %s=%s (e.g. a recent MFA sign-in)", ErrNotApprover, key, strings.Join(want, "|"))
		}
	}
	return nil
}

var (
	ErrSelf        = errors.New("you can't approve or deny your own session: ask a teammate")
	ErrNotApprover = errors.New("you can't approve sessions here")
)
