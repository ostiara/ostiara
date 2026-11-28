package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func load(t *testing.T, body string) (Policy, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(p, []byte(body), 0o600)
	return Load(p)
}

const sample = `
default: {}
rules:
  - namespaces: ["prod", "prod-*"]
    approvals: 2
    approverGroups: ["sre"]
    requireTicket: true
    maxWindow: 30m
    approverExtra:
      example.com/amr: ["mfa"]
  - namespaces: ["oncall-*"]
    selfApproval: true
`

func TestFor(t *testing.T) {
	p, err := load(t, sample)
	if err != nil {
		t.Fatal(err)
	}
	if r := p.For("prod-payments"); r.Approvals != 2 || r.MaxWindowDuration() != 30*time.Minute {
		t.Fatalf("prod-payments got %+v", r)
	}
	if r := p.For("staging"); r.Approvals != 1 || r.MaxWindowDuration() != time.Hour || r.SelfApproval {
		t.Fatalf("staging should get the default: %+v", r)
	}
	if def, _ := Load(filepath.Join(t.TempDir(), "missing")); def.For("x").Approvals != 1 {
		t.Fatal("missing file: want one approval")
	}
}

func TestInvalidPolicies(t *testing.T) {
	for name, body := range map[string]string{
		"default with namespaces": `default: {namespaces: [x]}`,
		"rule without namespaces": `rules: [{approvals: 2}]`,
		"bad glob":                `rules: [{namespaces: ["[x"]}]`,
		"too many approvals":      `default: {approvals: 6}`,
		"self with two":           `default: {approvals: 2, selfApproval: true}`,
		"bad ticket regex":        `default: {ticketPattern: "("}`,
		"window too long":         `default: {maxWindow: 3h}`,
		"unknown field":           `default: {approvers: [bob]}`,
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestCheckRequest(t *testing.T) {
	p, _ := load(t, sample)
	prod := p.For("prod")
	for reason, ok := range map[string]bool{"INC-1234 checkout errors": true, "see https://status.example/x": true, "just looking": false, "": false} {
		if err := prod.CheckRequest(reason); (err == nil) != ok {
			t.Errorf("reason %q: err=%v, want ok=%v", reason, err, ok)
		}
	}
	if err := p.For("oncall-db").CheckRequest("no ticket"); err == nil {
		t.Error("self-approval namespaces need a ticket too")
	}
	if err := p.For("staging").CheckRequest(""); err != nil {
		t.Errorf("default needs no ticket: %v", err)
	}
}

func TestCheckApprover(t *testing.T) {
	p, _ := load(t, sample)
	prod := p.For("prod")
	mfa := map[string][]string{"example.com/amr": {"pwd", "mfa"}}
	cases := []struct {
		name string
		id   Identity
		want error
	}{
		{"sre with mfa", Identity{Name: "bob", Groups: []string{"sre"}, Extra: mfa}, nil},
		{"sre without mfa", Identity{Name: "bob", Groups: []string{"sre"}}, ErrNotApprover},
		{"not in sre", Identity{Name: "carol", Groups: []string{"dev"}, Extra: mfa}, ErrNotApprover},
		{"the requester", Identity{Name: "alice", Groups: []string{"sre"}, Extra: mfa}, ErrSelf},
	}
	for _, tc := range cases {
		if err := prod.CheckApprover(tc.id, "alice"); !errors.Is(err, tc.want) && !(err == nil && tc.want == nil) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if err := p.For("oncall-db").CheckApprover(Identity{Name: "alice"}, "alice"); err != nil {
		t.Errorf("solo on-call self-approval: %v", err)
	}
	if err := p.For("staging").CheckApprover(Identity{Name: "alice"}, "alice"); !errors.Is(err, ErrSelf) {
		t.Errorf("default self-approval: %v", err)
	}
	star, _ := load(t, `default: {approverExtra: {k: ["*"]}}`)
	if star.For("x").CheckApprover(Identity{Name: "b", Extra: map[string][]string{"k": {"anything"}}}, "a") != nil ||
		star.For("x").CheckApprover(Identity{Name: "b"}, "a") == nil {
		t.Error(`"*" should mean: the key is present with any value`)
	}
}
