package actions

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "actions.yaml")
	os.WriteFile(p, []byte(body), 0o600)
	return p
}

func TestLoad(t *testing.T) {
	if c, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err != nil || len(c.Actions) != len(Defaults.Actions) {
		t.Fatalf("missing file: got (%v, %v), want the defaults", c, err)
	}
	c, err := Load(write(t, `
actions:
  - name: threads
    command: ["jstack", "1"]
    namespaces: [payments]
`))
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := c.Find("threads", "payments"); !ok || a.Approval != Required {
		t.Fatalf("Find in payments = %+v %v, want it, with approval defaulting to required", a, ok)
	}
	if _, ok := c.Find("threads", "orders"); ok {
		t.Fatal("Find in orders: want nothing, the action is limited to payments")
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]string{
		"bad name":      `actions: [{name: "Bad Name", command: [ps]}]`,
		"duplicate":     `actions: [{name: ps, command: [ps]}, {name: ps, command: [ps]}]`,
		"no command":    `actions: [{name: ps, command: []}]`,
		"bad approval":  `actions: [{name: ps, command: [ps], approval: sometimes}]`,
		"bad redact":    `actions: [{name: ps, command: [ps], redact: everything}]`,
		"unknown field": `actions: [{name: ps, command: [ps], shell: true}]`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestRedactEnvLine(t *testing.T) {
	cases := map[string]string{
		"DB_PASSWORD=hunter2":                      "DB_PASSWORD=•••••• (hidden by ostiara)",
		"STRIPE_API_KEY=sk_live_123":               "STRIPE_API_KEY=•••••• (hidden by ostiara)",
		"aws_secret_access_key=abc":                "aws_secret_access_key=•••••• (hidden by ostiara)",
		"DATABASE_URL=postgres://app:hunter2@db/x": "DATABASE_URL=postgres://app:••••••@db/x",
		"HOME=/root":                               "HOME=/root",
		"EMPTY_TOKEN=":                             "EMPTY_TOKEN=",
		"not an assignment":                        "not an assignment",
	}
	for in, want := range cases {
		if got := string(RedactEnvLine([]byte(in))); got != want {
			t.Errorf("RedactEnvLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLineRedactorAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	r := EnvRedactor(&out)
	// A secret split across writes must still be hidden, never passed on half-done.
	r.Write([]byte("PATH=/bin\nAPI_TO"))
	if strings.Contains(out.String(), "API_TO") {
		t.Fatalf("a partial line was passed on: %q", out.String())
	}
	r.Write([]byte("KEN=abc\nLAST_SECRET=x"))
	r.Flush()
	want := "PATH=/bin\nAPI_TOKEN=•••••• (hidden by ostiara)\nLAST_SECRET=•••••• (hidden by ostiara)"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}
