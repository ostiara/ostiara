package audit

import (
	"bytes"
	"strings"
	"testing"
)

func sealedLog(t *testing.T, key []byte, n int) []string {
	t.Helper()
	var buf bytes.Buffer
	l := New(&buf).WithKey(key)
	for i := range n {
		if err := l.Record(Event{Kind: Requested, Session: "s" + string(rune('a'+i)), Actor: "alice"}); err != nil {
			t.Fatal(err)
		}
	}
	return strings.Split(strings.TrimSpace(buf.String()), "\n")
}

func verify(t *testing.T, lines []string, key []byte) []ChainReport {
	t.Helper()
	r, err := Verify(strings.NewReader(strings.Join(lines, "\n")), key)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func problems(r []ChainReport) string {
	var all []string
	for _, c := range r {
		all = append(all, c.Problems...)
	}
	return strings.Join(all, "\n")
}

func TestIntactChain(t *testing.T) {
	lines := sealedLog(t, nil, 3)
	lines = append(lines[:1], append([]string{`time=... level=INFO msg="operational line"`}, lines[1:]...)...)
	r := verify(t, lines, nil)
	if len(r) != 1 || r[0].First != 1 || r[0].Last != 3 || len(r[0].Problems) != 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestTamperingIsCaught(t *testing.T) {
	cases := map[string]func([]string) []string{
		"edited": func(l []string) []string {
			l[1] = strings.Replace(l[1], `"actor":"alice"`, `"actor":"bob"`, 1)
			return l
		},
		"removed":   func(l []string) []string { return append(l[:1], l[2:]...) },
		"reordered": func(l []string) []string { l[1], l[2] = l[2], l[1]; return l },
		"head cut":  func(l []string) []string { return l[1:] },
		"unsealed":  func(l []string) []string { return append(l, `{"stream":"ostiara.audit","event":"session.approved"}`) },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			if p := problems(verify(t, tamper(sealedLog(t, nil, 4)), nil)); p == "" {
				t.Fatal("tampering went unnoticed")
			}
		})
	}
}

func TestKeyedChain(t *testing.T) {
	lines := sealedLog(t, []byte("k1"), 2)
	if p := problems(verify(t, lines, []byte("k1"))); p != "" {
		t.Fatalf("right key: %s", p)
	}
	if p := problems(verify(t, lines, []byte("other"))); p == "" {
		t.Fatal("wrong key: want every line flagged")
	}
	if p := problems(verify(t, lines, nil)); p == "" {
		t.Fatal("no key on a signed log: want it flagged")
	}
}

func TestNewChainPerRun(t *testing.T) {
	a, b := sealedLog(t, nil, 2), sealedLog(t, nil, 2)
	r := verify(t, append(a, b...), nil)
	if len(r) != 2 || problems(r) != "" {
		t.Fatalf("two broker runs: want two intact chains, got %+v", r)
	}
}
