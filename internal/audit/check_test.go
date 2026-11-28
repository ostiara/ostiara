package audit

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const broker = "system:serviceaccount:ostiara-system:ostiara-broker"

var t0 = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

// k8sLine builds one Kubernetes audit event line.
func k8sLine(id, user, sub, ns, pod string, at time.Time, code int) string {
	return fmt.Sprintf(`{"kind":"Event","auditID":%q,"stage":"ResponseStarted","verb":"get","user":{"username":%q},`+
		`"objectRef":{"resource":"pods","subresource":%q,"namespace":%q,"name":%q},`+
		`"responseStatus":{"code":%d},"requestReceivedTimestamp":%q}`,
		id, user, sub, ns, pod, code, at.Format(time.RFC3339Nano))
}

func attachLine(ns, pod string, at time.Time) string {
	return fmt.Sprintf(`{"stream":"ostiara.audit","time":%q,"event":"session.attached","session":"s","actor":"alice","namespace":%q,"pod":%q}`,
		at.Format(time.RFC3339Nano), ns, pod)
}

func TestCheck(t *testing.T) {
	cases := []struct {
		name    string
		k8s     []string
		ostiara []string
		want    []string // finding kind + audit ID
	}{
		{
			name:    "approved exec",
			k8s:     []string{k8sLine("a1", broker, "exec", "demo", "p", t0.Add(50*time.Millisecond), 101)},
			ostiara: []string{attachLine("demo", "p", t0)},
		},
		{
			name: "broker exec with no approval",
			k8s:  []string{k8sLine("a1", broker, "exec", "demo", "p", t0, 101)},
			want: []string{"unapproved-broker-exec a1"},
		},
		{
			name:    "approval was for another pod",
			k8s:     []string{k8sLine("a1", broker, "exec", "demo", "other", t0, 101)},
			ostiara: []string{attachLine("demo", "p", t0)},
			want:    []string{"unapproved-broker-exec a1"},
		},
		{
			name:    "approval too long before the exec",
			k8s:     []string{k8sLine("a1", broker, "exec", "demo", "p", t0.Add(time.Minute), 101)},
			ostiara: []string{attachLine("demo", "p", t0)},
			want:    []string{"unapproved-broker-exec a1"},
		},
		{
			name: "one approval, two execs",
			k8s: []string{
				k8sLine("a1", broker, "exec", "demo", "p", t0, 101),
				k8sLine("a2", broker, "exec", "demo", "p", t0.Add(time.Second), 101),
			},
			ostiara: []string{attachLine("demo", "p", t0)},
			want:    []string{"unapproved-broker-exec a2"},
		},
		{
			name: "broker port-forward is never approved",
			k8s:  []string{k8sLine("a1", broker, "portforward", "demo", "p", t0, 101)},
			want: []string{"unapproved-broker-exec a1"},
		},
		{
			name: "someone else exec'd",
			k8s:  []string{k8sLine("a1", "kubernetes-admin", "exec", "demo", "p", t0, 101)},
			want: []string{"direct-access a1"},
		},
		{
			name: "refused by the API server",
			k8s:  []string{k8sLine("a1", "mallory", "exec", "demo", "p", t0, 403)},
		},
		{
			name: "same request at two stages",
			k8s: []string{
				k8sLine("a1", "kubernetes-admin", "exec", "demo", "p", t0, 101),
				k8sLine("a1", "kubernetes-admin", "exec", "demo", "p", t0, 101),
			},
			want: []string{"direct-access a1"},
		},
		{
			name: "noise is ignored",
			k8s: []string{
				`not json`,
				`{"auditID":"x","objectRef":{"resource":"secrets","name":"s"}}`,
				k8sLine("a2", "kubernetes-admin", "log", "demo", "p", t0, 200),
			},
			ostiara: []string{`time=... level=INFO msg="broker listening"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Check(strings.NewReader(strings.Join(tc.k8s, "\n")),
				strings.NewReader(strings.Join(tc.ostiara, "\n")),
				CheckOptions{BrokerUser: broker, Window: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range findings {
				got = append(got, f.Kind+" "+f.AuditID)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("findings = %v, want %v", got, tc.want)
			}
		})
	}
}
