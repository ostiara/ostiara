package audit

import (
	"strings"
	"testing"
	"time"
)

const gkeArray = `[
 {"insertId":"g1","timestamp":"2026-11-28T12:00:00.050Z","protoPayload":{
   "@type":"type.googleapis.com/google.cloud.audit.AuditLog",
   "methodName":"io.k8s.core.v1.pods.exec.create",
   "resourceName":"core/v1/namespaces/demo/pods/p/exec",
   "authenticationInfo":{"principalEmail":"system:serviceaccount:ostiara-system:ostiara-broker"}}},
 {"insertId":"g2","timestamp":"2026-11-28T12:05:00Z","protoPayload":{
   "methodName":"io.k8s.core.v1.pods.portforward.create",
   "resourceName":"core/v1/namespaces/demo/pods/p/portforward",
   "authenticationInfo":{"principalEmail":"dev@example.com"}}},
 {"insertId":"g3","timestamp":"2026-11-28T12:06:00Z","protoPayload":{
   "methodName":"io.k8s.core.v1.pods.exec.create",
   "resourceName":"core/v1/namespaces/demo/pods/p/exec",
   "authenticationInfo":{"principalEmail":"mallory@example.com"},"status":{"code":7}}},
 {"insertId":"g4","timestamp":"2026-11-28T12:07:00Z","protoPayload":{
   "methodName":"io.k8s.core.v1.secrets.get","resourceName":"core/v1/namespaces/demo/secrets/db"}}
]`

func TestCheckGKE(t *testing.T) {
	findings, err := Check(strings.NewReader(gkeArray), strings.NewReader(attachLine("demo", "p", t0)), CheckOptions{BrokerUser: broker, Window: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Kind != DirectAccess || findings[0].User != "dev@example.com" || findings[0].Subresource != "portforward" {
		t.Fatalf("findings = %+v: want only dev's direct port-forward (the broker exec matches, mallory was refused)", findings)
	}
}

func TestCheckEKSCloudWatch(t *testing.T) {
	inner := k8sLine("e1", "arn:aws:iam::1:user/ops", "exec", "demo", "p", t0, 101)
	export := `{"events":[{"timestamp":1,"message":` + quote(inner) + `}]}`
	findings, err := Check(strings.NewReader(export), strings.NewReader(""), CheckOptions{BrokerUser: broker, Window: time.Second})
	if err != nil || len(findings) != 1 || findings[0].AuditID != "e1" || findings[0].Kind != DirectAccess {
		t.Fatalf("findings = %+v, %v", findings, err)
	}
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
