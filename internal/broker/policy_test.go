package broker

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/audit"
)

func policyServer(t *testing.T) (http.Handler, *recordingNotifier, *bytes.Buffer) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(file, []byte(`
rules:
  - namespaces: ["prod"]
    approvals: 2
    approverGroups: ["sre"]
    requireTicket: true
    maxWindow: 10m
  - namespaces: ["oncall"]
    selfApproval: true
`), 0o600)
	cs := fake.NewClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "oncall"}},
	)
	var auditBuf bytes.Buffer
	notes := &recordingNotifier{}
	srv, err := NewServer(NewStore(), groupAuth{}, cs, nil, slog.New(slog.DiscardHandler), audit.New(&auditBuf)).WithNotifier(notes).WithPolicy(file)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), notes, &auditBuf
}

func call(h http.Handler, method, path, user, body string) (int, api.Session, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(api.UserHeader, user)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var s api.Session
	json.Unmarshal(w.Body.Bytes(), &s)
	return w.Code, s, w.Body.String()
}

func TestProdNeedsTicketAndTwoSREs(t *testing.T) {
	h, notes, auditBuf := policyServer(t)
	if code, _, body := call(h, "POST", "/v1/sessions", "alice:dev", `{"namespace":"prod","pod":"p","reason":"just looking"}`); code != http.StatusBadRequest {
		t.Fatalf("no ticket: %d %s", code, body)
	}
	if code, _, body := call(h, "POST", "/v1/sessions", "alice:dev", `{"kind":"port-forward","namespace":"prod","pod":"p","port":5432,"windowSeconds":1800,"reason":"INC-1"}`); code != http.StatusBadRequest {
		t.Fatalf("30m port-forward over the 10m cap: %d %s", code, body)
	}
	_, s, _ := call(h, "POST", "/v1/sessions", "alice:dev", `{"namespace":"prod","pod":"p","reason":"INC-42 checkout down"}`)
	if s.RequiredApprovals != 2 {
		t.Fatalf("required approvals = %d", s.RequiredApprovals)
	}
	approve := "/v1/sessions/" + s.ID + "/approve"
	if code, _, _ := call(h, "POST", approve, "carol:dev", ""); code != http.StatusForbidden {
		t.Fatalf("non-SRE approver: %d", code)
	}
	if _, got, _ := call(h, "POST", approve, "sam:sre", ""); got.Status != api.StatusPending {
		t.Fatalf("after one SRE: %s", got.Status)
	}
	if code, _, _ := call(h, "POST", approve, "sam:sre", ""); code != http.StatusConflict {
		t.Fatalf("same SRE twice: %d", code)
	}
	if _, got, _ := call(h, "POST", approve, "tom:sre", ""); got.Status != api.StatusApproved {
		t.Fatalf("after two SREs: %s", got.Status)
	}

	var kinds []string
	for _, n := range notes.events {
		kinds = append(kinds, n.Kind)
	}
	if strings.Join(kinds, ",") != "requested,approval_added,approved" {
		t.Fatalf("notifications = %v", kinds)
	}
	if !strings.Contains(auditBuf.String(), `"event":"session.approval_added"`) ||
		!strings.Contains(auditBuf.String(), `"actor":"carol","error":"you can't approve sessions here`) {
		t.Fatalf("audit should show the partial approval and carol's refusal:\n%s", auditBuf)
	}
}

func TestSoloOnCallSelfApproval(t *testing.T) {
	h, notes, _ := policyServer(t)
	_, s, _ := call(h, "POST", "/v1/sessions", "alice:dev", `{"namespace":"oncall","pod":"p","reason":"INC-7 paged at 3am"}`)
	code, got, body := call(h, "POST", "/v1/sessions/"+s.ID+"/approve", "alice:dev", "")
	if code != http.StatusOK || got.Status != api.StatusApproved || !got.SelfApproved {
		t.Fatalf("self-approval in oncall: %d %s", code, body)
	}
	if last := notes.events[len(notes.events)-1]; last.Kind != "self_approved" {
		t.Fatalf("want a loud self_approved notification, got %s", last.Kind)
	}
}
