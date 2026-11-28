package broker

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/ostiara/ostiara/internal/actions"
	"github.com/ostiara/ostiara/internal/api"
)

// actionServer has the default catalog; only users in group "devs" may get pods in demo.
func actionServer(t *testing.T) (http.Handler, *recordingNotifier) {
	t.Helper()
	cs := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "demo"}})
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		ra := sar.Spec.ResourceAttributes
		for _, g := range sar.Spec.Groups {
			if g == "devs" && ra.Namespace == "demo" && ra.Resource == "pods" && ra.Verb == "get" {
				sar.Status.Allowed = true
			}
		}
		return true, sar, nil
	})
	rec := &recordingNotifier{}
	srv := NewServer(NewStore(), groupAuth{}, cs, nil, slog.New(slog.DiscardHandler), nil).WithNotifier(rec)
	return srv.Handler(), rec
}

func post(h http.Handler, user, body string) (int, api.Session, string) {
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(body))
	req.Header.Set(api.UserHeader, user)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var s api.Session
	json.Unmarshal(w.Body.Bytes(), &s)
	return w.Code, s, w.Body.String()
}

func TestAutoActionRunsWithoutATeammate(t *testing.T) {
	h, notes := actionServer(t)
	code, s, body := post(h, "alice:devs", `{"namespace":"demo","pod":"p","action":"ps"}`)
	if code != http.StatusCreated || s.Status != api.StatusApproved || s.Approver != AutoApprover {
		t.Fatalf("auto action: %d %s", code, body)
	}
	if strings.Join(s.Command, " ") != "ps" || s.TTY {
		t.Fatalf("command = %v tty=%v, want the catalog's ps without a tty", s.Command, s.TTY)
	}
	if len(notes.events) != 1 || notes.events[0].Kind != "approved" {
		t.Fatalf("notifications = %+v, want one 'approved'", notes.events)
	}
}

func TestAutoActionNeedsAccessToTheNamespace(t *testing.T) {
	h, _ := actionServer(t)
	if code, _, body := post(h, "mallory:outsiders", `{"namespace":"demo","pod":"p","action":"ps"}`); code != http.StatusForbidden {
		t.Fatalf("someone who can't read pods there: %d %s", code, body)
	}
}

func TestRequiredActionWaits(t *testing.T) {
	h, _ := actionServer(t)
	code, s, body := post(h, "mallory:outsiders", `{"namespace":"demo","pod":"p","action":"env"}`)
	if code != http.StatusCreated || s.Status != api.StatusPending || s.Redact != "" {
		t.Fatalf("required action: %d %s", code, body)
	}
	if strings.Contains(body, "redact") {
		t.Fatalf("the redaction mode is internal and shouldn't be in the response: %s", body)
	}
}

func TestBadActionRequests(t *testing.T) {
	h, _ := actionServer(t)
	for name, body := range map[string]string{
		"unknown action":   `{"namespace":"demo","pod":"p","action":"rm-rf"}`,
		"action + command": `{"namespace":"demo","pod":"p","action":"ps","command":["sh"]}`,
		"action + tty":     `{"namespace":"demo","pod":"p","action":"ps","tty":true}`,
		"action + forward": `{"kind":"port-forward","namespace":"demo","pod":"p","action":"ps","port":80}`,
	} {
		if code, _, resp := post(h, "alice:devs", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, code, resp)
		}
	}
}

func TestListActions(t *testing.T) {
	h, _ := actionServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/actions?namespace=demo", nil)
	req.Header.Set(api.UserHeader, "alice:devs")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var list []actions.Action
	json.Unmarshal(w.Body.Bytes(), &list)
	if w.Code != http.StatusOK || len(list) != len(actions.Defaults.Actions) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
}
