package broker

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/audit"
)

func TestServerRecordsAuditEvents(t *testing.T) {
	var buf bytes.Buffer
	pods := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "demo"}})
	srv := NewServer(NewStore(), HeaderAuth{}, pods, nil, slog.New(slog.DiscardHandler), audit.New(&buf)).Handler()

	call := func(method, path, user, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set(api.UserHeader, user)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	rec := call(http.MethodPost, "/v1/sessions", "alice", `{"namespace":"demo","pod":"p","command":["sh"],"reason":"debug"}`)
	var sess api.Session
	json.Unmarshal(rec.Body.Bytes(), &sess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := call(http.MethodPost, "/v1/sessions/"+sess.ID+"/approve", "alice", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("self-approve: %d", rec.Code)
	}
	if rec := call(http.MethodPost, "/v1/sessions/"+sess.ID+"/approve", "bob", ""); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d", rec.Code)
	}

	var kinds, actors []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		kinds = append(kinds, e.Kind)
		actors = append(actors, e.Actor)
	}
	if got := strings.Join(kinds, ","); got != "session.requested,session.refused,session.approved" {
		t.Fatalf("events = %s", got)
	}
	if got := strings.Join(actors, ","); got != "alice,alice,bob" {
		t.Fatalf("actors = %s", got)
	}
}
