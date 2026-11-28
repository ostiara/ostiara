package broker

import (
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
	"github.com/ostiara/ostiara/internal/notify"
)

type recordingNotifier struct{ events []notify.Event }

func (r *recordingNotifier) Notify(e notify.Event) { r.events = append(r.events, e) }

func TestServerAnnouncesRequestsAndDecisions(t *testing.T) {
	pods := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "demo"}})
	rec := &recordingNotifier{}
	srv := NewServer(NewStore(), HeaderAuth{}, pods, nil, slog.New(slog.DiscardHandler), nil).WithNotifier(rec).Handler()

	call := func(path, user, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set(api.UserHeader, user)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	var a, b api.Session
	json.Unmarshal(call("/v1/sessions", "alice", `{"namespace":"demo","pod":"p"}`).Body.Bytes(), &a)
	json.Unmarshal(call("/v1/sessions", "alice", `{"kind":"port-forward","namespace":"demo","pod":"p","port":80}`).Body.Bytes(), &b)
	call("/v1/sessions/"+a.ID+"/approve", "alice", "") // refused: not announced
	call("/v1/sessions/"+a.ID+"/approve", "bob", "")
	call("/v1/sessions/"+b.ID+"/deny", "bob", "")

	var got []string
	for _, e := range rec.events {
		got = append(got, e.Kind+" "+string(e.Session.Kind))
	}
	want := "requested exec,requested port-forward,approved exec,denied port-forward"
	if strings.Join(got, ",") != want {
		t.Fatalf("announced %v, want %s", got, want)
	}
}
