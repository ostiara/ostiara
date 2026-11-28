package broker

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/audit"
	"github.com/ostiara/ostiara/internal/recording"
)

// recordingServer allows viewing for the "security" group only, and has one recording.
func recordingServer(t *testing.T) (http.Handler, *bytes.Buffer, *[]authzv1.SubjectAccessReviewSpec) {
	t.Helper()
	var asked []authzv1.SubjectAccessReviewSpec
	cs := fake.NewClientset()
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		asked = append(asked, sar.Spec)
		for _, g := range sar.Spec.Groups {
			if g == "security" {
				sar.Status.Allowed = true
			}
		}
		return true, sar, nil
	})
	st := recording.Store{Dir: t.TempDir()}
	rec, _ := st.Create("2cd09933", "t", time.Now())
	rec.Output([]byte("secret-output"))
	rec.Close()

	var auditBuf bytes.Buffer
	srv := NewServer(NewStore(), groupAuth{}, cs, nil, slog.New(slog.DiscardHandler), audit.New(&auditBuf)).WithRecordings(st, false)
	return srv.Handler(), &auditBuf, &asked
}

// groupAuth reads "name:group" from the user header, for tests.
type groupAuth struct{}

func (groupAuth) Authenticate(r *http.Request) (Identity, error) {
	name, group, _ := strings.Cut(r.Header.Get(api.UserHeader), ":")
	return Identity{Name: name, Groups: []string{group}}, nil
}

func get(h http.Handler, path, user string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(api.UserHeader, user)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestRecordingViewIsAuthorizedAndAudited(t *testing.T) {
	h, auditBuf, asked := recordingServer(t)

	if w := get(h, "/v1/sessions/2cd09933/recording", "mallory:devs"); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "secret-output") {
		t.Fatalf("not allowed: %d %s", w.Code, w.Body)
	}
	w := get(h, "/v1/sessions/2cd09933/recording", "sam:security")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "secret-output") {
		t.Fatalf("allowed: %d %s", w.Code, w.Body)
	}
	if w := get(h, "/v1/sessions/aaaaaaaa/recording", "sam:security"); w.Code != http.StatusNotFound {
		t.Fatalf("no such recording: %d", w.Code)
	}

	spec := (*asked)[0]
	if spec.User != "mallory" || spec.ResourceAttributes.Group != RecordingsGroup ||
		spec.ResourceAttributes.Subresource != "recording" || spec.ResourceAttributes.Name != "2cd09933" {
		t.Fatalf("access review asked the wrong question: %+v %+v", spec, spec.ResourceAttributes)
	}

	var kinds []string
	for _, line := range strings.Split(strings.TrimSpace(auditBuf.String()), "\n") {
		var e audit.Event
		json.Unmarshal([]byte(line), &e)
		kinds = append(kinds, e.Kind+" "+e.Actor)
	}
	if got := strings.Join(kinds, ","); got != "session.refused mallory,recording.viewed sam" {
		t.Fatalf("audit = %s", got)
	}
}

func TestRecordingWhenNotRecording(t *testing.T) {
	srv := NewServer(NewStore(), HeaderAuth{}, fake.NewClientset(), nil, slog.New(slog.DiscardHandler), nil)
	if w := get(srv.Handler(), "/v1/sessions/2cd09933/recording", "alice"); w.Code != http.StatusNotFound {
		t.Fatalf("broker without recordings: %d", w.Code)
	}
}
