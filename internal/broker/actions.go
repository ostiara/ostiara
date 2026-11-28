package broker

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ostiara/ostiara/internal/actions"
	"github.com/ostiara/ostiara/internal/api"
)

// AutoApprover is who approves actions whose catalog entry says approval: auto.
const AutoApprover = "ostiara:auto"

// actionSource reloads the catalog file when it changes (a mounted ConfigMap updates in place).
type actionSource struct {
	path    string
	mu      sync.Mutex
	current actions.Catalog
	mtime   time.Time
	log     func(msg string, args ...any)
}

func (a *actionSource) catalog() actions.Catalog {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.path == "" {
		return a.current
	}
	info, err := os.Stat(a.path)
	if err != nil || info.ModTime().Equal(a.mtime) {
		return a.current
	}
	c, err := actions.Load(a.path)
	if err != nil {
		a.log("actions catalog not reloaded; keeping the last good one", "err", err)
		return a.current
	}
	a.current, a.mtime = c, info.ModTime()
	return a.current
}

// WithActions offers the catalog at path (empty: the built-in defaults). It's checked now and
// re-read whenever the file changes.
func (s *Server) WithActions(path string) (*Server, error) {
	c, err := actions.Load(path)
	if err != nil {
		return s, err
	}
	src := &actionSource{path: path, current: c, log: s.log.Warn}
	if info, err := os.Stat(path); err == nil {
		src.mtime = info.ModTime()
	}
	s.actions = src
	return s, nil
}

func (s *Server) catalog() actions.Catalog {
	if s.actions == nil {
		return actions.Defaults
	}
	return s.actions.catalog()
}

// listActions shows what can be run in a namespace: GET /v1/actions?namespace=ns.
func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireUser(w, r); !ok {
		return
	}
	ns := r.URL.Query().Get("namespace")
	out := []actions.Action{}
	for _, a := range s.catalog().Actions {
		if found, ok := s.catalog().Find(a.Name, ns); ok {
			out = append(out, found)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// resolveAction turns an action request into its command. The catalog, not the caller, decides
// what runs.
func (s *Server) resolveAction(req *api.CreateSessionRequest) (actions.Action, error) {
	a, ok := s.catalog().Find(req.Action, req.Namespace)
	if !ok {
		return a, badRequest("no action " + req.Action + " in namespace " + req.Namespace + " (ostiara actions lists them)")
	}
	if len(req.Command) > 0 || req.TTY || req.Kind == api.KindPortForward {
		return a, badRequest("an action runs its own command: leave out the command, tty and port-forward")
	}
	req.Command = append([]string(nil), a.Command...)
	req.Redact = a.Redact
	return a, nil
}

// mayUseNamespace asks Kubernetes whether the caller can at least read pods there, the bar for
// actions that run without a teammate's approval.
func (s *Server) mayUseNamespace(ctx context.Context, id Identity, ns string) (bool, error) {
	review := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: id.Name, Groups: id.Groups,
		ResourceAttributes: &authzv1.ResourceAttributes{Namespace: ns, Resource: "pods", Verb: "get"},
	}}
	result, err := s.clientset.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return result.Status.Allowed, nil
}

type badRequest string

func (b badRequest) Error() string { return string(b) }
