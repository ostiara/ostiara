package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/ostiara/ostiara/internal/actions"
	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/audit"
	"github.com/ostiara/ostiara/internal/notify"
	"github.com/ostiara/ostiara/internal/recording"
)

// Server is the broker's HTTP API.
type Server struct {
	store     *Store
	auth      Authenticator
	clientset kubernetes.Interface
	config    *rest.Config
	log       *slog.Logger
	audit     *audit.Log
	notifier  Notifier

	recordings  *recording.Store // nil: sessions aren't recorded
	recordInput bool
	actions     *actionSource // nil: the built-in defaults
}

// WithRecordings records every exec session's output, and its keystrokes too if input is set.
func (s *Server) WithRecordings(store recording.Store, input bool) *Server {
	s.recordings = &store
	s.recordInput = input
	return s
}

// Notifier tells the team's chat about requests and decisions. Notify must not block.
type Notifier interface {
	Notify(notify.Event)
}

// WithNotifier turns on chat notifications.
func (s *Server) WithNotifier(n Notifier) *Server {
	s.notifier = n
	return s
}

func (s *Server) announce(kind string, sess api.Session) {
	if s.notifier != nil {
		s.notifier.Notify(notify.Event{Kind: kind, Session: sess})
	}
}

func NewServer(store *Store, auth Authenticator, clientset kubernetes.Interface, config *rest.Config,
	log *slog.Logger, auditLog *audit.Log) *Server {
	return &Server{store: store, auth: auth, clientset: clientset, config: config, log: log, audit: auditLog}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", s.createSession)
	mux.HandleFunc("GET /v1/sessions", s.listSessions)
	mux.HandleFunc("GET /v1/sessions/{id}", s.getSession)
	mux.HandleFunc("POST /v1/sessions/{id}/approve", s.decide(true))
	mux.HandleFunc("POST /v1/sessions/{id}/deny", s.decide(false))
	mux.HandleFunc("GET /v1/sessions/{id}/attach", s.attach)
	mux.HandleFunc("GET /v1/sessions/{id}/forward", s.forward)
	mux.HandleFunc("GET /v1/sessions/{id}/recording", s.recording)
	mux.HandleFunc("GET /v1/actions", s.listActions)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	return mux
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	id, ok := s.requireIdentity(w, r)
	if !ok {
		return
	}
	user := id.Name

	var req api.CreateSessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Namespace == "" || req.Pod == "" {
		writeError(w, http.StatusBadRequest, "namespace and pod are required")
		return
	}
	req.Redact = ""
	var action actions.Action
	if req.Action != "" {
		var err error
		if action, err = s.resolveAction(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := normalize(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Fail fast so nobody approves a request for a pod that doesn't exist.
	_, err := s.clientset.CoreV1().Pods(req.Namespace).Get(r.Context(), req.Pod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("pod %s/%s not found", req.Namespace, req.Pod))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "checking pod: "+err.Error())
		return
	}

	// An auto action skips the teammate, so the caller must at least be able to read pods there.
	auto := action.Approval == actions.Auto
	if auto {
		allowed, err := s.mayUseNamespace(r.Context(), id, req.Namespace)
		if err != nil {
			s.log.Error("authorization check failed", "err", err)
			writeError(w, http.StatusBadGateway, "authorization unavailable")
			return
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "running "+req.Action+" without approval needs permission to get pods in "+req.Namespace)
			return
		}
	}

	sess, err := s.store.Create(user, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	e := audit.ForSession(audit.Requested, sess)
	e.Actor = user
	s.record(e)
	if !auto {
		s.announce(notify.Requested, sess)
		writeJSON(w, http.StatusCreated, sess)
		return
	}
	if sess, err = s.store.Decide(sess.ID, AutoApprover, true); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	e = audit.ForSession(audit.Approved, sess)
	e.Actor = AutoApprover
	s.record(e)
	s.announce(notify.Approved, sess)
	writeJSON(w, http.StatusCreated, sess)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireUser(w, r); !ok {
		return
	}
	sessions := s.store.List(api.Status(r.URL.Query().Get("status")))
	if sessions == nil {
		sessions = []api.Session{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireUser(w, r); !ok {
		return
	}
	sess, err := s.store.Get(r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

// decide returns the handler for /approve or /deny.
func (s *Server) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.requireUser(w, r)
		if !ok {
			return
		}
		sess, err := s.store.Decide(r.PathValue("id"), user, approve)
		if err != nil {
			s.recordRefusal(r.PathValue("id"), user, err)
			writeStoreError(w, err)
			return
		}
		kind, announced := audit.Denied, notify.Denied
		if approve {
			kind, announced = audit.Approved, notify.Approved
		}
		e := audit.ForSession(kind, sess)
		e.Actor = user
		s.record(e)
		s.announce(announced, sess)
		writeJSON(w, http.StatusOK, sess)
	}
}

// Only the CLI attaches, and it sends no Origin; browsers always do, so refuse them.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
}

// --- helpers ---

// Port-forward approvals last DefaultWindow unless asked otherwise, and never more than MaxWindow.
const (
	DefaultWindow = 15 * time.Minute
	MaxWindow     = time.Hour
)

// normalize fills defaults and rejects requests that make no sense for their kind.
func normalize(req *api.CreateSessionRequest) error {
	switch req.Kind {
	case "", api.KindExec:
		req.Kind = api.KindExec
		if req.Port != 0 || req.WindowSeconds != 0 {
			return errors.New("port and window are only for port-forward sessions")
		}
		if len(req.Command) == 0 {
			req.Command = []string{"sh"}
		}
	case api.KindPortForward:
		if req.Port < 1 || req.Port > 65535 {
			return fmt.Errorf("port-forward needs a pod port between 1 and 65535, got %d", req.Port)
		}
		if len(req.Command) > 0 || req.TTY || req.Container != "" {
			return errors.New("command, tty and container are only for exec sessions")
		}
		window := time.Duration(req.WindowSeconds) * time.Second
		if window == 0 {
			window = DefaultWindow
		}
		if window < time.Minute || window > MaxWindow {
			return fmt.Errorf("port-forward window must be between 1m and %s", MaxWindow)
		}
		req.WindowSeconds = int(window / time.Second)
	default:
		return fmt.Errorf("unknown session kind %q (want exec or port-forward)", req.Kind)
	}
	return nil
}

// record writes an audit event; a failure is reported in the operational log.
func (s *Server) record(e audit.Event) error {
	err := s.audit.Record(e)
	if err != nil {
		s.log.Error("audit log write failed", "event", e.Kind, "session", e.Session, "err", err)
	}
	return err
}

// recordRefusal audits the attempts that matter for security: deciding your own
// session, or using someone else's.
func (s *Server) recordRefusal(id, user string, err error) {
	if errors.Is(err, ErrSelfApproval) || errors.Is(err, ErrNotRequester) {
		s.record(audit.Event{Kind: audit.Refused, Session: id, Actor: user, Error: err.Error()})
	}
}

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := s.requireIdentity(w, r)
	return id.Name, ok
}

func (s *Server) requireIdentity(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, err := s.auth.Authenticate(r)
	if errors.Is(err, ErrUnauthenticated) {
		writeError(w, http.StatusUnauthorized, err.Error())
		return Identity{}, false
	}
	if err != nil {
		s.log.Error("authentication failed", "err", err)
		writeError(w, http.StatusBadGateway, "authentication unavailable")
		return Identity{}, false
	}
	return id, true
}

func writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrSelfApproval), errors.Is(err, ErrNotRequester):
		status = http.StatusForbidden
	case errors.Is(err, ErrNotPending), errors.Is(err, ErrNotAttachable), errors.Is(err, ErrWrongKind):
		status = http.StatusConflict
	}
	writeError(w, status, err.Error())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}
