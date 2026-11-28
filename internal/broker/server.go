package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/audit"
)

// Server is the broker's HTTP API.
type Server struct {
	store     *Store
	auth      Authenticator
	clientset kubernetes.Interface
	config    *rest.Config
	log       *slog.Logger
	audit     *audit.Log
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
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	return mux
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}

	var req api.CreateSessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Namespace == "" || req.Pod == "" {
		writeError(w, http.StatusBadRequest, "namespace and pod are required")
		return
	}
	if len(req.Command) == 0 {
		req.Command = []string{"sh"}
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

	sess, err := s.store.Create(user, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	e := audit.ForSession(audit.Requested, sess)
	e.Actor = user
	s.record(e)
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
		kind := audit.Denied
		if approve {
			kind = audit.Approved
		}
		e := audit.ForSession(kind, sess)
		e.Actor = user
		s.record(e)
		writeJSON(w, http.StatusOK, sess)
	}
}

// Only the CLI attaches, and it sends no Origin; browsers always do, so refuse them.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
}

// --- helpers ---

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
	user, err := s.auth.Authenticate(r)
	if errors.Is(err, ErrUnauthenticated) {
		writeError(w, http.StatusUnauthorized, err.Error())
		return "", false
	}
	if err != nil {
		s.log.Error("authentication failed", "err", err)
		writeError(w, http.StatusBadGateway, "authentication unavailable")
		return "", false
	}
	return user, true
}

func writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrSelfApproval), errors.Is(err, ErrNotRequester):
		status = http.StatusForbidden
	case errors.Is(err, ErrNotPending), errors.Is(err, ErrNotAttachable):
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
