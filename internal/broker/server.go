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
)

// Server is the broker's HTTP API.
type Server struct {
	store     *Store
	clientset *kubernetes.Clientset
	config    *rest.Config
	log       *slog.Logger
}

func NewServer(store *Store, clientset *kubernetes.Clientset, config *rest.Config, log *slog.Logger) *Server {
	return &Server{store: store, clientset: clientset, config: config, log: log}
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
	user, ok := requireUser(w, r)
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
	s.log.Info("session requested", "id", sess.ID, "requester", user,
		"namespace", sess.Namespace, "pod", sess.Pod, "command", sess.Command, "reason", sess.Reason)
	writeJSON(w, http.StatusCreated, sess)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireUser(w, r); !ok {
		return
	}
	sessions := s.store.List(api.Status(r.URL.Query().Get("status")))
	if sessions == nil {
		sessions = []api.Session{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireUser(w, r); !ok {
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
		user, ok := requireUser(w, r)
		if !ok {
			return
		}
		sess, err := s.store.Decide(r.PathValue("id"), user, approve)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		s.log.Info("session "+string(sess.Status), "id", sess.ID,
			"requester", sess.Requester, "approver", user)
		writeJSON(w, http.StatusOK, sess)
	}
}

// Our client is a CLI using no cookies, so any origin is fine.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// --- helpers ---

func requireUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	user := r.Header.Get(api.UserHeader)
	if user == "" {
		writeError(w, http.StatusUnauthorized, "missing "+api.UserHeader+" header (set OSTIARA_USER)")
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
