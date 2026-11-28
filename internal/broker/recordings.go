package broker

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ostiara/ostiara/internal/audit"
)

// RecordingsGroup is the API group RBAC uses to decide who may view recordings. It isn't served:
// RBAC rules can name it all the same, e.g. verbs [get] on resources [sessions/recording].
const RecordingsGroup = "ostiara.io"

// recording serves a session's recording to callers Kubernetes allows to view it. Every view,
// and every refused attempt, goes in the audit log.
func (s *Server) recording(w http.ResponseWriter, r *http.Request) {
	id, ok := s.requireIdentity(w, r)
	if !ok {
		return
	}
	if s.recordings == nil {
		writeError(w, http.StatusNotFound, "this broker doesn't record sessions")
		return
	}
	sessionID := r.PathValue("id")
	allowed, err := s.mayViewRecording(r.Context(), id, sessionID)
	if err != nil {
		s.log.Error("authorization check failed", "err", err)
		writeError(w, http.StatusBadGateway, "authorization unavailable")
		return
	}
	if !allowed {
		s.record(audit.Event{Kind: audit.Refused, Session: sessionID, Actor: id.Name, Error: "not allowed to view recordings"})
		writeError(w, http.StatusForbidden, "viewing recordings needs RBAC verb get on sessions/recording in API group "+RecordingsGroup)
		return
	}
	f, err := s.recordings.Open(sessionID)
	if errors.Is(err, fs.ErrNotExist) {
		writeError(w, http.StatusNotFound, "no recording for session "+sessionID)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer f.Close()
	if err := s.record(audit.Event{Kind: audit.RecordingViewed, Session: sessionID, Actor: id.Name}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit log unavailable; refusing an unlogged view")
		return
	}
	w.Header().Set("Content-Type", "application/x-asciicast")
	io.Copy(w, f)
}

func (s *Server) mayViewRecording(ctx context.Context, id Identity, sessionID string) (bool, error) {
	review := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User:   id.Name,
		Groups: id.Groups,
		ResourceAttributes: &authzv1.ResourceAttributes{
			Group: RecordingsGroup, Resource: "sessions", Subresource: "recording", Verb: "get", Name: sessionID,
		},
	}}
	result, err := s.clientset.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return result.Status.Allowed, nil
}
