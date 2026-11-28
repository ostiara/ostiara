package broker

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authnclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
)

// TokenReviewAuth asks the Kubernetes API who a bearer token belongs to.
type TokenReviewAuth struct {
	Reviews  authnclient.TokenReviewInterface
	Audience string // "": accept any token the API server accepts
}

func (a TokenReviewAuth) Authenticate(r *http.Request) (string, error) {
	token, ok := bearerToken(r)
	if !ok {
		return "", fmt.Errorf("%w: missing bearer token", ErrUnauthenticated)
	}

	review := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}
	if a.Audience != "" {
		review.Spec.Audiences = []string{a.Audience}
	}
	result, err := a.Reviews.Create(r.Context(), review, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("token review: %w", err)
	}
	if !result.Status.Authenticated || result.Status.User.Username == "" {
		return "", fmt.Errorf("%w: invalid token", ErrUnauthenticated)
	}
	// The API server must confirm the audience; an empty list means it didn't check.
	if a.Audience != "" && !slices.Contains(result.Status.Audiences, a.Audience) {
		return "", fmt.Errorf("%w: token not issued for audience %q", ErrUnauthenticated, a.Audience)
	}
	return result.Status.User.Username, nil
}

// bearerToken pulls the token out of "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
