package broker

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ostiara/ostiara/internal/api"
)

// ErrUnauthenticated means the caller didn't prove who they are.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator works out which user sent a request.
type Authenticator interface {
	Authenticate(r *http.Request) (string, error)
}

// HeaderAuth trusts the self-declared X-Ostiara-User header. Dev only.
type HeaderAuth struct{}

func (HeaderAuth) Authenticate(r *http.Request) (string, error) {
	user := r.Header.Get(api.UserHeader)
	if user == "" {
		return "", fmt.Errorf("%w: missing %s header (set OSTIARA_USER)", ErrUnauthenticated, api.UserHeader)
	}
	return user, nil
}
