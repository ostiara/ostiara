package broker

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ostiara/ostiara/internal/api"
)

// ErrUnauthenticated means the caller didn't prove who they are.
var ErrUnauthenticated = errors.New("unauthenticated")

// Identity is who sent a request, as Kubernetes knows them.
type Identity struct {
	Name   string
	Groups []string
}

// Authenticator works out which user sent a request.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// HeaderAuth trusts the self-declared X-Ostiara-User header. Dev only.
type HeaderAuth struct{}

func (HeaderAuth) Authenticate(r *http.Request) (Identity, error) {
	user := r.Header.Get(api.UserHeader)
	if user == "" {
		return Identity{}, fmt.Errorf("%w: missing %s header (set OSTIARA_USER)", ErrUnauthenticated, api.UserHeader)
	}
	return Identity{Name: user}, nil
}
