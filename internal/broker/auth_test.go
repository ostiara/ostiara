package broker

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ostiara/ostiara/internal/api"
)

// brokenAuth stands in for an identity backend that is down.
type brokenAuth struct{}

func (brokenAuth) Authenticate(*http.Request) (string, error) {
	return "", errors.New("backend down")
}

func TestRequireUser(t *testing.T) {
	cases := []struct {
		name   string
		auth   Authenticator
		header string
		want   int
	}{
		{"header present", HeaderAuth{}, "alice", http.StatusOK},
		{"header missing", HeaderAuth{}, "", http.StatusUnauthorized},
		{"backend error", brokenAuth{}, "alice", http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(NewStore(), tc.auth, nil, nil, slog.New(slog.DiscardHandler), nil)
			req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
			if tc.header != "" {
				req.Header.Set(api.UserHeader, tc.header)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}
