package broker

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeReviews acts as the API server: "good-token" is alice, "boom" fails, anything else is rejected.
func fakeReviews() TokenReviewAuth {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		switch review.Spec.Token {
		case "good-token":
			review.Status = authnv1.TokenReviewStatus{Authenticated: true, User: authnv1.UserInfo{Username: "alice"}}
		case "boom":
			return true, nil, errors.New("api server unreachable")
		default:
			review.Status = authnv1.TokenReviewStatus{Authenticated: false, Error: "token expired"}
		}
		return true, review, nil
	})
	return TokenReviewAuth{Reviews: cs.AuthenticationV1().TokenReviews()}
}

func TestTokenReviewAuth(t *testing.T) {
	cases := []struct {
		name     string
		header   string
		wantUser string
		wantErr  string // "", "unauth" or "backend"
	}{
		{"valid token", "Bearer good-token", "alice", ""},
		{"lowercase scheme", "bearer good-token", "alice", ""},
		{"no header", "", "", "unauth"},
		{"wrong scheme", "Basic good-token", "", "unauth"},
		{"empty token", "Bearer ", "", "unauth"},
		{"rejected token", "Bearer stale", "", "unauth"},
		{"api error", "Bearer boom", "", "backend"},
	}
	auth := fakeReviews()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			user, err := auth.Authenticate(req)

			switch tc.wantErr {
			case "":
				if err != nil || user != tc.wantUser {
					t.Fatalf("got (%q, %v), want (%q, nil)", user, err, tc.wantUser)
				}
			case "unauth":
				if !errors.Is(err, ErrUnauthenticated) {
					t.Fatalf("err = %v, want ErrUnauthenticated", err)
				}
			case "backend":
				if err == nil || errors.Is(err, ErrUnauthenticated) {
					t.Fatalf("err = %v, want a backend error", err)
				}
			}
		})
	}
}
