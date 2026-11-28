package broker

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// fakeReviews acts as the API server. "good-token" is alice with the API server's own audience,
// "ostiara-token" is alice with audience "ostiara" only, "unaware-token" passes without any audience
// check (like a webhook that ignores audiences), "boom" fails, and anything else is rejected.
func fakeReviews(audience string) TokenReviewAuth {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		want := review.Spec.Audiences
		if len(want) == 0 {
			want = []string{"kube-api"}
		}
		alice := authnv1.UserInfo{Username: "alice", Groups: []string{"devs", "system:authenticated"}}
		switch review.Spec.Token {
		case "good-token", "ostiara-token":
			tokenAud := map[string]string{"good-token": "kube-api", "ostiara-token": "ostiara"}[review.Spec.Token]
			if slices.Contains(want, tokenAud) {
				review.Status = authnv1.TokenReviewStatus{Authenticated: true, User: alice, Audiences: []string{tokenAud}}
			} else {
				review.Status = authnv1.TokenReviewStatus{Authenticated: false, Error: "token audiences are invalid"}
			}
		case "unaware-token":
			review.Status = authnv1.TokenReviewStatus{Authenticated: true, User: alice}
		case "boom":
			return true, nil, errors.New("api server unreachable")
		default:
			review.Status = authnv1.TokenReviewStatus{Authenticated: false, Error: "token expired"}
		}
		return true, review, nil
	})
	return TokenReviewAuth{Reviews: cs.AuthenticationV1().TokenReviews(), Audience: audience}
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
	auth := fakeReviews("")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			id, err := auth.Authenticate(req)
			user := id.Name

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

func TestTokenReviewAudience(t *testing.T) {
	cases := []struct {
		name     string
		token    string
		wantUser string
	}{
		{"token for ostiara", "ostiara-token", "alice"},
		{"token for the API server only", "good-token", ""},
		{"server didn't check the audience", "unaware-token", ""},
	}
	auth := fakeReviews("ostiara")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			id, err := auth.Authenticate(req)
			user := id.Name
			if tc.wantUser != "" {
				if err != nil || user != tc.wantUser {
					t.Fatalf("got (%q, %v), want (%q, nil)", user, err, tc.wantUser)
				}
				return
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("err = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestTokenReviewWithoutAudienceRejectsOstiaraOnlyTokens(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer ostiara-token")
	if _, err := fakeReviews("").Authenticate(req); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ostiara-only token without -token-audience: err = %v, want ErrUnauthenticated", err)
	}
}

func TestTokenReviewKeepsGroups(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	id, err := fakeReviews("").Authenticate(req)
	if err != nil || id.Name != "alice" || !slices.Equal(id.Groups, []string{"devs", "system:authenticated"}) {
		t.Fatalf("got (%+v, %v): want alice with her groups, for access reviews", id, err)
	}
}
