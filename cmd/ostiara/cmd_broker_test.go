package main

import (
	"log/slog"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/ostiara/ostiara/internal/broker"
)

func TestNewAuthenticator(t *testing.T) {
	cs := fake.NewClientset()

	if a, err := newAuthenticator("tokenreview", "", cs); err != nil {
		t.Fatalf("tokenreview: %v", err)
	} else if _, ok := a.(broker.TokenReviewAuth); !ok {
		t.Fatalf("tokenreview: got %T", a)
	}
	if a, err := newAuthenticator("tokenreview", "ostiara", cs); err != nil {
		t.Fatalf("tokenreview with audience: %v", err)
	} else if tr, ok := a.(broker.TokenReviewAuth); !ok || tr.Audience != "ostiara" {
		t.Fatalf("tokenreview with audience: got %#v", a)
	}
	if _, err := newAuthenticator("header", "ostiara", cs); err == nil {
		t.Fatal("header with audience: want an error")
	}
	if a, err := newAuthenticator("header", "", cs); err != nil {
		t.Fatalf("header: %v", err)
	} else if _, ok := a.(broker.HeaderAuth); !ok {
		t.Fatalf("header: got %T", a)
	}
	if _, err := newAuthenticator("oidc", "", cs); err == nil {
		t.Fatal("unknown mode: want an error")
	}
}

func TestCheckHeaderMode(t *testing.T) {
	cases := []struct {
		addr      string
		inCluster bool
		ok        bool
	}{
		{"127.0.0.1:8080", false, true},
		{"localhost:8080", false, true},
		{"[::1]:8080", false, true},
		{"127.0.0.2:8080", false, true},
		{":8080", false, false},
		{"0.0.0.0:8080", false, false},
		{"[::]:8080", false, false},
		{"10.0.0.5:8080", false, false},
		{"example.com:8080", false, false},
		{"not-an-addr", false, false},
		{"127.0.0.1:8080", true, false},
	}
	for _, tc := range cases {
		err := checkHeaderMode(tc.addr, tc.inCluster)
		if (err == nil) != tc.ok {
			t.Errorf("checkHeaderMode(%q, inCluster=%v) = %v, want ok=%v", tc.addr, tc.inCluster, err, tc.ok)
		}
	}
}

func TestNewNotifier(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	t.Setenv("OSTIARA_SLACK_WEBHOOK_URL", "")
	t.Setenv("OSTIARA_TEAMS_WEBHOOK_URL", "")
	if d, err := newNotifier(logger, "full"); d != nil || err != nil {
		t.Fatalf("no URLs: got (%v, %v), want no notifier", d, err)
	}

	t.Setenv("OSTIARA_SLACK_WEBHOOK_URL", "not a url s3cr3t")
	if _, err := newNotifier(logger, "full"); err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("bad URL: err = %v, want an error that doesn't echo the URL", err)
	}

	t.Setenv("OSTIARA_SLACK_WEBHOOK_URL", "https://hooks.slack.example/services/x")
	t.Setenv("OSTIARA_TEAMS_WEBHOOK_URL", "https://teams.example/workflows/y")
	d, err := newNotifier(logger, "full")
	if err != nil || d == nil {
		t.Fatalf("both URLs: got (%v, %v)", d, err)
	}
	d.Close()
}
