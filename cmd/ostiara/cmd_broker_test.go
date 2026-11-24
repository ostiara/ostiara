package main

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/ostiara/ostiara/internal/broker"
)

func TestNewAuthenticator(t *testing.T) {
	cs := fake.NewClientset()

	if a, err := newAuthenticator("tokenreview", cs); err != nil {
		t.Fatalf("tokenreview: %v", err)
	} else if _, ok := a.(broker.TokenReviewAuth); !ok {
		t.Fatalf("tokenreview: got %T", a)
	}
	if a, err := newAuthenticator("header", cs); err != nil {
		t.Fatalf("header: %v", err)
	} else if _, ok := a.(broker.HeaderAuth); !ok {
		t.Fatalf("header: got %T", a)
	}
	if _, err := newAuthenticator("oidc", cs); err == nil {
		t.Fatal("unknown mode: want an error")
	}
}
