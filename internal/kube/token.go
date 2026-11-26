package kube

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// TokenSource returns the current kubeconfig user's bearer token on each call.
// It returns nil, nil when there is no kubeconfig at all.
func TokenSource(kubeconfigPath string) (func(context.Context) (string, error), error) {
	config, err := loadConfig(kubeconfigPath)
	if clientcmd.IsEmptyConfig(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}

	// client-go adds the same auth headers kubectl would, including exec plugins (EKS, GKE).
	rt, err := rest.HTTPWrappersForConfig(config, captureHeaders{})
	if err != nil {
		return nil, fmt.Errorf("kubeconfig credentials: %w", err)
	}

	return func(ctx context.Context) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ostiara.invalid/", nil)
		if err != nil {
			return "", err
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			return "", fmt.Errorf("getting kubeconfig token: %w", err)
		}
		scheme, token, _ := strings.Cut(resp.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			return "", nil
		}
		return token, nil
	}, nil
}

// captureHeaders ends the chain without any network call and echoes the request headers back.
type captureHeaders struct{}

func (captureHeaders) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: req.Header.Clone(), Body: http.NoBody, Request: req}, nil
}
