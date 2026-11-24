package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/ostiara/ostiara/internal/broker"
	"github.com/ostiara/ostiara/internal/kube"
)

// runBroker serves the broker API until interrupted.
func runBroker(args []string) error {
	fs := flag.NewFlagSet("broker", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "address to listen on")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: in-cluster, $KUBECONFIG or ~/.kube/config)")
	authMode := fs.String("auth", "header", "how to identify callers: tokenreview, or header (dev only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	clientset, config, err := kube.NewClient(*kubeconfig)
	if err != nil {
		return err
	}
	auth, err := newAuthenticator(*authMode, clientset)
	if err != nil {
		return err
	}
	if *authMode == "header" {
		logger.Warn("auth=header trusts the X-Ostiara-User header; use only for local development")
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           broker.NewServer(broker.NewStore(), auth, clientset, config, logger).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("broker listening", "addr", *addr, "apiServer", config.Host, "auth", *authMode)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// newAuthenticator picks how the broker identifies callers.
func newAuthenticator(mode string, clientset kubernetes.Interface) (broker.Authenticator, error) {
	switch mode {
	case "tokenreview":
		return broker.TokenReviewAuth{Reviews: clientset.AuthenticationV1().TokenReviews()}, nil
	case "header":
		return broker.HeaderAuth{}, nil
	default:
		return nil, fmt.Errorf("unknown -auth %q (want tokenreview or header)", mode)
	}
}
