package main

import (
	"context"
	"crypto/tls"
	"errors"
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
	authMode := fs.String("auth", "tokenreview", "how to identify callers: tokenreview, or header (dev only)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (PEM); serve HTTPS when set with -tls-key")
	tlsKey := fs.String("tls-key", "", "TLS private key file (PEM)")
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
	tlsConf, err := loadTLS(*tlsCert, *tlsKey)
	if err != nil {
		return err
	}
	if tlsConf == nil {
		logger.Warn("serving plain HTTP: callers' tokens cross the network unencrypted; set -tls-cert and -tls-key")
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           broker.NewServer(broker.NewStore(), auth, clientset, config, logger).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConf,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("broker listening", "addr", *addr, "apiServer", config.Host, "auth", *authMode, "tls", tlsConf != nil)
		if tlsConf != nil {
			errCh <- srv.ListenAndServeTLS("", "")
		} else {
			errCh <- srv.ListenAndServe()
		}
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

// loadTLS reads the broker's certificate; both files empty means plain HTTP (nil config).
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("set both -tls-cert and -tls-key, or neither")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
