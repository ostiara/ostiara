package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ostiara/ostiara/internal/broker"
	"github.com/ostiara/ostiara/internal/kube"
)

// runBroker serves the broker API until interrupted.
func runBroker(args []string) error {
	fs := flag.NewFlagSet("broker", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "address to listen on")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: in-cluster, $KUBECONFIG or ~/.kube/config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	clientset, config, err := kube.NewClient(*kubeconfig)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           broker.NewServer(broker.NewStore(), broker.HeaderAuth{}, clientset, config, logger).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("broker listening", "addr", *addr, "apiServer", config.Host)
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
