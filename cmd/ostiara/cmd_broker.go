package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/ostiara/ostiara/internal/audit"
	"github.com/ostiara/ostiara/internal/broker"
	"github.com/ostiara/ostiara/internal/kube"
	"github.com/ostiara/ostiara/internal/notify"
	"github.com/ostiara/ostiara/internal/recording"
)

// runBroker serves the broker API until interrupted.
func runBroker(args []string) error {
	fs := flag.NewFlagSet("broker", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "address to listen on")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: in-cluster, $KUBECONFIG or ~/.kube/config)")
	authMode := fs.String("auth", "tokenreview", "how to identify callers: tokenreview, or header (dev only)")
	audience := fs.String("token-audience", "", "only accept tokens issued for this audience, e.g. ostiara (tokenreview only)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (PEM); serve HTTPS when set with -tls-key")
	tlsKey := fs.String("tls-key", "", "TLS private key file (PEM)")
	auditPath := fs.String("audit-log", "-", "where to append audit events as JSON lines: - for stdout, or a file path")
	recordingsDir := fs.String("recordings-dir", "", "record every exec session into this directory (asciicast files); empty means off")
	recordInput := fs.Bool("record-input", false, "also record keystrokes, which can include passwords typed at prompts that don't echo")
	notifyDetail := fs.String("notify-detail", "full", "chat messages: full, or minimal (no pods, commands or reasons)")
	policyFile := fs.String("policy-file", "", "approval rules per namespace (YAML); empty means one approval from anyone but the requester")
	actionsFile := fs.String("actions-file", "", "catalog of predefined actions (YAML); empty means the built-in ps, df, env")
	recordingMax := fs.Int64("recording-max-bytes", recording.DefaultLimit, "cap per recording; longer sessions are cut off and marked truncated")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *authMode == "header" {
		if err := checkHeaderMode(*addr, os.Getenv("KUBERNETES_SERVICE_HOST") != ""); err != nil {
			return err
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	clientset, config, err := kube.NewClient(*kubeconfig)
	if err != nil {
		return err
	}
	auth, err := newAuthenticator(*authMode, *audience, clientset)
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

	auditLog, closeAudit, err := openAudit(*auditPath)
	if err != nil {
		return err
	}
	if key := os.Getenv("OSTIARA_AUDIT_KEY"); key != "" {
		auditLog.WithKey([]byte(key))
		logger.Info("audit log lines are signed (HMAC)")
	}
	defer closeAudit()

	notifier, err := newNotifier(logger, *notifyDetail)
	if err != nil {
		return err
	}
	recordings, err := openRecordings(*recordingsDir, *recordingMax)
	if err != nil {
		return err
	}
	if recordings == nil {
		logger.Warn("sessions aren't recorded; set -recordings-dir to keep what was done in each shell")
	}
	if notifier != nil {
		defer notifier.Close()
	}

	brokerSrv, err := newBrokerServer(auth, clientset, config, logger, auditLog, notifier, recordings, *recordInput).WithActions(*actionsFile)
	if err != nil {
		return err
	}
	if _, err := brokerSrv.WithPolicy(*policyFile); err != nil {
		return err
	}
	handler := brokerSrv.Handler()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConf,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("broker listening", "addr", *addr, "apiServer", config.Host, "auth", *authMode,
			"tokenAudience", *audience, "tls", tlsConf != nil, "auditLog", *auditPath)
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
func newAuthenticator(mode, audience string, clientset kubernetes.Interface) (broker.Authenticator, error) {
	switch mode {
	case "tokenreview":
		return broker.TokenReviewAuth{Reviews: clientset.AuthenticationV1().TokenReviews(), Audience: audience}, nil
	case "header":
		if audience != "" {
			return nil, errors.New("-token-audience needs -auth tokenreview")
		}
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

// checkHeaderMode keeps -auth header on this machine: loopback only, never inside a pod.
func checkHeaderMode(addr string, inCluster bool) error {
	if inCluster {
		return errors.New("-auth header is for local development and won't run inside a cluster; use -auth tokenreview")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad -addr %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("-auth header lets anyone claim any identity, so it only listens on this machine: use -addr 127.0.0.1:8080 (got %q)", addr)
}

// openAudit opens the audit destination: stdout for "-", otherwise a file opened for appending.
func openAudit(path string) (*audit.Log, func(), error) {
	if path == "-" || path == "" {
		return audit.New(os.Stdout), func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log: %w", err)
	}
	return audit.New(f), func() { f.Close() }, nil
}

func newBrokerServer(auth broker.Authenticator, clientset kubernetes.Interface, config *rest.Config,
	logger *slog.Logger, auditLog *audit.Log, notifier *notify.Dispatcher, recordings *recording.Store, recordInput bool) *broker.Server {
	srv := broker.NewServer(broker.NewStore(), auth, clientset, config, logger, auditLog)
	if recordings != nil {
		srv.WithRecordings(*recordings, recordInput)
	}
	if notifier != nil {
		srv.WithNotifier(notifier)
	}
	return srv
}

// newNotifier reads webhook URLs from the environment (mount them from a Secret); none set means no chat.
func newNotifier(logger *slog.Logger, detail string) (*notify.Dispatcher, error) {
	if detail != "full" && detail != "minimal" {
		return nil, fmt.Errorf("-notify-detail must be full or minimal, got %q", detail)
	}
	var senders []notify.Sender
	for _, w := range []struct {
		env  string
		make func(string) notify.Sender
	}{
		{"OSTIARA_SLACK_WEBHOOK_URL", func(u string) notify.Sender { return notify.Slack{URL: u} }},
		{"OSTIARA_TEAMS_WEBHOOK_URL", func(u string) notify.Sender { return notify.Teams{URL: u} }},
	} {
		raw := strings.TrimSpace(os.Getenv(w.env))
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, fmt.Errorf("%s isn't a valid http(s) URL", w.env) // don't echo it: it's a secret
		}
		if u.Scheme != "https" {
			logger.Warn("webhook URL isn't https; use http only for local testing", "env", w.env)
		}
		senders = append(senders, w.make(raw))
	}
	if len(senders) == 0 {
		return nil, nil
	}
	names := []string{}
	for _, s := range senders {
		names = append(names, s.Name())
	}
	logger.Info("chat notifications on", "to", strings.Join(names, ","), "detail", detail)
	d := notify.NewDispatcher(logger, senders...)
	if detail == "minimal" {
		d.Minimal()
	}
	return d, nil
}

// openRecordings checks the recordings directory is writable now, rather than at the first session.
func openRecordings(dir string, limit int64) (*recording.Store, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("recordings directory: %w", err)
	}
	probe, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return nil, fmt.Errorf("recordings directory %s isn't writable: %w", dir, err)
	}
	probe.Close()
	os.Remove(probe.Name())
	return &recording.Store{Dir: dir, Limit: limit}, nil
}
