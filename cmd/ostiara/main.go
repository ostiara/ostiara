// Command ostiara is the CLI and the broker in one binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ostiara/ostiara/internal/client"
	"github.com/ostiara/ostiara/internal/kube"
)

const usage = `ostiara - the doorkeeper for your Kubernetes pods

Usage:
  ostiara exec [-n namespace] [-c container] [-reason text] POD [-- COMMAND...]
      Ask for access to a pod, wait for a teammate's approval, then connect.
  ostiara port-forward [-n namespace] [-for 15m] [-reason text] POD [LOCAL:]REMOTE
      Ask to reach one pod port; once approved, localhost:LOCAL forwards to it until the window ends.
  ostiara list [-all]
      Show sessions waiting for approval (-all: every session).
  ostiara approve SESSION_ID
  ostiara deny SESSION_ID
      Decide on a teammate's request. You can't decide on your own.
  ostiara broker [-addr :8080] [-kubeconfig path] [-tls-cert file -tls-key file] [-audit-log path] [-recordings-dir dir]
      Run the broker service (the only thing allowed to exec into pods).
  ostiara replay [-speed 1] [-o file] SESSION_ID|FILE.cast
      Play back what happened in a recorded session (needs permission to view recordings).
  ostiara doctor [-all] [-strict]
      Show who can still get around ostiara (RBAC, admission policy, platform), as an admin.
  ostiara audit check -k8s FILE -ostiara FILE
      Flag every pod exec/attach/port-forward that no ostiara approval explains.

Environment:
  OSTIARA_BROKER   broker URL (default http://localhost:8080)
  OSTIARA_CA       PEM file with the CA that signed the broker's certificate
  OSTIARA_USER     who you are (default $USER). DEV ONLY: not authenticated yet.
`

// exitCode passes the remote command's exit code through to our own exit.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit code %d", int(e)) }

func main() {
	err := run(os.Args[1:])
	if err == nil {
		return
	}
	var code exitCode
	if errors.As(err, &code) {
		os.Exit(int(code))
	}
	fmt.Fprintln(os.Stderr, "ostiara:", err)
	os.Exit(1)
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("missing command")
	}
	command, rest := args[0], args[1:]

	switch command {
	case "exec":
		return runExec(rest)
	case "port-forward":
		return runPortForward(rest)
	case "list":
		return runList(rest)
	case "approve":
		return runDecide(rest, true)
	case "deny":
		return runDecide(rest, false)
	case "broker":
		return runBroker(rest)
	case "audit":
		return runAudit(rest)
	case "doctor":
		return runDoctor(rest)
	case "replay":
		return runReplay(rest)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", command)
	}
}

// newClient builds a broker client from OSTIARA_BROKER, OSTIARA_CA, OSTIARA_USER and your kubeconfig token.
func newClient() (*client.Client, error) {
	broker := os.Getenv("OSTIARA_BROKER")
	if broker == "" {
		broker = "http://localhost:8080"
	}
	user := os.Getenv("OSTIARA_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	c := client.New(broker, user)
	if ca := os.Getenv("OSTIARA_CA"); ca != "" {
		if err := c.TrustCA(ca); err != nil {
			return nil, err
		}
	}
	token, err := kube.TokenSource("")
	if err != nil {
		c.Token = func(context.Context) (string, error) { return "", err }
	} else {
		c.Token = token
	}
	return c, nil
}
