package kube

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// Target is the container and command to run.
type Target struct {
	Namespace string
	Pod       string
	Container string
	Command   []string
	TTY       bool
}

// Streams are where input comes from and output goes.
type Streams struct {
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer // must be nil when TTY is true
	SizeQueue remotecommand.TerminalSizeQueue
}

// Stream runs a command in a container until it exits or ctx is cancelled.
// A non-zero exit returns an error satisfying util/exec.ExitError.
func Stream(ctx context.Context, clientset kubernetes.Interface, config *rest.Config, t Target, s Streams) error {
	req := clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Namespace(t.Namespace).
		Name(t.Pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: t.Container,
			Command:   t.Command,
			Stdin:     s.Stdin != nil,
			Stdout:    true,
			Stderr:    !t.TTY,
			TTY:       t.TTY,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("creating executor: %w", err)
	}

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             s.Stdin,
		Stdout:            s.Stdout,
		Stderr:            s.Stderr,
		Tty:               t.TTY,
		TerminalSizeQueue: s.SizeQueue,
	})
	if err != nil {
		return fmt.Errorf("exec %s/%s: %w", t.Namespace, t.Pod, err)
	}
	return nil
}
