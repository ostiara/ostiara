package kube

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// Forward connects conn to one port of a pod, until either side closes or ctx ends.
// Each call is one port-forward request to the API server, so each shows up in its audit log.
func Forward(ctx context.Context, clientset kubernetes.Interface, config *rest.Config, namespace, pod string, port int, conn io.ReadWriter) error {
	url := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(namespace).Name(pod).SubResource("portforward").URL()

	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)
	streams, _, err := dialer.Dial(portforward.PortForwardProtocolV1Name)
	if err != nil {
		return fmt.Errorf("port-forward %s/%s: %w", namespace, pod, err)
	}
	defer streams.Close()

	// The kubelet expects an error stream and a data stream per connection, tagged with the port.
	headers := http.Header{}
	headers.Set(corev1.StreamType, corev1.StreamTypeError)
	headers.Set(corev1.PortHeader, strconv.Itoa(port))
	headers.Set(corev1.PortForwardRequestIDHeader, "0")
	errorStream, err := streams.CreateStream(headers)
	if err != nil {
		return fmt.Errorf("port-forward error stream: %w", err)
	}
	errorStream.Close() // we only read from it

	headers.Set(corev1.StreamType, corev1.StreamTypeData)
	dataStream, err := streams.CreateStream(headers)
	if err != nil {
		return fmt.Errorf("port-forward data stream: %w", err)
	}
	defer dataStream.Reset()

	done := make(chan error, 3)
	go func() {
		if msg, _ := io.ReadAll(errorStream); len(msg) > 0 {
			done <- fmt.Errorf("port-forward %s/%s:%d: %s", namespace, pod, port, msg)
		}
	}()
	go func() { _, err := io.Copy(dataStream, conn); done <- err }() // client → pod
	go func() { _, err := io.Copy(conn, dataStream); done <- err }() // pod → client

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
