// Package kube talks to the Kubernetes API.
package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient loads kubeconfig like kubectl does ($KUBECONFIG, ~/.kube/config, or in-cluster).
func NewClient(kubeconfigPath string) (*kubernetes.Clientset, *rest.Config, error) {
	config, err := loadConfig(kubeconfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("loading kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("creating kubernetes client: %w", err)
	}
	return clientset, config, nil
}

func loadConfig(kubeconfigPath string) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}
