package kube

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// writeKubeconfig writes a one-context kubeconfig for the given user and returns its path.
func writeKubeconfig(t *testing.T, user *clientcmdapi.AuthInfo) string {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["c"] = &clientcmdapi.Cluster{Server: "https://example.invalid"}
	cfg.AuthInfos["u"] = user
	cfg.Contexts["ctx"] = &clientcmdapi.Context{Cluster: "c", AuthInfo: "u"}
	cfg.CurrentContext = "ctx"
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokenSource(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		user *clientcmdapi.AuthInfo
		want string
	}{
		{"inline token", &clientcmdapi.AuthInfo{Token: "abc123"}, "abc123"},
		{"token file", &clientcmdapi.AuthInfo{TokenFile: tokenFile}, "from-file"},
		{"client certs only", &clientcmdapi.AuthInfo{ClientCertificateData: []byte("x"), ClientKeyData: []byte("y")}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source, err := TokenSource(writeKubeconfig(t, tc.user))
			if err != nil {
				t.Fatal(err)
			}
			got, err := source(context.Background())
			if err != nil || got != tc.want {
				t.Fatalf("got (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
}

func TestTokenSourceNoKubeconfig(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	source, err := TokenSource("")
	if err != nil || source != nil {
		t.Fatalf("got (%v, %v), want (nil, nil)", source != nil, err)
	}
}
