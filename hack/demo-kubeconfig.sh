#!/usr/bin/env bash
# Writes a kubeconfig that logs in only as a demo ServiceAccount: hack/demo-kubeconfig.sh alice
set -euo pipefail

user="${1:?usage: $0 <alice|bob> [output-file]}"
out="${2:-bin/kubeconfig-$user}"

server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
ca="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
token="$(kubectl create token "$user" -n demo --duration 1h)"

mkdir -p "$(dirname "$out")"
umask 077
cat > "$out" <<KUBECONFIG
apiVersion: v1
kind: Config
clusters:
  - name: demo
    cluster:
      server: $server
      certificate-authority-data: $ca
users:
  - name: $user
    user:
      token: $token
contexts:
  - name: $user
    context: { cluster: demo, user: $user, namespace: demo }
current-context: $user
KUBECONFIG
echo "$out"
