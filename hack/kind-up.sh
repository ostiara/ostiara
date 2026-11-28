#!/usr/bin/env bash
# Creates a kind cluster with Kubernetes API auditing (deploy/audit-policy.yaml): hack/kind-up.sh [name]
# WORKERS=n adds worker nodes; KIND_IMAGE picks the node image.
# The audit log is then at /var/log/kubernetes/audit.log inside the <name>-control-plane container.
set -euo pipefail

name="${1:-kind}"
policy_dir="$(cd "$(dirname "$0")/../deploy" && pwd)"
config="$(mktemp)"
trap 'rm -f "$config"' EXIT

cat > "$config" <<CONFIG
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $policy_dir
        containerPath: /etc/kubernetes/policies
        readOnly: true
    kubeadmConfigPatches:
      - |
        apiVersion: kubeadm.k8s.io/v1beta4
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            - name: audit-policy-file
              value: /etc/kubernetes/policies/audit-policy.yaml
            - name: audit-log-path
              value: /var/log/kubernetes/audit.log
          extraVolumes:
            - name: audit-policies
              hostPath: /etc/kubernetes/policies
              mountPath: /etc/kubernetes/policies
              readOnly: true
              pathType: Directory
            - name: audit-logs
              hostPath: /var/log/kubernetes
              mountPath: /var/log/kubernetes
              pathType: DirectoryOrCreate
CONFIG
for _ in $(seq 1 "${WORKERS:-0}"); do
  echo "  - role: worker" >> "$config"
done

kind create cluster --name "$name" --config "$config" ${KIND_IMAGE:+--image "$KIND_IMAGE"}
echo "API audit log: docker exec $name-control-plane cat /var/log/kubernetes/audit.log"
