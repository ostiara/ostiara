# Audit and detection

ostiara keeps two records of every shell, and `ostiara audit check` compares them.

| Record | Written by | Tells you |
|---|---|---|
| ostiara audit log | the broker | who asked, who approved, which pod and command, exit code |
| Kubernetes API audit log | the API server | every exec, attach and port-forward actually opened, by anyone |

Kubernetes' record is the one an attacker can't edit through ostiara. If the broker's
token is stolen and used directly, the API server logs an exec that ostiara never approved.

## 1. The ostiara audit log

The broker writes one JSON object per line to stdout (or `-audit-log /path`), each tagged
`"stream":"ostiara.audit"`:

```json
{"stream":"ostiara.audit","time":"2026-11-28T12:03:40Z","event":"session.approved","session":"5d9ac7f9","actor":"bob","requester":"alice","approver":"bob","namespace":"demo","pod":"demo-pod","command":["sh"]}
```

Events: `session.requested`, `session.approved`, `session.denied`, `session.attached`,
`session.ended` (with `exitCode` and `duration`), and `session.refused` (someone tried to
approve their own session or use someone else's). Port-forward sessions add
`forward.opened` and `forward.closed` for every connection, with the `port`. If the broker
can't write `session.attached` or `forward.opened`, it refuses to open the connection.

**Ship it off the pod.** A log line that only lives in the broker pod can be lost on restart
or rewritten by whoever controls the broker. Have your log collector (Fluent Bit, Vector,
the cloud provider's agent) forward lines with `stream=ostiara.audit` to storage the broker
can't modify, such as a separate account or a bucket with object lock.

## 2. The Kubernetes audit log

Enable API auditing with the rules in [`deploy/audit-policy.yaml`](../deploy/audit-policy.yaml).
They record every exec, attach and port-forward, and every change to Roles and bindings.

- **kind:** `hack/kind-up.sh` creates a cluster with these rules (`WORKERS=2` adds worker
  nodes); read the log with `docker exec kind-control-plane cat /var/log/kubernetes/audit.log`.
- **Self-managed:** pass `--audit-policy-file` and `--audit-log-path` to kube-apiserver.
- **EKS:** turn on the `audit` control-plane log type; events land in CloudWatch Logs.
- **GKE:** Admin Activity audit logs are always on; exec appears as `io.k8s.core.v1.pods.exec.create`.
- **AKS:** enable the `kube-audit` diagnostic setting.

## 3. Check them against each other

```bash
kubectl -n ostiara-system logs deploy/ostiara-broker > ostiara-audit.log
ostiara audit check -k8s /var/log/kubernetes/audit.log -ostiara ostiara-audit.log
```

It reports two kinds of finding and exits with status 1 if there are any, so you can run it
from cron or CI and alert on failure:

- **`unapproved-broker-exec`**: the broker's identity opened a shell or port-forward with
  no matching `session.attached` or `forward.opened` for that pod within `-window`
  (default 10s). Treat it as a stolen broker token until proven otherwise.
- **`direct-access`**: someone other than the broker exec'd, attached or port-forwarded.
  That is either break-glass (below) or someone who still has rights they shouldn't.

Limits: the check trusts ostiara's own log for the approvals, so a fully compromised broker
process could forge matching lines. It catches the more likely case of the broker's token
being used from somewhere else. Shipping both logs off the cluster as they're written keeps
the evidence intact.

## 4. Break-glass

If the broker is down during an incident, an admin can allow direct exec for a short time.
With the admission policy on, that takes two steps: RBAC for the exec right
([`deploy/break-glass.yaml`](../deploy/break-glass.yaml) defines the role; nothing binds it),
and an exemption so the policy lets that user through.

```bash
kubectl apply -f deploy/break-glass.yaml
kubectl create rolebinding ostiara-break-glass-<you> -n <namespace> \
  --clusterrole=ostiara-break-glass --user=<you>
kubectl -n ostiara-system patch configmap ostiara-admission --type merge \
  -p '{"data":{"exemptUsers":"<you>"}}'
# ...fix the incident...
kubectl -n ostiara-system patch configmap ostiara-admission --type merge \
  -p '{"data":{"exemptUsers":""}}'
kubectl delete rolebinding ostiara-break-glass-<you> -n <namespace>
```

Every step is visible: the audit policy records changes to the binding and to the
`ostiara-admission` ConfigMap, each exec shows up as `direct-access` in `ostiara audit check`,
and `ostiara doctor` warns while the exemption is open. Agree up front who may break the
glass, and review every use afterwards.
