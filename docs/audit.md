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
`session.ended` (with `exitCode` and `duration`; sessions started with `ostiara run` also carry
`action`, and auto-approved ones show the approver `ostiara:auto`), `session.approval_added` (one of several
approvals a rule asks for; events carry `approvers` and `requiredApprovals`), and `session.refused` (someone tried to
approve their own session or use someone else's, or to view a recording without permission). Port-forward sessions add
`forward.opened` and `forward.closed` for every connection, with the `port` and, on close,
`bytesIn` and `bytesOut`. When sessions are recorded, `session.ended` carries
`recording: {file, bytes, sha256, truncated}`, and every view of one is a `recording.viewed`
event. If the broker
can't write `session.attached` or `forward.opened`, it refuses to open the connection.

**Ship it off the pod.** A log line that only lives in the broker pod can be lost on restart
or rewritten by whoever controls the broker. Have your log collector (Fluent Bit, Vector,
the cloud provider's agent) forward lines with `stream=ostiara.audit` to storage the broker
can't modify, such as a separate account or a bucket with object lock.

**Every line is chained.** Each event carries a `chain` id (one per broker run), a `seq`
number and the hash of the line before it (`prev`), and starts with its own `hash`. That makes
an edited, removed or reordered line visible:

```bash
ostiara audit verify ostiara-audit.log
# ✅ chain 3f9a1c2b7d0e: seq 1 to 214, intact
```

With a plain hash, anyone rewriting the log could recompute every hash, so for stronger
protection give the broker a key and it signs each line (HMAC-SHA256) instead. Keep the key
away from wherever the log is stored, and pass the same key to `verify`:

```bash
kubectl -n ostiara-system create secret generic ostiara-audit-key --from-literal=key="$(openssl rand -hex 32)"
kubectl -n ostiara-system rollout restart deploy/ostiara-broker
OSTIARA_AUDIT_KEY=... ostiara audit verify ostiara-audit.log
```

A cut-off end can't be seen from one file alone: compare the last `seq` with your shipped copy.

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

`-k8s` takes the audit log as each platform exports it, and detects which it is:

```bash
# GKE: Cloud Audit Logs
gcloud logging read 'protoPayload.methodName=~"io.k8s.core.v1.pods.(exec|attach|portforward)"' \
  --freshness=1d --format=json > k8s-audit.json
# EKS: CloudWatch Logs
aws logs filter-log-events --log-group-name /aws/eks/<cluster>/cluster \
  --log-stream-name-prefix kube-apiserver-audit > k8s-audit.json
```

(The GKE and EKS formats are tested against their documented shapes, not yet on live clusters.)
Add `-notify` to also post a one-line summary of the findings to the Slack or Teams webhooks in
`OSTIARA_SLACK_WEBHOOK_URL` / `OSTIARA_TEAMS_WEBHOOK_URL`, for example from a nightly job.

It reports two kinds of finding and exits with status 1 if there are any, so you can run it
from cron or CI and alert on failure:

- **`unapproved-broker-exec`**: the broker's identity opened a shell or port-forward with
  no matching `session.attached` or `forward.opened` for that pod within `-window`
  (default 10s). Treat it as a stolen broker token until proven otherwise.
- **`self-approved`**: someone approved their own session where a rule allows solo on-call.
  Nothing went wrong, but each one deserves a look afterwards.
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
