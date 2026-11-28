<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/ostiara-mark-dark.svg">
    <img src="assets/logo/ostiara-mark.svg" alt="ostiara" width="96">
  </picture>
</p>

<h1 align="center">ostiara</h1>

<p align="center"><em>The doorkeeper for your Kubernetes pods.</em></p>

Gated, approval-based access to Kubernetes pods: an open-source alternative to `kubectl exec`.
Nobody gets a shell until a teammate lets them in.

> **Why the name?** An *ostiarius* (English: *ostiary*) was the doorkeeper who decided
> who could enter. ostiara does the same for your pods.

```
alice: ostiara exec demo-pod ──► broker: session 2cd09933 pending
bob:   ostiara approve 2cd09933 ──► broker: approved (alice may connect once, within 5 min)
alice's CLI ⇄ WebSocket ⇄ broker ⇄ exec stream ⇄ container
```

## Roadmap
1. ✅ `exec` streams a shell into a pod, like `kubectl exec`.
2. ✅ **Broker**: holds the only `pods/exec` permission; sessions need a teammate's
   approval; one approval = one connection; requests and approvals expire; audit log.
3. ✅ **Real identity**: the broker checks each caller's Kubernetes token (TokenReview),
   so EKS/GKE/OIDC/ServiceAccount logins all work; developers get a role without `pods/exec`.
4. ✅ **Port-forward**: `ostiara port-forward` reaches one pod port after a teammate
   approves, for a time window (default 15m, max 1h); every connection is logged.
5. 🚧 **Slack / Teams**: ✅ notifications of requests and decisions; next, routing to the
   pod's owning team, and approve buttons that still require the approver's cluster login.
6. ✅ **No way around it**: an admission policy blocks direct exec, attach, port-forward and
   `kubectl debug` in protected namespaces, whatever RBAC or cloud IAM allows; `ostiara doctor`
   shows who can still read Secrets, change workloads or escalate.
7. ✅ **Session recording**: every shell's output is saved as an asciicast file, its sha256
   goes in the audit log, and `ostiara replay` plays it back for people RBAC allows.
8. ✅ **Predefined actions**: `ostiara run POD ps` runs a shell-free command from a catalog
   your team controls; low-risk ones need no approval, and `env` hides secret values.
9. ✅ **Approval rules**: per namespace, who may approve, how many approvers (e.g. two SREs
   for prod), a required ticket, shorter port-forwards, approver sign-in requirements such as
   MFA, and a solo on-call mode that's flagged for review.
10. Persistent session storage, HA broker.

## Layout
```
cmd/ostiara/              the one binary
  main.go                 picks the subcommand
  cmd_exec.go             request → wait for approval → connect
  cmd_review.go           list / approve / deny
  cmd_broker.go           runs the broker HTTP server
  terminal.go             raw terminal ⇄ WebSocket
internal/api/             JSON types shared by CLI and broker
internal/wire/            framing for the live session WebSocket
internal/broker/          session store (rules), HTTP API, exec proxy
internal/audit/           audit events, and the check against Kubernetes audit logs
internal/doctor/          finds RBAC and setup that get around ostiara
internal/recording/       records shell sessions as asciicast files
internal/actions/         predefined actions and output redaction
internal/policy/          approval rules: who, how many, tickets, solo on-call
internal/notify/          Slack and Teams messages about requests and decisions
internal/client/          the CLI's HTTP client for the broker
internal/kube/            Kubernetes client + exec stream
deploy/broker.yaml        in-cluster broker: ServiceAccount, RBAC, Deployment, NetworkPolicy
deploy/broker-namespace.yaml  lets the broker exec in one namespace (copy per namespace)
deploy/audit-policy.yaml  Kubernetes audit rules for pod access and RBAC changes
deploy/break-glass.yaml   emergency exec role, bound only during an incident
deploy/admission-policy.yaml  blocks direct pod access except through the broker
deploy/recordings-viewer.yaml who may watch session recordings
deploy/actions.yaml       the catalog of predefined actions
deploy/policy.yaml        approval rules per namespace
docs/audit.md             audit logs, `ostiara audit check`, break-glass
deploy/dev-role.yaml      developer role: see pods and logs, no exec
testdata/demo-pod.yaml    a busybox pod to practise against
testdata/demo-web.yaml    a tiny web server on port 8080, for port-forward
testdata/demo-users.yaml  alice and bob as ServiceAccounts, for trying real identity
hack/demo-kubeconfig.sh   writes a kubeconfig that logs in as alice or bob
hack/broker-cert.sh       dev-only CA and broker certificate, as Secret ostiara-broker-tls
hack/kind-up.sh           kind cluster with Kubernetes API auditing turned on
```

## How callers are identified
The CLI sends the same bearer token kubectl would (from your kubeconfig, including
exec plugins such as `aws eks get-token`). The broker asks Kubernetes who it belongs to,
so nobody can claim to be someone else. The token is only sent over https, or plain
http to localhost (e.g. `kubectl port-forward`).

Serve the broker over HTTPS with `-tls-cert` and `-tls-key` (PEM files). Without them
it serves plain HTTP and logs a warning, because tokens would cross the network unencrypted.
If the broker's certificate comes from your own CA, point the CLI at it with
`OSTIARA_CA=/path/to/ca.pem`; the CLI then trusts only that CA for the broker.
`deploy/broker.yaml` reads the certificate from Secret `ostiara-broker-tls`
(keys `tls.crt` and `tls.key`), so the broker won't start until it exists. In a real
cluster, issue it with your own CA or cert-manager.

With `-token-audience ostiara`, the broker only accepts tokens issued for ostiara
(e.g. `kubectl create token <sa> --audience ostiara`). Such a token is rejected by the
API server itself, so even a compromised broker can't reuse it. It's off by default
because cloud logins (EKS, GKE, AKS with Entra ID) issue tokens for the API server, not for ostiara.

**On AKS**, two settings can bypass ostiara entirely. Disable local accounts
(`--disable-local-accounts`): otherwise `az aks get-credentials --admin` hands out a
certificate login with full exec rights. And if the cluster uses Azure RBAC for Kubernetes,
give developers an Azure role without exec (e.g. *Azure Kubernetes Service RBAC Reader*),
because Azure role assignments decide who can exec there, not `deploy/dev-role.yaml`.

For quick local hacking, `ostiara broker -auth header` trusts `OSTIARA_USER` instead.
Since anyone could claim any name, it only listens on this machine (`-addr 127.0.0.1:8080`)
and refuses to start inside a cluster.

## No way around it
RBAC only ever adds permissions, so ostiara can't take exec away from anyone who has it
through another role, such as Kubernetes' built-in `edit` or `admin`, or a cloud IAM role.
An admission policy can: [`deploy/admission-policy.yaml`](deploy/admission-policy.yaml)
refuses direct exec, attach, port-forward and `kubectl debug` in every namespace labelled
`ostiara.io/enforce=true`, for everyone except the broker, cluster admins included.
```bash
kubectl apply -f deploy/admission-policy.yaml       # needs Kubernetes 1.30+
kubectl label namespace payments ostiara.io/enforce=true
```
Set `validationActions: [Warn, Audit]` in the binding first to see who would be blocked
without blocking anyone. If its ConfigMap `ostiara-admission` goes missing, the policy
blocks everyone, the broker included, rather than no one. Break-glass users and groups go
in that ConfigMap (see [docs/audit.md](docs/audit.md)).

The policy only covers getting into pods. `ostiara doctor` lists, from RBAC, who can still
**read Secrets**, **create or change workloads** (which can mount Secrets or run any
command), or **grant themselves more**, and checks the policy is installed, blocking and
covering every namespace the broker serves. Run it as an admin; `-strict` makes it exit 1
for CI. It can't see cloud IAM (GKE IAM roles, EKS access entries, Azure RBAC), so it reminds
you which to check on that platform.

## Which namespaces the broker can reach
The broker can only exec in namespaces you opt in. Cluster-wide it may just check
tokens, so a compromised broker can't open a shell everywhere. To add a namespace:
```bash
kubectl create rolebinding ostiara-broker -n <namespace> \
  --clusterrole=ostiara-broker-exec --serviceaccount=ostiara-system:ostiara-broker
```

## Port-forward
`kubectl port-forward` reaches any port on a pod and isn't covered by NetworkPolicy, so the
developer role doesn't have it. Ask ostiara instead:
```bash
ostiara port-forward -n demo -for 30m -reason "check the queue" db-0 15432:5432
# once a teammate approves: localhost:15432 → demo/db-0:5432 until the window ends
```
The approver sees the pod, port and window. Any number of connections may use one approval,
each logged as `forward.opened` / `forward.closed`; when the window ends, open connections
are cut. The local end only listens on 127.0.0.1.

## Approval rules
Without rules, a session needs one approval from anyone but the requester.
[`deploy/policy.yaml`](deploy/policy.yaml) sets rules per namespace (glob patterns; the first
match wins):

| Rule | What it does |
|---|---|
| `approvals: 2` | needs that many different approvers; one denial ends the request |
| `approverUsers` / `approverGroups` | only they may approve or deny here |
| `requireTicket` | `-reason` must mention a ticket or incident (`INC-123`, a link, or your `ticketPattern`) |
| `maxWindow: 30m` | caps port-forwards here |
| `approverExtra` | the approver's login must carry these values, e.g. an `amr` claim your OIDC setup maps through so only a recent MFA sign-in can approve |
| `selfApproval` | solo on-call: you may approve yourself, with a ticket. Chat gets a 🚨 alert and `ostiara audit check` lists it for review |

`ostiara list` shows progress (`pending 1/2`). Predefined actions marked `approval: auto` skip
these rules; limit those actions' namespaces in the catalog if a namespace should have none.

## Predefined actions
Most of the time you open a shell to look at the same few things. Predefined actions run
those directly, with no shell, from a catalog your team controls
([`deploy/actions.yaml`](deploy/actions.yaml); without it the broker offers `ps`, `df` and `env`):
```bash
ostiara actions -n payments          # what can I run here?
ostiara run -n payments api-7f9c ps  # no approval needed, still audited and recorded
ostiara run -n payments api-7f9c env # waits for a teammate; secret values are hidden
```
Each action has `approval: auto` or `required`. Auto actions skip the teammate, so the broker
first checks with Kubernetes that you can at least `get pods` in that namespace, and records
the approver as `ostiara:auto`. The catalog decides the command; callers can only pick a
name. With `redact: env`, the broker hides the value of any `KEY=VALUE` line whose key looks
secret (password, token, key, …) and any password inside a URL, before the output reaches your
screen or the recording. Redaction works by pattern, so keep sensitive actions on `required`.

## Session recording
The broker records what every exec session prints into the `ostiara-recordings` volume, as
[asciicast](https://docs.asciinema.org/manual/asciicast/v2/) files. If it can't start a
recording, it refuses the session. Keystrokes are left out unless you add `-record-input`,
because they can include passwords typed at prompts that don't echo. Each `session.ended`
audit event carries the recording's size and sha256, so a recording that was changed later
won't match the log you shipped off the cluster.

Watching one needs RBAC verb `get` on `sessions/recording` in API group `ostiara.io`. Cluster
admins have it; grant others the `ostiara-recordings-viewer` ClusterRole:
```bash
kubectl apply -f deploy/recordings-viewer.yaml
kubectl create clusterrolebinding ostiara-recordings-viewer-security \
  --clusterrole=ostiara-recordings-viewer --group=security
ostiara replay 2cd09933                 # play it in your terminal
ostiara replay -o 2cd09933.cast 2cd09933  # or save it (asciinema play works too)
```
Every view, and every refused attempt, is in the audit log. Recordings hold whatever was on
screen, secrets included, so keep the viewer role small. Port-forward connections aren't
recorded, but each `forward.closed` event counts the bytes sent each way.

## Chat notifications
The broker can post every request, approval and denial to Slack and/or Microsoft Teams, with
the pod, the access asked for, the reason and the `ostiara approve` command to run. Chat only
announces: approving still happens in the CLI, checked against the approver's Kubernetes
identity, so a hijacked chat account can't approve anything.
```bash
kubectl -n ostiara-system create secret generic ostiara-notify \
  --from-literal=slack-webhook-url=https://hooks.slack.com/services/... \
  --from-literal=teams-webhook-url=https://...   # a Teams Workflows webhook; either key is optional
kubectl -n ostiara-system rollout restart deploy/ostiara-broker
```
Messages are sent in the background, so a slow or broken chat service never holds up a
request, and webhook URLs never appear in logs. For a busy or broad channel, run the broker
with `-notify-detail minimal`: messages then say who asked, for which namespace and kind of
access, and how to approve, but leave out pod names, commands and reasons. The NetworkPolicy above only limits traffic
into the broker, so outgoing webhook calls work.

## Audit and detection
The broker writes every request, approval, attach and exit as JSON lines
(`"stream":"ostiara.audit"`), each chained to the one before by a hash or, with a key, an
HMAC; `ostiara audit verify` shows if any line was changed, removed or reordered. `ostiara audit check` compares them with the Kubernetes API
audit log and flags any pod exec, attach or port-forward that no approval explains.
See [docs/audit.md](docs/audit.md), including the break-glass procedure.

## Who can reach the broker
A NetworkPolicy in `deploy/broker.yaml` blocks all in-cluster traffic to the broker,
except from namespaces you label (for example your ingress controller's).
Admins can still reach it with `kubectl port-forward`, which NetworkPolicy doesn't
cover; the developer role has no port-forward rights. This needs a network plugin
that enforces NetworkPolicy (kind's default does; so do Calico and Cilium).
```bash
kubectl label namespace <namespace> ostiara.io/broker-access=true
```

## Images and signatures
Pushing a `v*` tag runs `.github/workflows/release.yml`: it builds `linux/amd64` and
`linux/arm64` images, pushes them to `ghcr.io/ostiara/ostiara` with an SBOM and build
provenance, and signs them with cosign using GitHub's OIDC identity (no keys to leak).
Check an image before you run it, and deploy it by digest:
```bash
cosign verify ghcr.io/ostiara/ostiara:<version> \
  --certificate-identity-regexp '^https://github.com/ostiara/ostiara/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
Base images are pinned by digest, and Dependabot proposes updates to them, to Go modules
and to GitHub Actions every week.

## Try it locally (dev mode)
```bash
go build -o bin/ostiara ./cmd/ostiara
kubectl apply -f testdata/demo-pod.yaml

# terminal 1: the broker, trusting OSTIARA_USER
./bin/ostiara broker -auth header -addr 127.0.0.1:8080

# terminal 2: alice asks for access
OSTIARA_USER=alice ./bin/ostiara exec -n demo -reason "debugging" demo-pod

# terminal 3: bob reviews and approves
OSTIARA_USER=bob ./bin/ostiara list
OSTIARA_USER=bob ./bin/ostiara approve <ID>
```

## Run it in the cluster with real identity (kind)
```bash
hack/kind-up.sh            # kind cluster with Kubernetes API auditing on (WORKERS=2 for workers)
docker build -t ostiara:dev .
kind load docker-image ostiara:dev
kubectl apply -f testdata/demo-pod.yaml -f testdata/demo-users.yaml -f testdata/demo-web.yaml
hack/broker-cert.sh        # throwaway CA + broker certificate, stored as a Secret
kubectl apply -f deploy/broker.yaml -f deploy/broker-namespace.yaml -f deploy/dev-role.yaml
kubectl apply -f deploy/admission-policy.yaml && kubectl label namespace demo ostiara.io/enforce=true
ostiara doctor             # as the admin: what can still get around ostiara?
kubectl -n ostiara-system port-forward svc/ostiara-broker 8080:8080

# the broker speaks HTTPS; trust the dev CA
export OSTIARA_BROKER=https://localhost:8080 OSTIARA_CA=bin/tls/ca.crt

# alice and bob each get a kubeconfig with a 1h token that only ostiara accepts
hack/demo-kubeconfig.sh alice
hack/demo-kubeconfig.sh bob

# the API server itself refuses those tokens...
KUBECONFIG=bin/kubeconfig-alice kubectl get pods -n demo    # Unauthorized
# ...and alice's role has no pods/exec anyway
kubectl auth can-i create pods --subresource=exec -n demo --as=system:serviceaccount:demo:alice    # no
# ...so she asks, and bob approves
KUBECONFIG=bin/kubeconfig-alice ./bin/ostiara exec -n demo demo-pod
KUBECONFIG=bin/kubeconfig-bob ./bin/ostiara list
KUBECONFIG=bin/kubeconfig-bob ./bin/ostiara approve <ID>
```

## Tests
```bash
go test ./...          # session rules, authentication, token handling, ...
go test -race ./...    # also check for data races
```

## License
[Apache 2.0](LICENSE)
