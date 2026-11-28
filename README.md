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
6. Read-only actions without approval (logs, env, ps), each logged.
7. Session recording, persistent storage, HA broker.

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
internal/notify/          Slack and Teams messages about requests and decisions
internal/client/          the CLI's HTTP client for the broker
internal/kube/            Kubernetes client + exec stream
deploy/broker.yaml        in-cluster broker: ServiceAccount, RBAC, Deployment, NetworkPolicy
deploy/broker-namespace.yaml  lets the broker exec in one namespace (copy per namespace)
deploy/audit-policy.yaml  Kubernetes audit rules for pod access and RBAC changes
deploy/break-glass.yaml   emergency exec role, bound only during an incident
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
request, and webhook URLs never appear in logs. The NetworkPolicy above only limits traffic
into the broker, so outgoing webhook calls work.

## Audit and detection
The broker writes every request, approval, attach and exit as JSON lines
(`"stream":"ostiara.audit"`). `ostiara audit check` compares them with the Kubernetes API
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
