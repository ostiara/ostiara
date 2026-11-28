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
4. Slack / Teams approvals, routed to the pod's owning team.
5. Read-only actions without approval (logs, env, ps), each logged.
6. Session recording, persistent storage, HA broker.

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
internal/client/          the CLI's HTTP client for the broker
internal/kube/            Kubernetes client + exec stream
deploy/broker.yaml        in-cluster broker: ServiceAccount, RBAC, Deployment
deploy/broker-namespace.yaml  lets the broker exec in one namespace (copy per namespace)
deploy/dev-role.yaml      developer role: see pods and logs, no exec
testdata/demo-pod.yaml    a busybox pod to practise against
testdata/demo-users.yaml  alice and bob as ServiceAccounts, for trying real identity
hack/demo-kubeconfig.sh   writes a kubeconfig that logs in as alice or bob
hack/broker-cert.sh       dev-only CA and broker certificate, as Secret ostiara-broker-tls
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

For quick local hacking, `ostiara broker -auth header` trusts `OSTIARA_USER` instead.
Never use it in a shared cluster.

## Which namespaces the broker can reach
The broker can only exec in namespaces you opt in. Cluster-wide it may just check
tokens, so a compromised broker can't open a shell everywhere. To add a namespace:
```bash
kubectl create rolebinding ostiara-broker -n <namespace> \
  --clusterrole=ostiara-broker-exec --serviceaccount=ostiara-system:ostiara-broker
```

## Try it locally (dev mode)
```bash
go build -o bin/ostiara ./cmd/ostiara
kubectl apply -f testdata/demo-pod.yaml

# terminal 1: the broker, trusting OSTIARA_USER
./bin/ostiara broker -auth header

# terminal 2: alice asks for access
OSTIARA_USER=alice ./bin/ostiara exec -n demo -reason "debugging" demo-pod

# terminal 3: bob reviews and approves
OSTIARA_USER=bob ./bin/ostiara list
OSTIARA_USER=bob ./bin/ostiara approve <ID>
```

## Run it in the cluster with real identity (kind)
```bash
docker build -t ostiara:dev .
kind load docker-image ostiara:dev
kubectl apply -f testdata/demo-pod.yaml -f testdata/demo-users.yaml
hack/broker-cert.sh        # throwaway CA + broker certificate, stored as a Secret
kubectl apply -f deploy/broker.yaml -f deploy/broker-namespace.yaml -f deploy/dev-role.yaml
kubectl -n ostiara-system port-forward svc/ostiara-broker 8080:8080

# the broker speaks HTTPS; trust the dev CA
export OSTIARA_BROKER=https://localhost:8080 OSTIARA_CA=bin/tls/ca.crt

# alice and bob each get a kubeconfig with only their own token (valid 1h)
hack/demo-kubeconfig.sh alice
hack/demo-kubeconfig.sh bob

# alice can't exec directly...
KUBECONFIG=bin/kubeconfig-alice kubectl exec demo-pod -- sh    # forbidden
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
