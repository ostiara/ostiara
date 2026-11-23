# ostiara

*The doorkeeper for your Kubernetes pods.*

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
3. **Real identity** ⚠️: today the user name is self-declared (`OSTIARA_USER`). Next:
   verify users via Kubernetes TokenReview / OIDC, and remove `pods/exec` from everyone else.
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
testdata/demo-pod.yaml    a busybox pod to practise against
```

## Try it locally
```bash
go build -o bin/ostiara ./cmd/ostiara
kubectl apply -f testdata/demo-pod.yaml

# terminal 1: the broker (uses your kubeconfig)
./bin/ostiara broker

# terminal 2: alice asks for access
OSTIARA_USER=alice ./bin/ostiara exec -n demo -reason "debugging" demo-pod

# terminal 3: bob reviews and approves
OSTIARA_USER=bob ./bin/ostiara list
OSTIARA_USER=bob ./bin/ostiara approve <ID>
```

## Run the broker in the cluster (kind)
```bash
docker build -t ostiara:dev .
kind load docker-image ostiara:dev
kubectl apply -f deploy/broker.yaml
kubectl -n ostiara-system port-forward svc/ostiara-broker 8080:8080
```

## Tests
```bash
go test ./...          # session rules: self-approval, one-time use, expiry, ...
go test -race ./...    # also check for data races
```

## License
[Apache 2.0](LICENSE)
