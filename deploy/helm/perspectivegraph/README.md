# PerspectiveGraph

PerspectiveGraph connects what the scanners you already run have found (Trivy, Semgrep,
Cloud Custodian, Falco, plus Kubernetes, IAM and cloud network data) into one graph of your
environment, and looks for the routes that matter: from the internet, through too much
privilege, to something valuable. It flags a route in the pull request that opens it, and
can open a second pull request with the fix.

**Want to look around before installing?** There is a read-only live demo with sample
data, no signup needed: [demo.a3thinker.it](https://demo.a3thinker.it).

This chart installs the whole thing: the Go backend (GraphQL API and ingest endpoint), the
dashboard behind nginx and, unless you bring your own, PostgreSQL with
[Apache AGE](https://age.apache.org/) and a NATS broker.

## Install

```console
helm install perspectivegraph oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  --namespace perspectivegraph --create-namespace
```

The chart and the images are signed with cosign. To check the chart's signature before
installing:

```console
cosign verify ghcr.io/luiacuaniello/charts/perspectivegraph:<version> \
  --certificate-identity-regexp 'https://github.com/luiacuaniello/perspectivegraph/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Then open the dashboard at http://localhost:8080:

```console
kubectl -n perspectivegraph port-forward \
  svc/$(kubectl -n perspectivegraph get svc -l app.kubernetes.io/component=frontend \
        -o jsonpath='{.items[0].metadata.name}') 8080:80
```

The service name depends on the release name, which is why the command looks it up.

A new install starts empty: the graph fills up as scanner output reaches the ingest
endpoint. The
[manual](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/MANUAL.md#1-the-order-that-builds-a-correct-graph)
shows what to send, and in which order.

## Requirements

Kubernetes 1.21 or newer, and a default StorageClass, because the bundled database keeps
its data on a 5 GiB volume. That's all. The backend creates and upgrades its own database
schema when it starts, so moving between versions needs no migration step.

On every change, CI installs the chart with its default values on kind, with Kubernetes
1.33 and 1.36. Older versions down to 1.21 should work, since the chart only uses APIs that
have been stable for years, but they aren't tested.

## Trying it out, or running it for real

The default values are there to try it out: everything runs inside the cluster and there's
no authentication. That's fine on a laptop or in a test cluster, not with real data.

Two more values files come with the chart:

- **`values-production.yaml`** connects to your own PostgreSQL+AGE over a verified TLS
  connection and requires authentication (the backend won't start without it). It reads
  secrets from a Secret you manage, keeps the audit log and the triage data on a persistent
  volume, terminates TLS at the ingress, moves `/metrics` to a local-only listener and sets
  resource requests and limits.
- **`values-ha.yaml`** goes on top of the production file: three backend replicas and two
  dashboard ones spread across nodes, a disruption budget, the audit log and triage data
  moved into PostgreSQL, and an external NATS.

```console
helm pull oci://ghcr.io/luiacuaniello/charts/perspectivegraph --untar
helm install perspectivegraph ./perspectivegraph \
  -f perspectivegraph/values-production.yaml \
  --set postgres.externalHost=db.internal --set ingress.host=pg.example.com
```

Create the Secret first: the production file lists the keys it expects.

## The values to read first

| Key | Default | What it does |
|---|---|---|
| `auth.apiTokens` / `auth.oidc` | empty | Authentication stays off until you set one of them. Without it, anyone who can reach the service can read your attack paths. |
| `auth.anonymousRole` | empty | `viewer` publishes the install read-only, like the live demo: visitors can look around and every change is refused. Set `backend.trustedProxyCidrs` to your ingress controller's pod network as well, so rate limits apply to each visitor rather than to all of them at once. |
| `postgres.enabled` | `true` | The bundled database, meant for trying things out. In production, set it to `false` and point `postgres.externalHost` (or `postgres.dsn`) at your own PostgreSQL+AGE. |
| `governanceBackend` | `file` | Where triage decisions, tickets, validation verdicts and the audit log are kept. `postgres` is what makes more than one backend replica possible. |
| `persistence.enabled` | `false` | A volume for the `file` backend, so that data survives restarts. It supports a single replica, and the chart won't render it with more. |
| `backend.replicas` | `1` | More than one needs `governanceBackend: postgres`. |
| `repoAllowlist` | empty | The repositories the engine may write to: PR comments, merge-gate statuses and fix PRs. Empty means none. |
| `ingress.enabled` | `false` | Publishes the dashboard, the API and the ingest endpoint. The chart won't render it without authentication, unless you set `ingress.allowUnauthenticated: true`. |
| `service.type` | `ClusterIP` | `LoadBalancer` or `NodePort` expose the backend outside the cluster, with the same authentication check as the ingress. |
| `ai.apiKey` | empty | Turns on the AI assistant through Anthropic's API (`ai.hf` takes an OpenAI-compatible endpoint instead). Once it's on, details of your attack paths are sent to that provider. |

`helm show values oci://ghcr.io/luiacuaniello/charts/perspectivegraph` prints every value,
each with a comment explaining it.

## Hardening

- Every pod, init containers included, meets the `restricted` Pod Security Standard, and CI
  checks it on every change.
- The backend and the dashboard run as non-root users on a read-only filesystem, with all
  Linux capabilities dropped. The backend image is distroless and has no shell.
- Every release ships with an SPDX SBOM and SLSA build provenance, and the chart and the
  images are signed.
- The audit log is a hash chain, so any edit to past records shows.

The [threat model](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/THREAT-MODEL.md)
explains what isn't covered and what's left to you as the operator.

## Documentation

- [Operations runbook](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/OPERATIONS.md): where to get PostgreSQL+AGE, backups and restores, upgrades, the production checklist
- [Manual](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/MANUAL.md): architecture, scoring, what to send and how
- [Scale](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/SCALE.md): measured sizing, and how to measure your own graph
- [Upgrade notes](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/UPGRADING.md): the releases that need something from you
- [Support policy](https://github.com/luiacuaniello/perspectivegraph/blob/main/SUPPORT.md): which versions get fixes, and how quickly

Apache-2.0. Issues and pull requests are welcome on
[GitHub](https://github.com/luiacuaniello/perspectivegraph).
