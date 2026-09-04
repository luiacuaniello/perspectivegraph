# PerspectiveGraph

Finds the reachable paths from internet exposure, through excessive privilege, to a
sensitive asset - by correlating the scanners you already run into one live graph of your
environment. It flags those paths in the pull request that opens them and can ship the fix
as a pull request of its own.

This chart installs the engine: a Go backend (GraphQL API + ingest endpoint), the React
dashboard behind nginx, and - unless you point it at your own - a bundled PostgreSQL with
[Apache AGE](https://age.apache.org/) and a NATS broker.

## Install

```console
helm install perspectivegraph oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  --namespace perspectivegraph --create-namespace
```

The chart and both images are **signed with cosign** (keyless, by digest). Verify before
you install:

```console
cosign verify ghcr.io/luiacuaniello/charts/perspectivegraph:<version> \
  --certificate-identity-regexp 'https://github.com/luiacuaniello/perspectivegraph/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Then open the dashboard:

```console
kubectl -n perspectivegraph port-forward \
  svc/$(kubectl -n perspectivegraph get svc -l app.kubernetes.io/component=frontend \
        -o jsonpath='{.items[0].metadata.name}') 8080:80
```

(The service name is derived from the release name, so a selector beats hard-coding it.)

## Requirements

Kubernetes **1.21+**. Nothing else: the chart brings its own database and broker by
default, and the backend creates and upgrades its own schema at start-up - there is no
migration step between versions.

## Two profiles, and which one you want

The defaults are a **demo**: everything in-cluster, no auth, an ephemeral database. They
exist so `helm install` shows you something in a minute, and they are not what you run.

```console
helm install perspectivegraph oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  -f values-production.yaml
```

`values-production.yaml` turns on the controls a production install needs: an external
PostgreSQL+AGE, the governance stores and the tamper-evident audit log in the database,
`/metrics` on its own listener, resource requests and limits, and TLS. `values-ha.yaml`
layers multiple replicas, pod spreading and a disruption budget on top of it.

## The values that decide the most

| Key | Default | What it decides |
|---|---|---|
| `postgres.enabled` | `true` | The bundled database. **Set `false` and give `postgres.dsn` in production** - the bundled image is a demo convenience and carries its own CVEs. |
| `governanceBackend` | `file` | `postgres` moves suppressions, tickets, verdicts and the **audit chain** into the database, which is what makes more than one replica safe. |
| `persistence.enabled` | `false` | A PVC for the file backend. Refuses to render with more than one replica, on purpose. |
| `backend.replicas` | `1` | Above 1 requires `governanceBackend: postgres`; at-most-once side effects are gated by a leader election. |
| `auth.apiTokens` / `auth.oidc` | empty | **Authentication is off by default.** A reachable install with neither is an unauthenticated map of how to breach your estate. |
| `repoAllowlist` | `[]` | The repositories the engine may write to. Empty refuses every PR comment, merge-gate status and remediation PR - the destination otherwise comes from ingested data. |
| `backend.image.tag` | `""` | Empty resolves to the chart's `appVersion`. Pin a `@sha256:` digest if your policy asks for it. |
| `ingress.enabled` | `false` | With `ingress.tls`, terminate TLS at the edge; `backend.tls` terminates in the process instead. |
| `ai.apiKey` | empty | The AI layer is off until set. When set, attack-path context leaves your boundary. |

`helm show values oci://ghcr.io/luiacuaniello/charts/perspectivegraph` prints all of them,
each with the comment explaining what it costs.

## Security posture

- Both containers run **non-root on a read-only root filesystem** with every Linux
  capability dropped, and satisfy the `restricted` Pod Security Standard. CI renders the
  chart and refuses a change that would break admission.
- The backend image is **distroless** - no shell, so the health check is a subcommand of
  the binary rather than `curl`.
- Every release publishes an **SPDX SBOM** and **SLSA build provenance** attached to the
  images, and the chart is signed by digest.
- The audit log is a hash chain. Under `governanceBackend: postgres` every replica appends
  to one chain; on the file backend it is single-writer, which is why replicas are refused
  there.

The [threat model](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/THREAT-MODEL.md)
states what is *not* covered, and what an operator has to do themselves.

## About the security report on this page

Artifact Hub scans every image a **default** install deploys, and the default here includes
a bundled PostgreSQL+AGE so that `helm install` works with nothing else in place. That
image is where the findings are. The split, from the report itself:

| Image | Critical | High |
|---|---|---|
| `perspectivegraph` (backend) | **0** | **0** |
| `perspectivegraph-dashboard` | **0** | **0** |
| `nats` | 0 | 2 |
| `apache/age` (bundled demo database) | 14 | 97 |

Nothing in the two images this project builds. Of the remaining criticals, **thirteen have
no fix available from Debian in any version** - they are not waiting on anyone's upgrade.

Medium and low follow the same shape: 144 and 150, and **77% of them have no fix available
either**. The rest would be cleared by an upstream rebuild of the database image on a
current Debian, which is the image maintainer's release cadence rather than a decision
anyone here can make.

`values-production.yaml` deploys none of it: production points at your own PostgreSQL+AGE,
which is what [OPERATIONS](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/OPERATIONS.md)
asks for, and the bundled database is a convenience for evaluating the chart rather than a
component of it.

Left there rather than trimmed on purpose. The annotation that feeds this report *replaces*
Artifact Hub's own image extraction, so listing only the two first-party images would take
the page to zero criticals without a single one having been fixed. That number would be
easier to look at and would mean nothing - which is the failure this engine exists to
measure. A critical on something a deployment does not run, or that nothing can route to,
is not the same as a critical on something exposed, and telling those two apart is the
whole product.

## Documentation

- [Operations runbook](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/OPERATIONS.md) - where to get PostgreSQL+AGE, backup and restore, upgrades, the production checklist
- [Manual](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/MANUAL.md) - architecture, scoring, the ingest contract
- [Scale](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/SCALE.md) - sizing measured rather than guessed, and how to measure it on your own graph
- [Upgrade notes](https://github.com/luiacuaniello/perspectivegraph/blob/main/docs/UPGRADING.md) - the releases that need an action from you
- [Support policy](https://github.com/luiacuaniello/perspectivegraph/blob/main/SUPPORT.md) - which versions get fixes, and how fast

Apache-2.0. Issues and pull requests:
[github.com/luiacuaniello/perspectivegraph](https://github.com/luiacuaniello/perspectivegraph).
