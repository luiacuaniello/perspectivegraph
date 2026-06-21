# 🛡️ AegisGraph

> **The Open DevSecOps Context Engine** — turn disconnected security scanner output into a queryable graph of *real, reachable* attack paths.

AegisGraph is an open-source (Apache 2.0) correlation engine. It is **not** another vulnerability
scanner. Instead, it ingests the output of the best-in-class open source tools you already run
(Trivy, Semgrep, Cloud Custodian, Falco), maps every asset, identity, and finding into a single
**graph**, and answers the question that actually matters:

> *Is this vulnerability reachable from the internet, running with excessive privileges, and on a path
> to something valuable?*

## Why?

Modern security teams don't suffer from a lack of tools — they suffer from **noise, fragmentation,
and missing context**.

| Role | Pain today | What AegisGraph gives them |
| --- | --- | --- |
| **Developer** | CI/CD blocked by thousands of irrelevant CVEs | PR comments *only* for findings on a verified attack path, plus suggested fix-as-code |
| **Security** | Triage on flat lists of 10,000 findings | A ranked list of ~5 critical **attack paths**, queryable like a database |
| **Architect** | No live view of how IaC becomes attack surface | Auto-generated, always-current architecture & data-flow maps + drift detection |

## The core idea

We model the whole environment as a directed graph `G = (V, E)`:

- **Vertices `V`** — assets, identities, and findings (`Container`, `IAM_Role`, `CVE`, ...)
- **Edges `E`** — relationships (`HOSTS`, `ASSUMES`, `AFFECTS`, `EXPOSES`, ...)

An **attack path** `P` is a sequence of nodes `v₁ → v₂ → … → vₖ` from an *Internet-Exposed* node to a
*Crown Jewel*. We score each path by composing per-edge exploit probabilities:

```
S(P) = ∏  p(vᵢ, vᵢ₊₁)
      i=1..k-1
```

Paths are found with graph traversal (BFS / weighted Dijkstra) and surfaced as
**Critical Attack Path** events.

## Architecture at a glance

```
            ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 Trivy ───► │              │   │ Normalization│   │  Graph Core  │
 Semgrep ─► │  Ingestion   │──►│  & Identity  │──►│ Postgres +   │
 Custodian► │  Collectors  │   │  Resolution  │   │ Apache AGE   │
 Falco ───► │              │   │              │   │ (openCypher) │
            └──────────────┘   └──────────────┘   └──────┬───────┘
                   │ NATS JetStream (event bus)           │
                   └──────────────────────────────────────┤
                                                           ▼
                                            ┌──────────────────────────┐
                                            │  Attack Path Analyzer     │
                                            │  (BFS/Dijkstra reachability)
                                            └──────────────┬────────────┘
                                                           ▼
          ┌──────────────┐   GraphQL    ┌──────────────────────────┐
          │  React UI     │◄────────────│  API / Action & Feedback  │
          │ Cytoscape.js  │   (BFF)     │  (PR comments, policies)  │
          └──────────────┘             └──────────────────────────┘
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design.

## Tech stack

100% open source, no vendor lock-in, no "freemium" walls (Apache 2.0 / MIT / CNCF only):

- **Core:** Go (concurrency, tiny static binaries, cloud-native)
- **Graph DB:** PostgreSQL + [Apache AGE](https://age.apache.org/) (openCypher)
- **Event bus:** [NATS JetStream](https://nats.io/)
- **Search:** OpenSearch *(optional, planned)*
- **API:** GraphQL
- **Frontend:** React + TailwindCSS + [Cytoscape.js](https://js.cytoscape.org/)
- **Sensors:** Trivy, Semgrep, Cloud Custodian, Falco

## Quick start

```bash
# 1. Boot the infrastructure (Postgres+AGE, NATS, OpenSearch)
make up

# 2. Run the backend (Go)
make run-backend

# 3. Run the frontend (React + Vite)
make run-frontend

# 4. Feed sample Trivy + Semgrep reports; they correlate into attack paths
make seed
```

`make seed` posts four sources — an infra/identity context, a Trivy report
(dependency CVEs), a Semgrep report (SAST weaknesses), a Cloud Custodian export
(cloud infra/identity), and a Falco runtime alert. They **correlate** into
multiple ranked attack paths to crown jewels, for example:

- **Trivy** → `internet LB → container → image → log4j → Log4Shell → admin IAM role`
- **Semgrep** → `internet LB → container → image → repo → command-injection → customers PII DB`
- **Custodian** → `public ALB → EC2 → assumes admin role → S3 PII bucket`

The **Falco** alert on the payments container flips the paths through it to
⚡ *runtime-confirmed* (actively exploited, ranked first). The **policy engine**
flags forbidden shapes (e.g. *internet → crown jewel*), and each path carries
generated **remediation** (a K8s NetworkPolicy or Terraform that cuts one edge).

### Developer feedback on the PR

When a scan is fed with PR context (the `make seed` demo passes
`?slug=acme/payments-api&pr=42`), the action layer comments on the originating
pull request — but **only** for findings on a verified attack path, with the
path diagram and a remediation hint. It upserts a single comment per path
(idempotent across the analyzer's repeated passes). Without a `GITHUB_TOKEN` it
runs in **dry-run**, logging exactly what it would post. Set the token to go live:

```bash
GITHUB_TOKEN=ghp_… make run-backend
```

Then open the dashboard at http://localhost:5173 and the GraphQL playground at
http://localhost:8080/graphql.

## Deploy to Kubernetes

A Helm chart bundles the backend, dashboard, Postgres+AGE, and NATS:

```bash
# Build & push images (or use your registry / prebuilt ones)
docker build -t ghcr.io/aegisgraph/aegisgraph:latest backend
docker build -t ghcr.io/aegisgraph/aegisgraph-dashboard:latest frontend

# Install
helm install aegis deploy/helm/aegisgraph \
  --set github.token=$GITHUB_TOKEN \
  --set opensearch.url=""           # optional full-text index
```

Bring your own managed Postgres/NATS by setting `postgres.enabled=false` /
`nats.enabled=false` and pointing the backend env at them. See
[`deploy/helm/aegisgraph/values.yaml`](./deploy/helm/aegisgraph/values.yaml).

## Project status

🚧 **MVP.** All architecture layers are implemented end-to-end with tests: four
collectors, NATS bus, in-memory + Apache AGE graph stores, attack-path analyzer,
policy invariants, GitHub/GitLab commenters, auto-remediation, optional
OpenSearch, GraphQL API, React/Cytoscape dashboard, Helm chart. The graph store
defaults to Apache AGE and falls back to in-memory for zero-dependency dev. See
[the roadmap](./ARCHITECTURE.md#roadmap) for what's next.

## License

[Apache License 2.0](./LICENSE).
