# AegisGraph — Architecture

AegisGraph is **event-driven and modular**. Each layer is decoupled so individual scanners and
sensors can be swapped without touching the core. Data flows in one direction: raw scanner output →
normalized events → graph → attack paths → actions.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. INGESTION LAYER  (Go plugins)                                              │
│    Static collectors (Trivy, Semgrep, Checkov)  — push via webhook / file     │
│    Cloud collectors  (Cloud Custodian)          — periodic pull of AWS/GCP/Az │
│    Runtime collectors (Falco / eBPF)            — live syscall stream         │
│    → every collector normalizes to an intermediate event and publishes it     │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                     │  NATS JetStream  (subject: aegis.events.*)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. NORMALIZATION & IDENTITY RESOLUTION                                        │
│    Maps every tool's vocabulary onto one common Ontology.                      │
│    Deduplicates assets (Trivy "image:tag" == ECR ARN == K8s PodSpec).         │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. GRAPH CORE   (PostgreSQL + Apache AGE, openCypher)                          │
│    Stores the directed graph G = (V, E). Upserts nodes & edges.               │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. ATTACK PATH ANALYZER                                                       │
│    Traverses from `internet-exposed` seeds to `crown-jewel` targets.          │
│    Scores paths: S(P) = ∏ p(edge). Emits Critical Attack Path events.         │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. ACTION & FEEDBACK + API (BFF)                                              │
│    GraphQL API for the dashboard. PR comments for devs. Policy invariants     │
│    for architects. Auto-remediation suggestions (Terraform / K8s NetworkPol). │
└─────────────────────────────────────────────────────────────────────────────┘
```

## The ontology

The common vocabulary every collector maps onto. Defined in
[`backend/pkg/ontology`](./backend/pkg/ontology).

| Category | Node labels (`V`) | Edge types (`E`) |
| --- | --- | --- |
| **Infrastructure** | `VirtualMachine`, `Container`, `VPC`, `LoadBalancer`, `Database`, `Bucket` | `HOSTS`, `CONNECTS_TO`, `EXPOSES`, `ROUTES_TO` |
| **Code / App** | `Repository`, `Package`, `Library`, `Image` | `DEPENDS_ON`, `COMPILED_INTO`, `BUILT_FROM` |
| **Identity** | `User`, `IAM_Role`, `ServiceAccount` | `ASSUMES`, `HAS_PERMISSION` |
| **Security** | `CVE`, `Weakness`, `Misconfiguration`, `Secret` | `AFFECTS`, `EXPLOITS`, `MITIGATES` |

`CVE` is a known vulnerability in a dependency (from Trivy); `Weakness` is a
SAST/code-level finding, CWE-classified (from Semgrep); `Misconfiguration` is an
IaC/cloud misconfiguration; `Secret` is an exposed credential.

Two boolean node attributes drive analysis:

- `internet_exposed` — a valid **seed** for traversal.
- `crown_jewel` — a valid **target** (e.g. a DB holding PII, an admin IAM role).

## Risk scoring

Each edge carries an exploit probability `p ∈ (0, 1]`. The probability that a full path is
exploitable (assuming independence, for tractability) is the product of its edge probabilities:

```
S(P) = ∏ p(vᵢ, vᵢ₊₁)
```

We convert to a traversal cost `w = -ln(p)` so that **maximizing `S(P)` becomes a shortest-path
problem** (minimizing `Σ w`) solvable with Dijkstra. See
[`backend/internal/analyzer`](./backend/internal/analyzer).

## Event contract

Collectors emit a single normalized envelope (`ontology.Event`) onto NATS. This is the *only*
contract collectors must satisfy — everything downstream consumes it:

```jsonc
{
  "source": "trivy",            // which collector
  "kind": "finding",            // asset | finding | relationship | runtime
  "observed_at": "2026-06-08T…",
  "nodes": [ /* ontology.Node[] */ ],
  "edges": [ /* ontology.Edge[] */ ]
}
```

## Component map

| Layer | Package | Responsibility |
| --- | --- | --- |
| Ingestion | `internal/ingestion` | HTTP webhook + collectors (`trivy`, `semgrep`, `custodian`, `falco`) |
| Bus | `internal/broker` | NATS JetStream publish/subscribe |
| Normalization | `internal/normalization` | identity resolution (image dedup, container→image), event → graph |
| Graph | `internal/graph` | `Store` interface + in-memory & Apache AGE implementations |
| Analyzer | `internal/analyzer` | reachability traversal + path scoring + runtime confirmation |
| Policy | `internal/policy` | architectural invariants (forbidden graph shapes) |
| Action | `internal/action` | GitHub/GitLab PR/MR commenters (shared base) |
| Remediation | `internal/remediation` | generate K8s NetworkPolicy / Terraform to cut an edge |
| Search | `internal/search` | optional OpenSearch full-text index |
| API | `internal/api` | GraphQL BFF for the dashboard |

## Roadmap

- [x] Repository scaffold + layered package layout
- [x] Ontology (nodes / edges / event envelope)
- [x] NATS JetStream broker wrapper
- [x] Graph `Store` interface + Apache AGE driver
- [x] Trivy collector (normalize JSON report → events)
- [x] Semgrep collector (SAST findings → Weakness/Secret nodes)
- [x] Normalization consumer (event → graph upsert)
- [x] Attack-path analyzer (Dijkstra over -ln(p))
- [x] GraphQL API skeleton + health checks
- [x] React + Cytoscape dashboard skeleton
- [x] GitHub PR commenter (upsert comment with path diagram + remediation)
- [x] Cloud Custodian collector (cloud infra/identity → attack paths)
- [x] Falco collector (runtime alerts → runtime-confirmed paths)
- [x] Identity resolution heuristics (image dedup, container→image stitching)
- [x] GitLab MR commenter (shared commenter base)
- [x] Policy-as-graph invariants engine (forbidden shapes + built-ins)
- [x] Auto-remediation (Terraform / K8s NetworkPolicy generation)
- [x] OpenSearch full-text index (optional)
- [x] Helm chart + Dockerfiles for one-command cluster deploy
- [ ] Future: GitLab/Bitbucket parity for other forges, OSCAL/compliance export,
      learned identity-resolution (embeddings), HA Postgres/AGE operator
