# PerspectiveGraph — Architecture

PerspectiveGraph is **event-driven and modular**. Each layer is decoupled so individual scanners and
sensors can be swapped without touching the core. Data flows in one direction: raw scanner output →
normalized events → graph → attack paths → actions.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. INGESTION LAYER  (Go plugins)                                              │
│    Static collectors (Trivy, Semgrep, Checkov)  — push via webhook / file     │
│    Cloud collectors  (Cloud Custodian)          — periodic pull of AWS/GCP/Az │
│    Discovery collectors (K8s, cloud-net, IAM)   — topology & privesc graph    │
│    Runtime collectors (Falco / eBPF)            — live syscall stream         │
│    → every collector normalizes to an intermediate event and publishes it     │
└───────────────────────────────────┬───────────────────────────────────────────┘
                                     │  NATS JetStream  (subject: perspective.events.*)
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
| **Identity** | `User`, `IAM_Role`, `ServiceAccount` | `ASSUMES`, `HAS_PERMISSION`, `CAN_ESCALATE_TO` |
| **Security** | `CVE`, `Weakness`, `Misconfiguration`, `Secret` | `AFFECTS`, `EXPLOITS`, `MITIGATES` |

`CVE` is a known vulnerability in a dependency (from Trivy); `Weakness` is a
SAST/code-level finding, CWE-classified (from Semgrep); `Misconfiguration` is an
IaC/cloud misconfiguration; `Secret` is an exposed credential.

`CAN_ESCALATE_TO` is an IAM **privilege-escalation** edge: a principal that can,
through its effective permissions, gain another's privileges (the "BloodHound
for cloud" question). The IAM collector flattens each principal's allowed
actions and matches them against known escalation primitives (e.g. `iam:PassRole`
+ a compute action, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`), drawing
the edge toward a synthetic account-admin crown jewel. A role whose trust policy
admits `"Principal":"*"` is marked `internet_exposed` — publicly assumable, the
seed of a full internet→admin path.

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

The product assumes the hops are **independent**. When they share a common cause (one weakness
gating several steps) they are positively correlated, and the product is then a *lower* bound for
"all hops succeed"; the comonotonic (Fréchet) upper bound is the weakest single hop, `min p`. So
rather than dressing up `S(P)` as exact, each path also exposes a `scoreUpperBound` (= `min p`) and
a `correlatedHops` flag (set when ≥2 hops rest on the same weight basis) — the true exploitability
lies in `[score, scoreUpperBound]`, and a wide band says the independence assumption is doing the
work. The headline score is unchanged.

**Where the traversal runs.** Node *and edge* properties are stored as **native
agtype** in Apache AGE, so the graph is genuinely queryable. The per-pass
critical-path search uses the **in-process Dijkstra by default** — a polynomial,
bounded algorithm that is the right engine for "all best paths every pass".

A DB-side finder is available as an **opt-in** (`ANALYZER_DB_PATHS=true`): a Cypher
variable-length match (`MATCH p=(a)-[*1..N]->(b) WHERE a.internet_exposed AND
b.crown_jewel`, bounded by `ANALYZER_MAX_HOPS`). It is honestly *not* a perf win
for the batch — AGE has no weighted shortest-path, so this **enumerates** paths,
which is unbounded in the worst case on dense/cyclic graphs. It is therefore
safe-railed (server `statement_timeout` + `LIMIT`, plus a client deadline that
**falls back to Dijkstra** on a runaway query) and best reserved for bounded or
targeted queries. The store-contract test asserts the DB finder and Dijkstra
agree on scores, and documents the recall bound when a path exceeds `maxHops`.
Either way the per-pass snapshot is materialized for the policy-invariant engine
and the Monte Carlo risk model, which need the full edge set.

### Beyond the single best path

The per-path product answers "how exploitable is *this* route". Three analyses go further:

- **K-shortest paths (Yen's algorithm).** The top-K highest-probability loopless routes to a
  crown jewel, so cutting the single best edge doesn't hide the near-best alternates.
- **Monte Carlo risk quantification.** Each trial realizes every edge independently (present
  with probability `p`), then checks crown-jewel reachability. The fraction of trials where a
  jewel is reachable is an unbiased estimate of its **compromise probability** — accounting for
  path multiplicity and shared edges that `∏p` can't — reported with a 95% Wilson confidence
  interval. This is the `P(at least one crown jewel compromised)` a CISO actually asks for.
- **What-if simulation.** Remove a set of edges (a proposed remediation) and recompute paths +
  risk, using *common random numbers* so the before/after delta reflects the cut, not sampling
  noise. Pairs with the choke-point optimizer: "if we fix these N edges, residual risk drops from
  X to Y".

Exposed as the GraphQL `kShortestPaths`, `riskSimulation` and `whatIf` queries.

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
| Ingestion | `internal/ingestion` | HTTP webhook + collectors: scanners (`trivy`, `semgrep`, `custodian`, `falco`, `build`), discovery (`k8s` incl. deep RBAC escalation, `cloudnet`, `iam` privesc), identity federation (`sso`: IdP→User→IAM_Role) and supply-chain (`supplychain`: cosign/SLSA trust + SBOM) |
| Bus | `internal/broker` | NATS JetStream publish/subscribe |
| Normalization | `internal/normalization` | identity resolution (image dedup, container→image) with **join confidence + provenance** (`resolution_method` / `resolution_confidence` / `resolution_alias`), event → graph |
| Graph | `internal/graph` | `Store` interface + in-memory & Apache AGE implementations (native agtype node/edge properties; optional DB-side `CriticalPaths` via Cypher, safe-railed; optional `Pruner` capability — `last_seen` staleness TTL so departed assets don't become phantom paths) |
| Analyzer | `internal/analyzer` | reachability (in-process Dijkstra by default; opt-in DB-side Cypher) + path scoring + runtime confirmation; Yen K-shortest, Monte Carlo risk quantification, what-if simulation |
| Compliance | `internal/compliance` | render attack-path posture as a NIST OSCAL 1.1.2 assessment-results document |
| Observability | `internal/metrics` | Prometheus collectors (ingest/normalize/analyzer/dead-letter) exposed at `/metrics` |
| Rate limiting | `internal/ratelimit` | per-client-IP token-bucket middleware for the ingest and API servers |
| Leader election | `internal/leader` | Postgres advisory-lock singleton so only one replica fires at-most-once side-effects |
| Policy | `internal/policy` | architectural invariants (forbidden graph shapes) |
| Action | `internal/action` | GitHub/GitLab PR/MR commenters (shared base) |
| Remediation | `internal/remediation` | generate K8s NetworkPolicy / Terraform to cut an edge; each fix records the structured edge it cuts so the API can *verify* it via what-if |
| Ticketing | `internal/ticket` | owned, tracked remediation tickets per path (one open per path; file-backed `TICKETS_PATH` + optional `TICKET_WEBHOOK_URL` external dispatch) |
| Validation | `internal/validation` | red-team/BAS verdicts per path (confirmed/refuted/partial/missed) + precision/recall over the tested subset; file-backed `VALIDATIONS_PATH` |
| Search | `internal/search` | optional OpenSearch full-text index |
| Suppression | `internal/suppress` | triage/suppression store (per-tenant, keyed by attack-path id; reason + owner + optional expiry; file-backed, atomic writes) |
| History | `internal/history` | temporal store: per-path lifecycle (first/last seen, open/resolved → MTTR, reopens) + posture trend series, fed each analyzer pass; file-backed (`HISTORY_PATH`) so path age survives restarts |
| API | `internal/api` | GraphQL BFF + REST triage board (`/suppressions`) for the dashboard |

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
- [x] Auto-remediation (Terraform / K8s NetworkPolicy generation, rule registry)
- [x] Choke-point remediation optimizer (greedy set-cover: fewest fixes → most risk removed)
- [x] Threat-intel enrichment: CISA KEV + FIRST EPSS reweight CVE edges by real exploitation likelihood
- [x] Endpoint auth: HMAC-signed ingest webhooks + bearer-token RBAC on the API, with audit logging
- [x] OIDC/JWT API auth (RS256 + JWKS; role/tenant claims) alongside static tokens
- [x] Multi-tenancy: per-tenant isolated AGE graphs + search indices, end-to-end routing & scoping
- [x] Immutable, hash-chained audit log with a `verify-audit` integrity check
- [x] Coverage expansion: **SSO/IdP federation** (`internal/ingestion/sso` + `/ingest/sso`) — Okta/Entra `IdentityProvider(internet)→AUTHENTICATES→User→ASSUMES→IAM_Role`, ARN-converged with the IAM graph, no-MFA hop weighted as phishable (the modern internet→SSO→cloud-admin vector); **deep K8s RBAC** — escalation primitives (create pods, read secrets, bind/escalate, impersonate, mint SA tokens) draw `CAN_ESCALATE_TO` a synthetic cluster-admin, not just wildcard/name checks; **crown-jewel inference** — untagged sensitive-named data stores inferred as jewels with `crown_jewel_basis` provenance (explicit tags win)
- [x] Supply-chain coverage (`internal/ingestion/supplychain` + `/ingest/supplychain`): per-image trust (cosign `signed`, SLSA level, builder) + SBOM bill-of-materials (plain list or CycloneDX) as DEPENDS_ON Library/Package nodes; built-in `no-internet-to-unsigned-image` invariant treats a reachable unsigned image as a tampering vector; surfaced on the image node ("⚠ unsigned" / "SLSA Ln")
- [x] Honest probabilities: every edge weight declares its provenance (`weight_basis`: kev/epss/runtime evidence vs cvss/severity/heuristic estimate — threat-intel stamps the first, the analyzer infers the rest), propagated to per-hop `weightConfidence` and a per-path `confidence`/`confidenceLabel` (high/medium/low). The score is unchanged; what's added is a defensible answer to "why this %?" instead of false precision
- [x] Independence honesty in the score: the path score `∏p` assumes independent hops, so each path also exposes `scoreUpperBound` (= `min p`, the comonotonic / shared-cause bound) and a `correlatedHops` flag (≥2 hops on the same basis). The true exploitability lies in `[score, scoreUpperBound]` — the UI shows "↑ up to X% if correlated" rather than pretending the product is exact
- [x] Secret scrubbing at ingest (data hygiene): scanner output can carry a live credential; the graph is a map of how to attack the org, so it must never *store* the secrets themselves. High-precision patterns (AWS/GitHub/Slack/Google tokens, PEM private keys, JWTs, `secret=…` assignments) are redacted out of property values before they hit the store (`internal/scrub`, `SCRUB_INGEST` default on) — the finding is kept, the value becomes `***redacted:<kind>***`, the node is stamped `secrets_scrubbed`; identifiers (ids, names, SHAs, digests, refs) are never touched; retention of the scrubbed findings is governed by `GRAPH_TTL`
- [x] Audit-of-views (tool self-governance): reads of the attack map are audited, not just writes — `view.attack_paths` (with the path ids seen) / `view.graph` / `export.oscal` / `export.ndjson`, each tamper-evidently chained, answering "who saw or exfiltrated which attack paths"
- [x] Kubernetes topology collector (Ingress/Service/Pod/SA/RBAC → EXPOSES/ROUTES_TO/ASSUMES)
- [x] Cloud-network collector (security groups / VPC peering → CONNECTS_TO + internet exposure)
- [x] IAM privilege-escalation graph (BloodHound-for-cloud): `get-account-authorization-details` → effective-permission flattening → CAN_ESCALATE_TO edges to a synthetic account-admin crown jewel; public-trust roles marked internet-exposed
- [x] K-shortest attack paths (Yen's algorithm): top-K routes per crown jewel, not just the single best
- [x] Monte Carlo risk quantification: per-crown-jewel compromise probability + 95% Wilson CI, capturing path multiplicity
- [x] What-if simulation: cut a set of edges → residual paths + quantified risk reduction (common random numbers)
- [x] OSCAL compliance export (`GET /export/oscal`): attack paths → NIST 800-53 control findings (assessment-results 1.1.2)
- [x] Drift detection + alerting (per-pass path diff → Slack/SOAR webhook)
- [x] Detection-as-code (Falco + Sigma rules generated per attack path)
- [x] SIEM enrichment export (`GET /export/ndjson`, per-asset risk context)
- [x] CI build-provenance collector (Image --BUILT_FROM--> Repository)
- [x] Cross-collector severity scale + tag-driven crown-jewel classification
- [x] Per-application scoping + pagination (GraphQL + dashboard); analyzer change-detection
- [x] OpenSearch full-text index (optional)
- [x] Helm chart + Dockerfiles for one-command cluster deploy. The chart wires all four components (backend, dashboard, Postgres+AGE with idempotent `create_graph` init, NATS) with env names that match `config.go`, and supports bring-your-own external Postgres/NATS (`required`-guarded). Governance is first-class, not just demo-grade: `auth.apiTokens`/`auth.oidc.*` (bearer + OIDC), `ingest.hmacSecret(s)` (signed ingestion), per-IP rate limits, `graph.ttl` pruning, and `persistence.enabled` — a ReadWriteOnce PVC that backs the suppression/ticket/validation/history stores **and the tamper-evident audit log**, so they survive restarts. The stores are single-writer, so the chart **refuses to render with `backend.replicas > 1` while persistence is on**, and `NOTES` prints a ⚠ whenever auth or persistence is left off (no silent insecure exposure). The backend also has `initContainers` that wait for the bundled Postgres/NATS to accept TCP before it starts, so a fresh install reaches AGE on the first try instead of crash-looping on NATS or silently falling back to the in-memory graph (verified end-to-end on minikube: 0 restarts, `graph=apache-age` from boot, suppression survives a pod restart on the PVC).
- [x] Hardened full-stack `docker compose` (`make up-full`): backend + dashboard + infra, digest-pinned images, non-root read-only backend, loopback-only ports, healthcheck-gated startup
- [x] Backend hardening: Cypher-injection-safe AGE store (randomized dollar-quote + ontology allowlist), AGE connection pool + per-label `id` index, per-IP rate limiting, Prometheus `/metrics`, dead-letter stream, `GRAPH_STRICT` fail-loud persistence, CI AGE integration job
- [x] Transport & supply-chain hardening pass: explicit `http.Server` timeouts (ReadHeader/Read/Write/Idle — Slowloris defense), dedicated timeout-bound HTTP clients + size-capped response reads (`httpx`, JWKS), CORS **allowlist** (`CORS_ALLOWED_ORIGINS`) replacing `*`, **fail-closed OIDC** (refuse to start if `OIDC_JWKS_URL` is set without `iss`/`aud`), and a **SAST gate (`gosec`) + secret scan (`gitleaks`) in CI** — the tool's own source held to the bar it sets (the few benign findings carry justified `// #nosec`). Test coverage closed on the two highest-risk untested packages: the **Trivy parser** (table test + a `FuzzParse` contract — untrusted webhook bytes must never panic and never emit a malformed node/edge) and **leader election** (fail-closed unit tests + a Postgres advisory-lock mutual-exclusion/failover integration test on the CI AGE service)
- [x] Defending the tool's own crown-jewel data: **at-rest AES-256-GCM encryption** of the file-backed governance stores **and the audit log** (`STORE_ENCRYPTION_KEY`; transparent read of pre-encryption files for migration); **Ed25519-signed exports** with a detached signature + `GET /export/pubkey` for the consumer to verify integrity/origin (`EXPORT_SIGNING_KEY`); and **abuse detection on itself** — per-IP auth brute-force **lockout** (HTTP 429) and per-principal **exfiltration alerting** on bulk attack-map reads/exports (`AUTH_LOCKOUT_THRESHOLD` / `EXFIL_ALERT_THRESHOLD`), both logged + audited via a shared sliding-window detector
- [x] Identity depth: **token lifecycle** (optional `YYYY-MM-DD` expiry + `sha256$<hex>` hashed-at-rest storage so the live secret isn't in config) and **object-level RBAC** — a token's `:app1|app2` field (or an OIDC `apps` claim) scopes a principal's *reads* to those applications. Enforced once at the data boundary (`a.snapshot` for graph reads, `a.scopedLatest` for paths), so every resolver (attack paths, graph, risk, violations, exports, search) inherits the restriction with no per-resolver bypass; shared infra on an allowed path stays visible (it's part of the attack)
- [x] **MITRE ATT&CK mapping** (`internal/attck`): each ontology edge type maps to a best-fit ATT&CK technique + tactic (EXPOSES→T1190 Initial Access, DEPENDS_ON→T1195.002, CONNECTS_TO→T1021 Lateral Movement, CAN_ESCALATE_TO→T1078.004 Privilege Escalation, …; structural edges carry none), surfaced on the GraphQL `Edge`/`AttackPathStep` `attack` field and in the UI — a technique badge per kill-chain hop (linking to the ATT&CK page) and on the highlighted graph edges, so a probability-ranked route reads as a recognizable kill chain. Heuristic mapping, consistent with the tool's evidence-vs-estimate honesty
- [x] UI professionalization: replaced decorative emoji across the dashboard (graph node/edge markers, kill chain, legend, banners) with a coherent inline-SVG icon set (Feather/Lucide-style, `currentColor`-themed for light/dark); graph entry/jewel/runtime status now read from border-ring swatches that match the canvas exactly
- [x] Container-escape vector (`ESCAPES_TO`): the K8s collector flags pods that break the host boundary (privileged container, `hostPath` mount, `hostPID`/`hostNetwork`/`hostIPC`) and emits an escape edge to the synthetic cluster-admin (ATT&CK **T1611 Escape to Host**) — so *internet → privileged pod → host → cluster takeover* becomes a first-class, ranked attack path, distinct from RBAC privilege escalation
- [x] Crown-jewel from real data classification (`dataclass` collector): a Macie/DLP/tag-policy finding (`POST /ingest/dataclass`) marks the named asset a crown jewel with an authoritative `classified:<source>:<kind>` basis — stronger than the name heuristic, and surfaced in the UI as a `(classified)` jewel + a data-classification badge. The `classifyCrownJewels` normalizer pass runs before the name heuristic; an explicit owner tag still wins
- [x] Coherence pass: remediation rules for `CAN_ESCALATE_TO` (IAM privesc deny-policy) and `CONNECTS_TO` (SG segmentation); what-if + OSCAL/NDJSON exports surfaced in the dashboard; search "feature-off" state; graph fit-on-path-select
- [x] Robustness pass: Monte Carlo sensitivity band (model/input uncertainty, shown as "modeled X–Y%"); leader-elected side-effects so multiple replicas don't duplicate drift/PR actions; Vitest frontend suite + CI; React error boundary; "analyzed N ago" freshness
- [x] Responsive dashboard: off-canvas sidebar drawer + hamburger on mobile, wrapping header/cards, stacked path list/detail on narrow; unchanged desktop split
- [x] Theming: a CSS-variable design-token layer (surfaces/accent + the slate text ramp as channel vars in `:root`/`.dark`) drives a full **light/dark mode** with a header toggle that persists (localStorage) and honours the OS preference on first load (no-flash inline boot script). The Cytoscape environment graph re-skins in place on toggle (labels/rings/edges/dot-grid), preserving pan/zoom; status colors are lightened in dark for contrast. Light theme is byte-for-byte unchanged.
- [x] Native, queryable graph: AGE node + edge properties stored as native agtype (legacy JSON-blob format still read for backward compatibility). In-process Dijkstra is the default path engine (polynomial, bounded); a Cypher variable-length finder is an opt-in (`ANALYZER_DB_PATHS`), safe-railed with statement_timeout + LIMIT + fallback, contract-verified for score-equivalence and its recall bound
- [x] Trustworthy correlation: identity-resolution **join confidence + provenance** (digest 1.0 / tag 0.85 / name 0.6; a weak join lowers the stitched edge probability) surfaced on nodes and in the kill chain as a "heuristic join" badge
- [x] Triage/suppression loop (`internal/suppress` + `/suppressions`): per-tenant accept-risk / false-positive / mitigating-control / duplicate decisions with accountable owner + auto-expiry; posture splits active vs suppressed; file-backed (`SUPPRESSIONS_PATH`) with atomic writes
- [x] Validation against reality (`internal/validation` + `/validations`): red-team/BAS verdicts per path (confirmed/refuted/partial/missed) → **precision** = confirmed/(confirmed+refuted), **recall** = confirmed/(confirmed+missed) over the *tested* subset (explicitly not a global claim); per-path verdict badge + a Validation precision card; `make seed-validation`
- [x] Closed-loop action: remediation **verification** (each fix records its cut edge; the API simulates removal via what-if → "verified: removes N paths / −X%" vs "unverified") + owned **ticketing** (`internal/ticket` + `/tickets`, file-backed `TICKETS_PATH`, optional `TICKET_WEBHOOK_URL` dispatch to Jira/GitHub/SOAR, dashboard create/close + "ticketed · owner" badge)
- [x] Temporal layer (`internal/history` + `HISTORY_PATH`): per-path lifecycle (first/last seen, open/resolved → MTTR, reopen/regression count) and a posture trend series recorded each pass; exposed via GraphQL (`history`, plus `firstSeen`/`openForSeconds`/`reopens` per path) and the dashboard (MTTR card, "open Nd"/"reopened N×" badges, exposure-trend sparkline) — the trend/accountability layer over point-in-time drift
- [x] Staleness pruning (`GRAPH_TTL`): `last_seen` stamped on every upsert; optional `Pruner` store capability (memory + AGE, contract-tested in lockstep) removes assets that left the source feeds (leader-only, derived cadence, grandfathers un-stamped data) so the graph can't accrete phantom paths; exposed via `status`/metrics/dashboard. DR posture: the graph is derived/rebuildable from the feeds — a lost AGE DB is a re-seed, not data loss
- [ ] Future: GitLab/Bitbucket parity for other forges,
      learned identity-resolution (embeddings), HA Postgres/AGE operator
