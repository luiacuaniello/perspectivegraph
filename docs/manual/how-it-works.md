# How it works

*Part of the [PerspectiveGraph manual](../MANUAL.md).* What an attack path is, the architecture that finds one, and the data model underneath.

## The core idea

We model the whole environment as a directed graph `G = (V, E)`:

- **Vertices `V`** - assets, identities, and findings (`Container`, `IAM_Role`, `CVE`, ...)
- **Edges `E`** - relationships (`HOSTS`, `ASSUMES`, `AFFECTS`, `EXPOSES`, ...)

An **attack path** `P` is a sequence of nodes `v₁ → v₂ → … → vₖ` from an *Internet-Exposed* node to a
*Sensitive Asset*. The **baseline** score composes the per-edge exploit probabilities:

```
S(P) = ∏  p(vᵢ, vᵢ₊₁)
      i=1..k-1
```

Taking `-ln` turns this into an additive cost `w = -ln p`, so the **highest-probability path is the
shortest path** - found with Dijkstra from every seed, then surfaced as
**Critical Attack Path** events.

**Seed origin (two threat models).** By default the only seeds are *Internet-Exposed* nodes, so a path
is the crisp "reachable from the internet -> sensitive asset" story. A second, opt-in lens
(`SEED_IAM_USERS=true`) also treats IAM users as seeds, on the premise a long-lived credential could
leak - which surfaces "if this credential leaks, what does it reach" (leaked key -> IAM privesc ->
admin) as scored paths. The two origins stay separable: credential-origin seeds are marked
`credential_exposed`, and the default stays internet-origin so the headline is not diluted.
Every engine starts from the same seeds - the path list, the risk simulation, the alternative
routes and the database path finder - so turning the lens on moves the risk figure too.

**An exposed sensitive asset: reachable is not compromised.** A crown jewel that is itself a
seed is compromised only when something stands open: a database or a VM reachable from the
internet still wants a password or an exploit, so it counts when an edge reaches it, and it is
reported on its own by the `no-internet-exposed-sensitive-asset` invariant (CRITICAL). One that
is **open to anyone** - `public_access`: a bucket whose ACL lets anyone read, a role whose trust
admits `"*"` without a condition - is compromised as it stands. It is listed as a
**direct-access path** (`directAccess: true`): the asset alone, no steps, score 1, priority P1,
with an S3 public access block as the generated fix. Counting every exposed asset as
compromised used to pin the risk figure at 100% and hide every other fix's effect.

That product is only the *starting point*: it assumes the hops are independent and treats a heuristic
guess like measured evidence. The engine is honest about all three gaps, and the layers are what make
it a risk tool rather than a number generator (see [Honest probabilities](scoring.md#honest-probabilities-provenance-not-false-precision)):

- **Correlation** - the product assumes independent hops, so it also reports `scoreUpperBound` (the
  shared-cause bound) and flags `correlatedHops`; the real value lies in `[score, scoreUpperBound]`.
- **One coherent posterior** (`posteriorMean` + `[scoreCiLow, scoreCiHigh]`) - a single Monte Carlo
  composes the two uncertainties that used to be separate, non-nesting numbers: **epistemic** (each `p`
  is a **Beta posterior** whose width reflects its evidence - KEV/runtime tight, heuristic wide; a real
  `evidence_count` adds its observations to it when known) and **attacker capability** (the score is
  marginalized over a latent attacker, `S(P) = Σ_c P(c)·∏ p(e|c)` over commodity/criminal/APT,
  anchored so the profiles average back to each hop's own probability - which leaves the correlation
  the bare product drops as the only thing it adds, so `score ≤ mixtureScore ≤ scoreUpperBound`). `posteriorMean` is the coherent point estimate the credible
  interval brackets (it even corrects the Jensen gap the plug-in `mixtureScore` ignores); `profileScores`
  keep the per-profile breakdown. The **headline risk** (`riskSimulation`) is marginalized the same way
  (`Σ_c P(c)·R_c`, `mixtureCompromiseProbability` + `profileCompromise`), so the environment number and
  the per-path scores share one correlation model instead of the Monte Carlo silently assuming
  independent edges.
- **Calibration** - red-team/BAS verdicts grade the scores against reality (Brier/ECE + a diagnosis),
  so "55%" is a *defensible probability*, not a label - the line between a demo and production.

## Architecture

PerspectiveGraph is **event-driven and modular**. Each layer is decoupled so individual scanners and
sensors can be swapped without touching the core. Data flows in one direction: raw scanner output →
normalized events → graph → attack paths → actions.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. INGESTION LAYER  (Go plugins)                                              │
│    Static collectors (Trivy, Semgrep, …)        - push via webhook / file     │
│    Agentless connectors (AWS, Azure: fixtures)  - scheduled PULL, leader-only │
│    Discovery collectors (K8s, cloud-net, IAM)   - topology & privesc graph    │
│    Runtime collectors (Falco / eBPF)            - live syscall stream         │
│    → push and pull both normalize to an event and publish it on the same bus  │
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
│    Traverses from `internet-exposed` seeds to `sensitive-asset` targets.      │
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
[`backend/pkg/ontology`](../../backend/pkg/ontology).

| Category | Node labels (`V`) | Edge types (`E`) |
| --- | --- | --- |
| **Infrastructure** | `VirtualMachine`, `Container`, `Function`, `API`, `VPC`, `LoadBalancer`, `Database`, `Bucket` | `HOSTS`, `CONNECTS_TO`, `EXPOSES`, `ROUTES_TO` |
| **Code / App** | `Repository`, `Package`, `Library`, `Image` | `DEPENDS_ON`, `COMPILED_INTO`, `BUILT_FROM` |
| **Identity** | `User`, `IAM_Role`, `ServiceAccount` | `ASSUMES`, `HAS_PERMISSION`, `CAN_ESCALATE_TO` |
| **Security** | `CVE`, `Weakness`, `Misconfiguration`, `Secret` | `AFFECTS`, `EXPLOITS`, `MITIGATES` |

`CVE` is a known vulnerability in a dependency (from Trivy); `Weakness` is a
SAST/code-level finding, CWE-classified (from Semgrep); `Misconfiguration` is an
IaC/cloud misconfiguration; `Secret` is an exposed credential.

`CAN_ESCALATE_TO` is an IAM **privilege-escalation** edge: a principal that can,
through its effective permissions, gain another's privileges (the "BloodHound
for cloud" question). The IAM collector flattens each principal's allowed
actions and matches them against known escalation primitives (e.g.
`iam:PassRole` + a compute action, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`; the ones
acting on the principal's own user or groups count only for users), drawing
the edge toward a synthetic account-admin sensitive asset. A role whose trust policy
admits `"Principal":"*"` is marked `internet_exposed` - publicly assumable, the
seed of a full internet→admin path. So is a role that trusts GitHub Actions' OIDC
issuer without pinning the token's `sub` to an owner: any workflow in any repository
can assume it, and the route starts at a *GitHub Actions (any repository)* identity
provider.

Two boolean node attributes drive analysis:

- `internet_exposed` - a valid **seed** for traversal.
- `crown_jewel` - a valid **target** (e.g. a DB holding PII, an admin IAM role).

## Event contract

Collectors emit a single normalized envelope (`ontology.Event`) onto NATS. This is the *only*
contract collectors must satisfy - everything downstream consumes it:

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
| Ingestion (push) | `internal/ingestion` | HTTP webhook + collectors: scanners (`trivy`, `semgrep`, `custodian`, `falco`, `build`), discovery (`k8s` incl. deep RBAC escalation, `cloudnet`, `iam` privesc), identity federation (`sso`: IdP→User→IAM_Role) and supply-chain (`supplychain`: cosign/SLSA trust + SBOM) |
| Connectors (pull) | `internal/connector` | Agentless, scheduled PULL sources that feed the **same** bus, so the whole downstream pipeline is reused. A leader-only `Scheduler` (mirrors `analyzer.Service`) polls each `Connector`, isolates per-source failures, and exposes health at `GET /connectors` + `connector_*` metrics. Connector `aws` reuses the `cloudnet`/`iam` collectors verbatim (transport-abstracted: `fixtures` for demo/test, `aws-sdk-go-v2` for live); `azure` maps normalized `az` network state (NSG CIDR rules + ASG sources, VMs, VNet peerings) onto the `cloudnet` shape - ASG micro-segmentation becomes SG-to-SG so the east-west path forms - then reuses that collector (transport-abstracted: `fixtures`, with `azure-sdk-for-go` the wired extension point) |
| Bus | `internal/broker` | NATS JetStream publish/subscribe |
| Normalization | `internal/normalization` | identity resolution (image dedup, container→image) with **join confidence + provenance** (`resolution_method` / `resolution_confidence` / `resolution_alias`), event → graph |
| Graph | `internal/graph` | `Store` interface + in-memory & Apache AGE implementations (native agtype node/edge properties; optional DB-side `CriticalPaths` via Cypher, safe-railed; optional `Pruner` capability - `last_seen` staleness TTL so departed assets don't become phantom paths) |
| Analyzer | `internal/analyzer` | reachability (in-process Dijkstra by default; opt-in DB-side Cypher) + path scoring + runtime confirmation; Yen K-shortest, Monte Carlo risk quantification, what-if simulation |
| Compliance | `internal/compliance` | render attack-path posture as a NIST OSCAL 1.1.2 assessment-results document |
| Observability | `internal/metrics` | Prometheus collectors (ingest/normalize/analyzer/dead-letter) exposed at `/metrics`. Open and unthrottled so a scrape never starves - and on the API's own port, with `tenant` labels, so do not publish that port (see [THREAT-MODEL](../THREAT-MODEL.md)) |
| Request correlation | `internal/reqid` | stamps every request with an id, echoed in `X-Request-Id`, attached to context-aware log lines and written into the audit record's `fields.request_id` - so one call joins the audit log, the application log and what a user reports. An inbound id is honoured only when short and alphanumeric, since that value is echoed and logged |
| Rate limiting | `internal/ratelimit` | per-client-IP token-bucket middleware for the ingest and API servers, with a capped client table (a flood of spoofed IPv6 sources cannot grow it without bound) and a shared overflow bucket past the cap |
| Leader election | `internal/leader` | Postgres advisory-lock singleton so only one replica fires at-most-once side-effects |
| Policy | `internal/policy` | architectural invariants (forbidden graph shapes) |
| Action | `internal/action` | GitHub/GitLab PR/MR commenters (shared base) |
| Remediation | `internal/remediation` | generate K8s NetworkPolicy / Terraform to cut an edge; each fix records the structured edge it cuts so the API can *verify* it via what-if |
| Ticketing | `internal/ticket` | owned, tracked remediation tickets per path (one open per path; file-backed `TICKETS_PATH` + optional `TICKET_WEBHOOK_URL` external dispatch) |
| Validation | `internal/validation` | red-team/BAS verdicts per path (confirmed/refuted/partial/missed) + precision/recall over the tested subset; **probability calibration** (Brier/log-loss/ECE + reliability diagram) pairing each verdict with the path's predicted score; file-backed `VALIDATIONS_PATH` |
| Search | `internal/search` | optional OpenSearch full-text index |
| Suppression | `internal/suppress` | triage/suppression store (per-tenant, keyed by attack-path id; reason + owner + optional expiry; file-backed, atomic writes) |
| History | `internal/history` | temporal store: per-path lifecycle (first/last seen, open/resolved → MTTR, reopens) + posture trend series, fed each analyzer pass; file-backed (`HISTORY_PATH`) so path age survives restarts |
| API | `internal/api` | GraphQL BFF + REST triage board (`/suppressions`) for the dashboard |

The full, dated feature history is in [CHANGELOG.md](../../CHANGELOG.md).

## Tech stack

100% open source, no vendor lock-in, no "freemium" walls (Apache 2.0 / MIT / CNCF only):

- **Core:** Go (concurrency, tiny static binaries, cloud-native)
- **Graph DB:** PostgreSQL + [Apache AGE](https://age.apache.org/) (openCypher)
- **Event bus:** [NATS JetStream](https://nats.io/)
- **Search:** OpenSearch *(optional - `make up-search` + `OPENSEARCH_URL=http://localhost:9200`)*
- **Threat intel:** CISA KEV + FIRST EPSS *(optional - `THREATINTEL=on`)*
- **API:** GraphQL
- **Frontend:** React + TailwindCSS + [Cytoscape.js](https://js.cytoscape.org/)
- **Sensors:** Trivy, Semgrep, Cloud Custodian, Falco, CI build-provenance (`/ingest/build`), supply-chain cosign/SLSA/SBOM (`/ingest/supplychain`)
- **Discovery:** Kubernetes (`/ingest/k8s`, incl. **container-escape** detection → ATT&CK T1611), cloud-network (`/ingest/cloudnet`), IAM privilege-escalation graph (`/ingest/iam`), and SSO/IdP federation (`/ingest/sso`)
- **Data classification:** Macie/DLP findings (`/ingest/dataclass`) mark assets as sensitive assets with an authoritative `classified:<source>:<kind>` basis
- **Agentless connectors:** scheduled, leader-only **PULL** sources that reach out to a cloud account instead of waiting for an upload (`CONNECTORS_ENABLED`, health at `GET /connectors`). Connectors: **AWS** (`aws`), live through the AWS SDK with read-only credentials, and **Azure** (`azure`), which maps normalized `az` state but runs from fixtures only: its live SDK transport is not wired yet, and `AZURE_CONNECTOR_MODE=sdk` refuses to start
- **Multi-tenant + SSO:** per-tenant isolated graphs (proven by test), bearer/OIDC auth with per-tenant/per-app/role RBAC, and a runtime login gate (`GET /auth/config` → token or "Sign in with SSO")
- **Dev workflow:** GitHub PR comment + a **PR merge-gate status** (red when the change opens an internet→sensitive-asset path; the CI gate compares the change with the estate), and **remediation-as-PR** (`POST /remediation/pr` opens a branch+commit+PR with the fix)
- **AI-native (Claude *or* HuggingFace):** natural-language Q&A over the graph, a board-level executive summary, and plain-English path explanations - grounded in the live attack paths (`ANTHROPIC_API_KEY`, or a free `HF_TOKEN`)
- **ATT&CK:** each kill-chain hop mapped to a MITRE ATT&CK technique + tactic
