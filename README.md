# PerspectiveGraph

> **The Open DevSecOps Context Engine** — turn disconnected security scanner output into a queryable graph of *real, reachable* attack paths.

PerspectiveGraph is an open-source (Apache 2.0) correlation engine. It is **not** another vulnerability
scanner. Instead, it ingests the output of the best-in-class open source tools you already run
(Trivy, Semgrep, Cloud Custodian, Falco), maps every asset, identity, and finding into a single
**graph**, and answers the question that actually matters:

> *Is this vulnerability reachable from the internet, running with excessive privileges, and on a path
> to something valuable?*

> 🇮🇹 **In italiano?** La [Guida completa (docs/GUIDA.md)](docs/GUIDA.md) spiega come avviare/spegnere
> tutto (con e senza Docker), come provarlo sui tuoi progetti e il significato dei dati in dashboard.

![PerspectiveGraph dashboard — security posture overview](docs/screenshot-overview.png)

<details>
<summary>More: ranked attack paths with kill chain, and the choke-point remediation optimizer</summary>

![Attack path detail — kill chain and suggested remediation](docs/screenshot-paths.png)

![Remediation plan — the fewest fixes that eliminate the most critical-path risk](docs/screenshot-remediation.png)

</details>

## Why?

Modern security teams don't suffer from a lack of tools — they suffer from **noise, fragmentation,
and missing context**.

| Role | Pain today | What PerspectiveGraph gives them |
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
- **Search:** OpenSearch *(optional — `make up-search` + `OPENSEARCH_URL=http://localhost:9200`)*
- **Threat intel:** CISA KEV + FIRST EPSS *(optional — `THREATINTEL=on`)*
- **API:** GraphQL
- **Frontend:** React + TailwindCSS + [Cytoscape.js](https://js.cytoscape.org/)
- **Sensors:** Trivy, Semgrep, Cloud Custodian, Falco, CI build-provenance (`/ingest/build`), supply-chain cosign/SLSA/SBOM (`/ingest/supplychain`)
- **Discovery:** Kubernetes (`/ingest/k8s`, incl. **container-escape** detection → ATT&CK T1611), cloud-network (`/ingest/cloudnet`), IAM privilege-escalation graph (`/ingest/iam`), and SSO/IdP federation (`/ingest/sso`)
- **Data classification:** Macie/DLP findings (`/ingest/dataclass`) mark assets as crown jewels with an authoritative `classified:<source>:<kind>` basis
- **ATT&CK:** each kill-chain hop mapped to a MITRE ATT&CK technique + tactic

## Quick start

**Everything in containers (one command):**

```bash
make up-full        # builds & runs infra + backend + dashboard (docker compose --profile app)
make seed           # feed the sample sources; they correlate into attack paths
open http://localhost:3000
```

`make up-full` brings up the whole stack — Postgres+AGE, NATS, the Go backend, and
the nginx-served dashboard on **:3000** (which proxies `/graphql` to the backend).
Tear it all down with `make down`. All ports bind to `127.0.0.1`; the backend runs
non-root on a read-only rootfs with every Linux capability dropped (see
[Container & compose hardening](#container--compose-hardening)). The dashboard ships
**light & dark themes** — a header toggle (☀️/🌙) that remembers your choice and
follows the OS preference on first load.

**Or run the backend/frontend on the host (dev loop):**

```bash
# 1. Boot just the infrastructure (Postgres+AGE, NATS)
make up          # or: make up-search to also start the optional OpenSearch index

# 2. Run the backend (Go)
make run-backend

# 3. Run the frontend (React + Vite)
make run-frontend

# 4. Feed sample Trivy + Semgrep reports; they correlate into attack paths
make seed
```

`make seed` posts six sources — an infra/identity context, a Trivy report
(dependency CVEs), CI build provenance (image ↔ repository), a Semgrep report
(SAST weaknesses), a Cloud Custodian export (cloud infra/identity), and a Falco
runtime alert. They **correlate** into
multiple ranked attack paths to crown jewels, for example:

- **Trivy** → `internet LB → container → image → log4j → Log4Shell → admin IAM role`
- **Semgrep** → `internet LB → container → image → repo → command-injection → customers PII DB`
- **Custodian** → `public ALB → EC2 → assumes admin role → S3 PII bucket`

The **Falco** alert on the payments container flips the paths through it to
⚡ *runtime-confirmed* (actively exploited, ranked first). The **policy engine**
flags forbidden shapes (e.g. *internet → crown jewel*), and each path carries
generated **remediation** (a K8s NetworkPolicy or Terraform that cuts one edge).

### Topology discovery (no hand-stitched IDs)

`make seed-discovery` posts a raw Kubernetes dump (`kubectl get … -o json`), a
cloud-network export (AWS `describe-*`) and an IAM authorization dump
(`aws iam get-account-authorization-details`). PerspectiveGraph **auto-discovers**
the exposure/reachability topology no scanner produces:

- **Kubernetes** → `Ingress → Service → Pod → ServiceAccount → Role`, surfacing
  e.g. *internet → ingress → pod → cluster-admin* — a privilege-escalation path
  found from cluster config alone. RBAC is modeled in depth: beyond
  wildcard/`admin`-named roles, a role that grants an **escalation primitive**
  (`create pods`, `read secrets`, `bind`/`escalate` roles, `impersonate`,
  mint SA tokens) draws a `CAN_ESCALATE_TO` edge to a synthetic **cluster-admin**
  — BloodHound-for-Kubernetes, not just a name check.
- **SSO / identity federation** (Okta, Entra, …) → the modern front door:
  `IdentityProvider(internet) → AUTHENTICATES → User → ASSUMES → IAM_Role`. The
  federated role is ARN-keyed, so it converges with the IAM graph — a **no-MFA**
  Okta user who federates into an admin/escalation role surfaces the whole chain
  *internet → Okta → user → cloud admin*, with the no-MFA hop weighted as easily
  phishable.
- **Cloud network** → internet-facing security groups, SG-to-SG reachability and
  VPC peering, surfacing e.g. *internet → web tier → PII database*.
- **IAM privesc graph** ("BloodHound for cloud") → flattens each principal's
  effective permissions, matches them against known escalation primitives
  (`iam:PassRole`+compute, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, …)
  and draws `CAN_ESCALATE_TO` edges to a synthetic **account-admin** crown jewel.
  A role trusting `"Principal":"*"` is flagged internet-exposed, surfacing
  *internet → publicly-assumable role → CAN_ESCALATE_TO → account compromise*.

This is what turns "demo that works because the IDs line up by hand" into
"discovery on real infrastructure".

Crown-jewel classification isn't purely tag-driven either: an untagged
`Database`/`Bucket` whose name carries a strong sensitive-data signal (pii,
customer, payment, credential, …) is **inferred** a crown jewel and marked
`crown_jewel_basis="inferred:<signal>"` — so a missed tag doesn't hide a target,
and the guess is auditable (the dashboard shows *crown jewel (inferred)*). An
explicit owner tag always wins.

### Supply-chain provenance (SBOM, signing, SLSA)

The modern breach often starts before runtime — a tampered build, an unsigned
image, a poisoned dependency. The **supply-chain collector** (`/ingest/supplychain`)
stamps each image with its trust signals and bill of materials, assembled from
the tools you already run:

```bash
syft "$IMG" -o cyclonedx-json > sbom.json
cosign verify "$IMG"                                  && SIGNED=true  || SIGNED=false
cosign verify-attestation --type slsaprovenance "$IMG" # SLSA build attestation
curl -X POST "$INGEST/ingest/supplychain" -d "{\"image\":\"$IMG\",\"signed\":$SIGNED,\"slsa_level\":3,\"sbom\":$(cat sbom.json)}"
```

The image gets `signed` / `slsaLevel` / `sbomComponents`, and every SBOM
component becomes a `Library`/`Package` the image **DEPENDS_ON** (the full bill,
not just the vulnerable parts Trivy flags). Crucially, an **unsigned image is
treated as a tampering vector**: the built-in invariant
**`no-internet-to-unsigned-image`** fires when one is reachable from the internet,
and the kill chain flags the image **⚠ unsigned** — so "this prod image isn't
signed *and* sits on a path to the crown jewel" surfaces as a policy violation,
not a footnote. `sbom` accepts a plain component list or a CycloneDX document
(raw `syft`/`trivy` output), so real tool output drops in unchanged.

### Closing the loop: drift, detection-as-code, SIEM export

Analysis without action is a report. PerspectiveGraph pushes its findings into
the daily workflow:

- **Drift alerting** — the analyzer diffs each pass and fires a webhook
  (Slack-format or generic JSON for SOAR) when a **new** attack path appears:
  *":rotating_light: 3 new critical attack paths: internet → … → cluster-admin (52%)"*.
  The sticky feature — you hear about a regression the moment a deploy introduces it.
- **Detection-as-code** — every path generates **Falco + Sigma** rules that
  *detect* exploitation of its exposed workload (scoped by container/namespace,
  referencing the path's CVE and crown jewel). Remediation cuts the path;
  detection watches it — closing the offense→defense loop.
- **SIEM enrichment export** — `GET /export/ndjson` streams one record per asset
  on a critical path (`on_critical_path`, `max_path_score`, `kev`,
  `runtime_confirmed`, …) in the NDJSON shape Splunk/Elastic/Sentinel ingest, so
  your SIEM can prioritize alerts about hosts that sit on a reachable path.
- **Verified remediation** — every generated fix records the exact edge it cuts,
  so the API *proves* it works: applying it is simulated (what-if) and the plan
  shows **"✓ verified · removes N paths · −X%"** instead of trusting the
  generator. A scaffold that doesn't actually reduce risk is flagged
  **"⚠ unverified"**.
- **Owned tickets** — raise a tracked, **owned** remediation ticket for a path
  (one open ticket per path, with status), recorded locally and optionally
  dispatched to an external tracker (`TICKET_WEBHOOK_URL` → Jira/GitHub/SOAR;
  dry-run when unset). The dashboard shows **"Ticketed · owner"** and closes it
  when done — the finding→fix→done loop, with accountability.

```bash
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/… make run-backend   # drift → Slack
curl -s $API/export/ndjson | head                                       # SIEM enrichment feed
```

### Choke-point remediation optimizer

Most critical paths share a handful of edges, so the question that matters isn't
"what are the 50 paths" but "what is the *smallest set of fixes* that removes the
most risk". The **Remediation** view answers it: a weighted greedy set-cover over
the generated artifacts ranks them so the top entries are the few fixes that
neutralize the most critical-path risk — e.g. *"5 fixes eliminate 92% of
critical-path risk"* — each with the ready-to-apply Terraform/NetworkPolicy and
an honest residual for paths needing manual review. The artifact catalog covers
the full ontology, including the newer edge types: an **IAM privilege-escalation**
path (`CAN_ESCALATE_TO`) yields a deny-the-primitive policy, and a **cloud
lateral-movement** edge (`CONNECTS_TO`) yields a security-group segmentation rule.

### Honest probabilities: provenance, not false precision

A CISO who asks "why 58%?" deserves better than "we multiplied some estimates".
Every edge weight now declares **where it came from**, and every path a
**confidence band** built from that provenance:

- **kev / epss / runtime** — evidence: observed exploitation (CISA KEV), a
  data-driven prediction (FIRST EPSS), or a live Falco runtime alert.
- **cvss / severity / heuristic** — estimate: a CVSS-anchored guess, a bare
  severity label, or an assumed topology/identity default.

Each hop in the kill chain is tagged (**KEV**/**runtime** green, **assumed** grey)
and mapped to a **MITRE ATT&CK technique + tactic** (`T1190 · Initial Access`,
clickable to the ATT&CK page; also shown on the highlighted graph edges) — so a
probability-ranked route reads as a recognizable kill chain a defender can map to
detections and controls. The path also carries `confidence` + a `confidenceLabel`
(**high / medium / low**)
— the mean trustworthiness of its hops. So *"58%, **low confidence** — rests
mostly on severity heuristics, here are the assumed hops to validate"* replaces a
falsely-precise number. A path resting on a KEV CVE and a runtime alert reads as
**high confidence** even at the same score as an all-heuristic one. The score
itself is unchanged — what's added is the honesty about how much to trust it.

The same honesty applies to the **independence assumption** baked into `∏p`: the
product treats every hop as independent, which understates the risk when several
hops share a common cause (one weakness gating multiple steps). So each path also
carries `scoreUpperBound` — the weakest hop, `min p`, the score if the hops are
perfectly correlated — and a `correlatedHops` flag when two or more hops rest on
the same weight basis. The real exploitability lives in **`[score, scoreUpperBound]`**,
and the UI shows *"↑ up to X% if correlated"* instead of pretending the point
estimate is exact.

### Data hygiene: a map of the attack surface, never a vault of secrets

PerspectiveGraph ingests raw scanner output, which can incidentally carry a **live
credential** — a hardcoded AWS key in a Semgrep snippet, a token on a Falco
command line. The graph is a map of *how to attack the org*, so the one thing it
must never become is a store of those secrets: a single read of the attack map
would otherwise hand an attacker working keys. At ingest, high-precision secret
patterns (AWS/GitHub/Slack/Google tokens, PEM private keys, JWTs, `secret=…`
assignments) are **redacted out of property values** before they reach the store —
you still learn *"an AWS key is hardcoded in `config.py:7`"*, you just never store
the key (`***redacted:aws-access-key***`, node stamped `secrets_scrubbed`).
Identifiers the graph joins on (ids, names, commit SHAs, image digests, refs) are
deliberately left untouched. On by default (`SCRUB_INGEST`); retention of the
scrubbed findings is governed by `GRAPH_TTL` — the graph is derived and
re-seedable, so nothing sensitive needs to live there long-term.

### Validated against reality (precision & recall)

A modeled attack path is a hypothesis until something walks it. PerspectiveGraph
takes the verdict back in: a **red-team or BAS platform** (Caldera, AttackIQ,
SafeBreach, Cymulate…) — or a human — records whether a path is **confirmed**
(exploitable end-to-end), **refuted** (a false positive — tested, not
traversable), **partial**, or **missed** (a real path the engine *didn't*
surface). From those verdicts it computes the trust metric a security tool
otherwise hand-waves:

```
precision = confirmed / (confirmed + refuted)   # of surfaced+tested paths, how many were real
recall    = confirmed / (confirmed + missed)     # of real paths, how many we surfaced
```

```bash
# A BAS run (or a human) posts the result; admin when auth is on.
curl -s -X POST "$API/validations" -H 'Content-Type: application/json' -d '{
  "pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","evidence":"atomic T1190"}'
curl -s "$API/validations" | jq .metrics      # precision / recall over the tested subset
```

It's deliberately **not** a global precision/recall claim (that needs exhaustive
ground truth) — it's "here's the evidence on what was actually tested", which is
how trust is earned. The dashboard shows a **Validation** card (precision) and a
**✓ validated real / ✗ refuted** badge on each tested path; set `VALIDATIONS_PATH`
to persist. `make seed-validation` records sample verdicts against the live paths.

### Quantified risk, what-if & compliance export

A path score answers "how exploitable is *this* route". Boards and auditors ask
harder questions, and PerspectiveGraph answers them:

- **Monte Carlo risk quantification** (`riskSimulation`) — each trial realizes
  every edge independently, then checks crown-jewel reachability. Over thousands
  of trials it estimates **P(crown jewel compromised)** with a 95% confidence
  interval, plus **P(at least one crown jewel compromised)** and the expected
  number that fall. Unlike `∏p`, it accounts for the many routes that share edges
  — in the demo, *P(account compromise) ≈ 1.0, ~5 crown jewels expected to fall*.
  The headline is honest about its own uncertainty: alongside the sampling CI it
  reports a **sensitivity band** (the answer when the heuristic per-edge
  probabilities are scaled ±30%), shown as *“modeled X–Y%”* — a tight band means
  trust the number, a wide one means treat it qualitatively.
- **K-shortest paths** (`kShortestPaths`) — Yen's algorithm lists the top-K routes
  to a crown jewel, so you see the near-best alternates a single edge-cut would
  leave standing.
- **What-if simulation** (`whatIf`) — propose a set of edges to cut and get the
  surviving paths and the **residual risk** (before → after, with enough trials
  to make the delta meaningful): *"cut this edge → account compromise 100% →
  99.9%, 11 paths remain"*. Available right in the dashboard: hit **“what-if”**
  on any hop of a kill chain to simulate cutting it.
- **OSCAL compliance export** — `GET /export/oscal` renders the posture as a NIST
  **OSCAL 1.1.2 assessment-results** document: each attack path becomes an
  observation + risk, and each undermined **NIST 800-53 control** (SC-7, AC-6,
  RA-5, SI-2, AC-2 for IAM privesc, SI-4/IR-4 when runtime-confirmed, …) a
  not-satisfied finding — the language GRC tooling and auditors actually consume.

Both exports — OSCAL and the SIEM NDJSON enrichment feed — download straight from
the dashboard header (**↓ OSCAL** / **↓ SIEM**), or over HTTP:

```bash
curl -s "$API/export/oscal" > oscal.json   # NIST OSCAL assessment-results
```

### Triage & suppression (close the false-positive loop)

A finding nobody can dismiss is a finding nobody trusts. PerspectiveGraph has a
first-class **triage loop**: from any attack path, record a decision that takes
it off the active board — **accept-risk**, **false-positive**,
**mitigating-control** or **duplicate** — with an **accountable owner**, an
optional note, and an optional **expiry** after which the path automatically
returns to the board (so *"accept for 30 days"* can't silently become *"accept
forever"*). The overview then headlines **active** paths and shows how many are
suppressed; the list dims and labels them and hides them behind a *Show
suppressed* toggle. The suppression board is the audit of the tool's *own*
findings — who decided what, and why.

```bash
# Suppress a path (admin when auth is on); expires automatically after ttlDays.
curl -s -X POST "$API/suppressions" -H 'Content-Type: application/json' -d '{
  "pathId": "ap-1a2b-3c4d", "reason": "mitigating-control",
  "owner": "secops@acme", "note": "WAF rule blocks this", "ttlDays": 30 }'
curl -s "$API/suppressions"                       # the triage board (incl. expired)
curl -s -X DELETE "$API/suppressions/ap-1a2b-3c4d"  # un-suppress
```

Set `SUPPRESSIONS_PATH` to persist decisions across restarts (else they live in
memory only). Each `attackPath` in GraphQL now carries `suppressed` and a
`suppression { reason owner note createdAt expiresAt }`.

### Trends, MTTR & regressions (the temporal layer)

A scanner tells you what's wrong *now*; security is managed on *trends*. The
analyzer folds every pass into a history, so PerspectiveGraph answers the
questions a point-in-time tool can't:

- **"How long has this path been open?"** Every attack path carries a
  `firstSeen`/`openForSeconds`, surfaced as an **"open 5d"** badge — persistence,
  not just existence, is what you triage on.
- **MTTR.** When a path stops appearing (fixed, or its asset went away) it's
  marked resolved; *resolved − first_seen* is its time-to-remediate, rolled up
  into an **MTTR** card — the accountability metric management actually asks for.
- **Regressions.** A path that resolved and came back is flagged **"⟳ reopened
  N×"** — the deploy-introduced-it-again signal, distinct from a brand-new path.
- **Exposure trend.** A sampled (critical-paths, account-compromise %) series
  drives a **sparkline** on the overview: a rising line is a regression to chase,
  a falling one is progress you can show a board.

It's all in GraphQL (`history { trend mttrSeconds openPaths resolvedPaths
oldestOpenSince }`, plus `firstSeen`/`openForSeconds`/`reopens` per path); set
`HISTORY_PATH` so "open for 5 days" survives a restart (else it's in-memory).

### Identity resolution you can trust (confidence + explainability)

Correlation across tools is only as good as the joins underneath it. When the
normalizer **infers** a link rather than reading one a tool asserted — e.g.
stitching a runtime container to the image a scanner reported — it now records
**how** and **how sure**: a digest pin is an exact identity (`1.0`), a tagged
ref is strong (`0.85`), a bare name is a weak correlation worth verifying
(`0.6`), and a weaker join lowers the stitched edge's probability so a path
resting on a shaky correlation scores below one built on a hard identity. The
provenance rides on the node (`resolutionMethod` / `resolutionConfidence` /
`resolutionAlias`) and surfaces in the kill chain as a **"⚠ heuristic join · N%"**
badge — so an analyst can *see, and distrust,* a heuristic correlation instead
of mistaking it for ground truth.

### Threat-intel: KEV + EPSS (optional)

Severity is a label; *exploitation* is a fact. Enable the threat-intel layer and
PerspectiveGraph enriches every CVE with **CISA KEV** (the catalog of
vulnerabilities *known exploited in the wild*) and **FIRST EPSS** (the
probability of exploitation in the next 30 days). KEV/EPSS reweight the `AFFECTS`
edge so path scores reflect real exploitation likelihood, not a severity guess —
and a KEV CVE on a *reachable, runtime-confirmed* path is the strongest
prioritization signal there is: theoretical → exploited-somewhere → exploited-here.

```bash
THREATINTEL=on make run-backend   # fetches live from CISA + FIRST (cached)
```

Disabled by default (zero network); the `AFFECTS` edge then keeps its
severity-derived weight.

### Auth, multi-tenancy & audit (optional, but do it before production)

Every door is open by default for zero-config local dev — and the backend
**logs a loud warning** when it is. The trust layer:

- **Ingest webhooks (write path)** — HMAC-SHA256 of the request body, keyed by a
  **per-tenant** secret that never travels on the wire (GitHub/Stripe model).
  Senders add `X-PerspectiveGraph-Signature: sha256=<hex>` and `X-Tenant: <id>`.
- **GraphQL API (read path)** — a bearer credential: a static token mapped to a
  role+tenant, or an **OIDC/JWT** (RS256, verified against the JWKS; `role` and
  `tenant` claims). RBAC roles are `viewer` / `operator` / `admin`; GraphiQL is
  disabled when auth is on, and the dashboard is built with `VITE_API_TOKEN`.
- **Multi-tenancy** — each tenant's assets live in their **own isolated graph**
  (a separate Apache AGE graph + search index). Ingest routes by the
  authenticated tenant; queries are scoped to it. A tenant can never read or
  write another's data.
- **Immutable audit log — of *reads*, not just writes.** The tool is a map of how
  to breach the org, so *who looked at it* matters as much as who changed it. Every
  request and denial, **every view of the attack paths or the graph**
  (`view.attack_paths` / `view.graph` — with the path ids seen), and **every export**
  (`export.oscal` / `export.ndjson` — the moment the whole map leaves the tool) is
  appended to a **hash-chained** JSONL file (each record links to the previous via
  SHA-256, so tampering is detectable). It answers "who saw — or exfiltrated —
  which attack paths". Verify the chain any time:

  ```bash
  perspectivegraph verify-audit /var/log/perspectivegraph/audit.log
  # → audit chain OK: N records verified
  ```

```bash
# Single-tenant, signed + token-gated, with an audit trail:
INGEST_HMAC_SECRET=$(openssl rand -hex 32) \
API_TOKENS=$(openssl rand -hex 16):admin \
AUDIT_LOG_PATH=./audit.log \
  make run-backend
```

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
http://localhost:8080/graphql. Prefer Postman? Import
[`docs/perspectivegraph.postman_collection.json`](./docs/perspectivegraph.postman_collection.json) —
health checks, every ingest webhook (with the demo payloads embedded) and all
GraphQL queries, ready to run.

Pointing it at a **real environment** (your own scanners, not the demo seed)?
Follow the [onboarding runbook](./docs/ONBOARDING.md) — per-source `curl`/CI
snippets, the identifier-correlation helper, and a "no paths?" troubleshooting
guide.

## Container & compose hardening

The images and the compose stack are built to the bar you'd expect in a review:

- **Tiny, reproducible images.** The backend is a multi-stage build → a static
  (CGO-off, `-trimpath`, stripped) binary on `distroless/static:nonroot` — **~14 MB,
  no shell, no package manager, no root.** The dashboard is a Vite build served by
  nginx-alpine. Every base image (incl. Postgres/AGE, NATS, OpenSearch) is **pinned
  by SHA-256 digest**, not a floating tag — reproducible and tamper-evident.
- **Least privilege at runtime.** Every compose service sets
  `no-new-privileges:true`; the backend additionally runs `read_only: true`,
  `cap_drop: [ALL]`, non-root, with a `tmpfs` `/tmp` — it writes nothing to disk.
- **No accidental exposure.** All published ports bind to `127.0.0.1`, so a laptop
  demo never puts Postgres/NATS/OpenSearch/the API on the LAN. OpenSearch's demo
  security plugin is explicitly disabled only behind the opt-in `search` profile.
- **Real health gating.** The backend ships a `healthz` subcommand (the distroless
  image has no shell/curl) used as its Docker `HEALTHCHECK`; the dashboard waits on
  `condition: service_healthy`, which in turn waits on Postgres/NATS being healthy —
  so `make up-full` comes up in the right order, every time.
- **CI scans the supply chain** — `govulncheck`, `npm audit`, and a Trivy image scan
  gate the build, plus an **AGE store integration job** (Postgres+AGE service
  container) that exercises the real, hand-written Cypher path — including an
  injection round-trip — that unit tests with the in-memory store can't cover
  (see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)).

### Application hardening

Beyond the container surface, the backend itself is built defensively:

- **Cypher injection defense (AGE store).** Values are wrapped in a *randomized*
  dollar-quote tag a value provably can't contain, single-quote-escaped, and
  labels/edge-types are validated against the ontology allowlist (graph names
  against a strict identifier pattern) — so attacker-influenceable scanner output
  (image tags, IAM role names, file paths) can never break out into SQL.
- **Per-IP rate limiting.** Token-bucket caps on the ingest webhook and the API
  (`INGEST_RATE_RPS` / `API_RATE_RPS`) blunt floods before any work is done.
- **Transport timeouts.** Both HTTP servers set explicit `ReadHeader`/`Read`/
  `Write`/`Idle` timeouts (Go's defaults are *none*), so slow-client / Slowloris
  connections can't pin resources; outbound clients (JWKS, forge APIs, webhooks)
  are timeout-bound with size-capped response reads.
- **CORS allowlist, not `*`.** `CORS_ALLOWED_ORIGINS` echoes only allow-listed
  browser origins (default: the dev/demo dashboards), so a page an analyst visits
  can't probe the API. **Fail-closed OIDC:** with `OIDC_JWKS_URL` set, the backend
  refuses to start without `OIDC_ISSUER` and `OIDC_AUDIENCE` (no unvalidated iss/aud).
- **Self-applied SAST.** CI runs `gosec` (static security analysis of the tool's
  own Go) and `gitleaks` (secret scan) alongside `govulncheck` + Trivy — a security
  tool held to the bar it sets.
- **At-rest encryption of its own crown-jewel data.** `STORE_ENCRYPTION_KEY`
  encrypts the governance stores (suppressions/tickets/validations/history) **and
  the audit log** with AES-256-GCM, so a stolen volume or backup doesn't hand over
  the attack map plus who-viewed-it in plaintext. (Reads pre-encryption files
  transparently — a one-way migration.)
- **Signed exports.** With `EXPORT_SIGNING_KEY` (Ed25519) the OSCAL/SIEM exports
  carry a detached signature (`X-PerspectiveGraph-Signature`); a consumer fetches
  the public key at **`GET /export/pubkey`** and verifies integrity + origin.
- **Abuse detection on its own data.** Repeated failed auth from one IP triggers a
  temporary **lockout** (`AUTH_LOCKOUT_THRESHOLD`, HTTP 429); an unusual volume of
  attack-path reads/exports by one principal raises an **exfiltration alert**
  (`EXFIL_ALERT_THRESHOLD`) — both logged and written to the audit log.
- **Token lifecycle & object-level RBAC.** API tokens take an optional **expiry**
  (`token:role:tenant:YYYY-MM-DD`) and can be stored **hashed** (`sha256$<hex>`) so
  the live secret never sits at rest; a token (or OIDC `apps` claim) can be scoped
  to a set of **applications**, restricting *reads* (paths, graph, violations,
  exports, search) to those apps — enforced once at the data boundary, no bypass.
- **Fail-loud persistence.** `GRAPH_STRICT=true` refuses to start if Apache AGE is
  unreachable instead of silently falling back to the non-persistent in-memory
  store. Events that exhaust redelivery go to a **dead-letter stream**, not the void.
- **Observability built in.** Prometheus metrics at **`GET /metrics`** (ingest /
  normalize / analyzer-pass timing / dead-letters + Go runtime), so you don't
  operate it blind.
- **Throughput.** The AGE store uses a real connection pool (not a single pinned
  connection) and creates a per-label `id` index, turning per-upsert scans into
  index lookups.
- **Queryable graph, honest traversal.** Node and edge properties are stored as
  **native agtype** (the graph is queryable in Cypher, not a JSON blob). Path
  finding uses the **in-process Dijkstra by default** — polynomial and bounded. A
  DB-side Cypher finder is an **opt-in** (`ANALYZER_DB_PATHS`): since AGE has no
  weighted shortest-path it *enumerates* paths (unbounded worst-case), so it's
  safe-railed with a `statement_timeout` + `LIMIT` and falls back to Dijkstra on a
  runaway query. Legacy JSON-blob data is still read, so upgrades don't lose paths.
- **Replica-safe side-effects.** Run more than one backend replica and each still
  computes attack paths locally (warm API reads), but **at-most-once** external
  actions — drift webhooks and PR/MR comments — fire only from the **leader**,
  elected via a Postgres advisory lock with automatic failover. No duplicate
  notifications, no external coordinator.

> Hardening is layered, not absolute: the default Postgres password and open
> auth are deliberate **local-dev** defaults (the backend logs a loud warning).
> Set `POSTGRES_PASSWORD`, `INGEST_HMAC_SECRET` and `API_TOKENS`/OIDC before any
> shared or production deployment — see [`.env.example`](./.env.example).

## Deploy to Kubernetes

A Helm chart bundles the backend, dashboard, Postgres+AGE, and NATS:

```bash
# Build & push images (or use your registry / prebuilt ones)
docker build -t ghcr.io/luiacuaniello/perspectivegraph:latest backend
docker build -t ghcr.io/luiacuaniello/perspectivegraph-dashboard:latest frontend

# Install
helm install perspective deploy/helm/perspectivegraph \
  --set github.token=$GITHUB_TOKEN \
  --set opensearch.url=""           # optional full-text index
```

Bring your own managed Postgres/NATS by disabling the bundled ones and pointing
the chart at the external endpoints:

```bash
helm install perspective deploy/helm/perspectivegraph \
  --set postgres.enabled=false \
  --set postgres.externalHost=my-postgres.example.internal \
  --set postgres.auth.user=perspective --set postgres.auth.password=… \
  --set nats.enabled=false \
  --set nats.externalUrl=nats://my-nats.example.internal:4222
```

The external Postgres must have the [Apache AGE](https://age.apache.org/)
extension installed and the graph created (see
[`deploy/postgres/init-age.sql`](./deploy/postgres/init-age.sql)). All knobs:
[`deploy/helm/perspectivegraph/values.yaml`](./deploy/helm/perspectivegraph/values.yaml).

### Hardening a real deployment (beyond a trusted cluster)

The default chart runs **unauthenticated with in-memory governance** — fine for a
demo inside a trusted cluster, but this tool is a *map of how to attack the org*,
so anything reachable beyond that boundary must turn the controls on. The chart
surfaces them as first-class values:

```bash
helm install perspective deploy/helm/perspectivegraph \
  --set auth.apiTokens="$(openssl rand -hex 16):admin" \   # bearer auth on the API (token:role[:tenant])
  --set ingest.hmacSecret="$(openssl rand -hex 16)" \      # scanners must sign ingest bodies
  --set persistence.enabled=true \                         # PVC for the governance stores + audit log
  --set graph.ttl=168h \                                   # prune stale assets (phantom paths)
  --set postgres.auth.password="$(openssl rand -hex 16)"   # don't ship the demo default
```

- **`auth.apiTokens` / `auth.oidc.*`** — without a token the API is open; set
  static tokens and/or OIDC (`issuer`/`audience`/`jwksUrl`). `auth.apiRateRps` /
  `auth.ingestRateRps` cap per-IP request rates (0 disables).
- **`ingest.hmacSecret` / `ingest.hmacSecrets`** — HMAC-sign ingestion so nobody
  can forge scanner data on the open ingest port.
- **`persistence.enabled`** — mounts a ReadWriteOnce PVC so suppressions, tickets,
  red-team validations, MTTR/posture history and the **tamper-evident audit log**
  survive restarts (in-memory and lost otherwise). Because the stores are
  single-writer, the chart **refuses to render with `backend.replicas > 1`** while
  persistence is on — scale-out would split-brain them.
- The release prints a ⚠ in `NOTES` whenever auth or persistence is left off, so
  an insecure exposure is never silent.
- **Startup ordering** — the backend has `initContainers` that block on the bundled
  Postgres:5432 and NATS:4222 before it boots, so a fresh install connects to
  Apache AGE on the first try instead of crash-looping on NATS or *silently* falling
  back to the in-memory graph when Postgres is slow. (External Postgres/NATS are
  assumed reachable and aren't gated.)

## Operating it: freshness, backup & DR

A correlation engine that only *adds* drifts toward fiction: a pod is deleted, a
security group is torn down, but the path through it lingers and gets reported
forever. Two things keep the graph honest over time.

- **Staleness pruning (`GRAPH_TTL`).** Every node and edge is stamped with a
  `last_seen` time on each observation. When `GRAPH_TTL` is set, the analyzer
  (leader-only, on a derived cadence ≈ TTL/6) removes anything not re-observed
  within the window, so a **departed asset stops generating phantom paths**.
  Pruning a node detaches its edges; elements that predate the stamp are
  *grandfathered* (never pruned) so turning the feature on can't wipe legacy
  data. It's off by default (the one-shot demo would prune itself); set it to a
  few feed-cycles in production:

  ```bash
  GRAPH_TTL=168h make run-backend      # 7 days; assets unseen for a week are dropped
  ```

  Visibility: the dashboard footer shows *“pruned N stale”*, the GraphQL
  `status { prunedNodes prunedEdges lastPrunedAt }` exposes the totals, and
  Prometheus has `perspectivegraph_graph_pruned_{nodes,edges}_total`.

- **The graph is *derived* state — that's your DR story.** Everything in
  Postgres+AGE is reconstructible by re-ingesting the source feeds, so a lost
  database is a *re-seed*, not a data-loss event. Back up Postgres for history
  and convenience (`pg_dump` of the AGE-extended database, or a managed
  Postgres's PITR/replica); restore, or just re-run the collectors, to recover.
  For HA, run Postgres as a managed/replicated service (the chart can point at an
  external one) — the backend is stateless and horizontally scalable, and
  leader election already ensures only one replica fires side-effects.

> **On Apache AGE (an honest caveat).** AGE is a younger, less battle-tested
> extension than core Postgres. PerspectiveGraph de-risks leaning on it: node and
> edge analysis runs over an in-process snapshot by default (the DB is storage,
> not the query engine, unless you opt into `ANALYZER_DB_PATHS`), the in-memory
> and AGE stores are held to one shared contract-test suite, and `GRAPH_STRICT`
> makes a misconfigured DB fail loudly. Because the graph is rebuildable, an AGE
> issue is an availability concern, not a correctness or data-durability one.

## Project status

**Implemented end-to-end, with tests.** Ten ingestion collectors, a NATS bus,
in-memory + Apache AGE graph stores (kept in lockstep by a shared contract-test
suite), the attack-path analyzer (scoring, Monte-Carlo risk, k-shortest, what-if,
MTTR/trend, TTL pruning), policy invariants, **MITRE ATT&CK** technique mapping,
GitHub/GitLab commenters, auto-remediation + Falco/Sigma detection-as-code,
OSCAL/SIEM exports, optional OpenSearch search, a GraphQL + REST API, and a
React/Cytoscape dashboard with **light/dark** themes. The tool's own security is
first-class: ingest HMAC, bearer/OIDC auth with role + **per-application RBAC**,
a tamper-evident **audit log**, **at-rest encryption**, **Ed25519-signed exports**,
and auth-lockout + exfiltration alerting — plus a Helm chart that surfaces all of
it. The graph store defaults to Apache AGE and falls back to in-memory for
zero-dependency dev. See [the roadmap](./ARCHITECTURE.md#roadmap) for what's next.

## License

[Apache License 2.0](./LICENSE).
