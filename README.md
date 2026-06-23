# PerspectiveGraph

[![CI](https://github.com/luiacuaniello/perspectivegraph/actions/workflows/ci.yml/badge.svg)](https://github.com/luiacuaniello/perspectivegraph/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/luiacuaniello/perspectivegraph?sort=semver)](https://github.com/luiacuaniello/perspectivegraph/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/luiacuaniello/perspectivegraph?filename=backend%2Fgo.mod)](backend/go.mod)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> **Catch the attack path in the pull request that opens it - then ship the fix as a PR.**

On every pull request, PerspectiveGraph (open source, Apache 2.0) answers one question against a
graph of your *real* environment - built from the scanners you already run (Trivy, Semgrep, Cloud
Custodian, Falco):

> *Does this change open a path from the internet, through excessive privilege, to something valuable?*

When it does, the **PR check goes red** - a required status you can block the merge on - and you get
the **fix as its own one-click pull request**. The reachable attack path is caught and closed in code
review, where it's cheapest, not months later in production. This is **shift-left attack-path
analysis**: not a scanner bolted onto CI, not a runtime CNAPP you log into after the fact - the
reachability question, answered *in the developer's workflow*.

That gate is powered by a full attack-path correlation engine, so the same graph also gives you the
rest: a queryable dashboard of your **~5 critical attack paths** (not 10,000 flat findings), triage,
runtime confirmation, an AI summary, and always-current architecture maps. **But the wedge is the
pull request.**

> 🇮🇹 **In italiano?** La [Guida completa (docs/GUIDA.md)](docs/GUIDA.md) spiega come avviare/spegnere
> tutto (con e senza Docker), come provarlo sui tuoi progetti e il significato dei dati in dashboard.

![PerspectiveGraph dashboard - security posture overview](docs/screenshot-overview.png)

<details>
<summary>More: ranked attack paths with kill chain, and the choke-point remediation optimizer</summary>

![Attack path detail - kill chain and suggested remediation](docs/screenshot-paths.png)

![Remediation plan - the fewest fixes that eliminate the most critical-path risk](docs/screenshot-remediation.png)

</details>

## Why?

Modern security teams don't suffer from a lack of tools - they suffer from **noise, fragmentation,
and missing context**.

| Role | Pain today | What PerspectiveGraph gives them |
| --- | --- | --- |
| **Developer** | CI/CD blocked by thousands of irrelevant CVEs | A PR check that goes red *only* when the change opens a real internet→crown-jewel path - plus the fix as a one-click PR |
| **Security** | Triage on flat lists of 10,000 findings | A ranked list of ~5 critical **attack paths**, queryable like a database |
| **Architect** | No live view of how IaC becomes attack surface | Auto-generated, always-current architecture & data-flow maps + drift detection |

## The core idea

We model the whole environment as a directed graph `G = (V, E)`:

- **Vertices `V`** - assets, identities, and findings (`Container`, `IAM_Role`, `CVE`, ...)
- **Edges `E`** - relationships (`HOSTS`, `ASSUMES`, `AFFECTS`, `EXPOSES`, ...)

An **attack path** `P` is a sequence of nodes `v₁ → v₂ → … → vₖ` from an *Internet-Exposed* node to a
*Crown Jewel*. The **baseline** score composes the per-edge exploit probabilities:

```
S(P) = ∏  p(vᵢ, vᵢ₊₁)
      i=1..k-1
```

Taking `-ln` turns this into an additive cost `w = -ln p`, so the **highest-probability path is the
shortest path** - found with Dijkstra from every internet-exposed seed, then surfaced as
**Critical Attack Path** events.

That product is only the *starting point*: it assumes the hops are independent and treats a heuristic
guess like measured evidence. The engine is honest about all three gaps, and the layers are what make
it a risk tool rather than a number generator (see [Honest probabilities](#honest-probabilities-provenance-not-false-precision)):

- **Correlation** - the product assumes independent hops, so it also reports `scoreUpperBound` (the
  shared-cause bound) and flags `correlatedHops`; the real value lies in `[score, scoreUpperBound]`.
- **Epistemic uncertainty** - each `p` is a **Beta posterior** whose width reflects its evidence
  (KEV/runtime tight, heuristic wide), propagated to a 90% **credible interval** on the score.
- **The independence fix** - the score is also marginalized over a latent **attacker capability**,
  `S(P) = Σ_c P(c)·∏ p(e|c)` (commodity/criminal/APT), which reintroduces the correlation the bare
  product drops and yields a per-profile breakdown. The **headline risk** (`riskSimulation`) is
  marginalized the same way (`Σ_c P(c)·R_c`, `mixtureCompromiseProbability` + `profileCompromise`), so
  the environment-level number and the per-path scores share one correlation model instead of the
  Monte Carlo silently assuming independent edges.
- **Calibration** - red-team/BAS verdicts grade the scores against reality (Brier/ECE + a diagnosis),
  so "55%" is a *defensible probability*, not a label - the line between a demo and production.

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
- **Search:** OpenSearch *(optional - `make up-search` + `OPENSEARCH_URL=http://localhost:9200`)*
- **Threat intel:** CISA KEV + FIRST EPSS *(optional - `THREATINTEL=on`)*
- **API:** GraphQL
- **Frontend:** React + TailwindCSS + [Cytoscape.js](https://js.cytoscape.org/)
- **Sensors:** Trivy, Semgrep, Cloud Custodian, Falco, CI build-provenance (`/ingest/build`), supply-chain cosign/SLSA/SBOM (`/ingest/supplychain`)
- **Discovery:** Kubernetes (`/ingest/k8s`, incl. **container-escape** detection → ATT&CK T1611), cloud-network (`/ingest/cloudnet`), IAM privilege-escalation graph (`/ingest/iam`), and SSO/IdP federation (`/ingest/sso`)
- **Data classification:** Macie/DLP findings (`/ingest/dataclass`) mark assets as crown jewels with an authoritative `classified:<source>:<kind>` basis
- **Agentless connectors:** scheduled, leader-only **PULL** sources that reach out to a cloud account instead of waiting for an upload (`CONNECTORS_ENABLED`, health at `GET /connectors`). First connector: **AWS** (`aws`)
- **Multi-tenant + SSO:** per-tenant isolated graphs (proven by test), bearer/OIDC auth with per-tenant/per-app/role RBAC, and a runtime login gate (`GET /auth/config` → token or "Sign in with SSO")
- **Dev workflow:** GitHub PR comment + a **PR merge-gate status** (red when the change opens an internet→crown-jewel path), and **remediation-as-PR** (`POST /remediation/pr` opens a branch+commit+PR with the fix)
- **AI-native (Claude *or* HuggingFace):** natural-language Q&A over the graph, a board-level executive summary, and plain-English path explanations - grounded in the live attack paths (`ANTHROPIC_API_KEY`, or a free `HF_TOKEN`)
- **ATT&CK:** each kill-chain hop mapped to a MITRE ATT&CK technique + tactic

## Quick start

**See the wedge in ~90 seconds** - bring up the stack, seed it, and watch the
findings correlate into the top ranked attack path with its fix:

```bash
make demo           # needs Docker + jq; then open http://localhost:3000
```

See [DEMO.md](DEMO.md) for the walkthrough (and how to turn the fix into a real PR).

**Or step by step (everything in containers):**

```bash
make up-full        # builds & runs infra + backend + dashboard (docker compose --profile app)
make seed           # feed the sample sources; they correlate into attack paths
open http://localhost:3000
```

`make up-full` brings up the whole stack - Postgres+AGE, NATS, the Go backend, and
the nginx-served dashboard on **:3000** (which proxies `/graphql` to the backend).
Tear it all down with `make down`. All ports bind to `127.0.0.1`; the backend runs
non-root on a read-only rootfs with every Linux capability dropped (see
[Container & compose hardening](#container--compose-hardening)). The dashboard ships
**light & dark themes** - a header toggle (☀️/🌙) that remembers your choice and
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

`make seed` posts six sources - an infra/identity context, a Trivy report
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

### The wedge: attack paths in your pull request

This is the one to try first - everything else exists to make it accurate. A
finding only changes behavior if it reaches the person who can fix it, where they
already work, so PerspectiveGraph plugs straight into the PR:

- **A PR comment** on the change that sits on a critical path (the kill chain +
  the one-edge fixes).
- **A merge-gate status** - a GitHub commit status `perspectivegraph/attack-paths`
  that goes **red** when the change opens an internet→crown-jewel path and **green**
  once it no longer does. Make it a *required* status check in branch protection
  and it **blocks the merge** - shift-left, not a comment you can scroll past.
- **Remediation-as-PR** - `POST /remediation/pr` (or the **Open fix PR** button on
  a path) branches off the default branch, commits the generated fix
  (NetworkPolicy / Terraform / IAM policy), and opens a pull request. The fix
  arrives as something you *review and merge*, not copy-paste.

One `GITHUB_TOKEN` drives all three (dry-run - logged, not posted - until it's set;
GitHub Enterprise via `GITHUB_API_URL`). The same path context the analyzer already
carries (`repo_slug` / `pr_number` / `commit_sha`) is what routes each action to the
right PR and commit.

Everything below - the connectors, topology discovery, scoring, runtime
confirmation, the dashboard - exists so that red check is *true*: a real, reachable
path, not noise.

### Agentless connectors: pull, don't wait for an upload

A scanner report only helps once someone uploads it. **Connectors** invert that:
they reach *out* to a system on a schedule and pull its current state - no agent
to deploy, no one to remember to `curl`. The goal is the one that won the cloud
security market: *connect a read-only role and see your real attack paths in
minutes.*

Crucially a connector publishes onto the **same bus** as the webhooks, so it
reuses the entire pipeline unchanged - identity resolution, the graph, the
analyzer. The first connector, **`aws`**, doesn't even add new parsing: it pulls
the EC2 `describe-*` network state and IAM authorization details and feeds them
straight into the existing `cloudnet`/`iam` collectors. The acquisition sits
behind a swappable transport - **`fixtures`** (local JSON, so the whole pull
pipeline is provable with zero credentials) and **`aws-sdk-go-v2`** for live AWS
(read-only, optional cross-account `AssumeRole`).

```bash
# Demo (no AWS account): pull from local describe-* JSON
CONNECTORS_ENABLED=aws AWS_CONNECTOR_MODE=fixtures AWS_FIXTURES_DIR=./backend/testdata
curl -s localhost:8081/connectors | jq   # per-connector health: last run, last error, events

# Live (read-only): assume a cross-account role and pull EC2 + IAM
CONNECTORS_ENABLED=aws AWS_CONNECTOR_MODE=sdk AWS_REGION=us-east-1 \
  AWS_ROLE_ARN=arn:aws:iam::<account>:role/perspectivegraph-readonly
# grant only: ec2:Describe*, iam:GetAccountAuthorizationDetails (≈ SecurityAudit)
```

Connectors are **leader-only** (replicas don't multiply API calls), interval-driven
(`CONNECTOR_INTERVAL`), and observable via `GET /connectors` plus
`perspectivegraph_connector_*` Prometheus metrics. SDK mode uses the standard AWS
credential chain (env / shared profile / IRSA / instance role).

### Topology discovery (no hand-stitched IDs)

`make seed-discovery` posts a raw Kubernetes dump (`kubectl get … -o json`), a
cloud-network export (AWS `describe-*`) and an IAM authorization dump
(`aws iam get-account-authorization-details`) - the same shapes the `aws`
connector pulls live. PerspectiveGraph **auto-discovers**
the exposure/reachability topology no scanner produces:

- **Kubernetes** → `Ingress → Service → Pod → ServiceAccount → Role`, surfacing
  e.g. *internet → ingress → pod → cluster-admin* - a privilege-escalation path
  found from cluster config alone. RBAC is modeled in depth: beyond
  wildcard/`admin`-named roles, a role that grants an **escalation primitive**
  (`create pods`, `read secrets`, `bind`/`escalate` roles, `impersonate`,
  mint SA tokens) draws a `CAN_ESCALATE_TO` edge to a synthetic **cluster-admin**
  - BloodHound-for-Kubernetes, not just a name check.
- **SSO / identity federation** (Okta, Entra, …) → the modern front door:
  `IdentityProvider(internet) → AUTHENTICATES → User → ASSUMES → IAM_Role`. The
  federated role is ARN-keyed, so it converges with the IAM graph - a **no-MFA**
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
`crown_jewel_basis="inferred:<signal>"` - so a missed tag doesn't hide a target,
and the guess is auditable (the dashboard shows *crown jewel (inferred)*). An
explicit owner tag always wins.

### Supply-chain provenance (SBOM, signing, SLSA)

The modern breach often starts before runtime - a tampered build, an unsigned
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
and the kill chain flags the image **⚠ unsigned** - so "this prod image isn't
signed *and* sits on a path to the crown jewel" surfaces as a policy violation,
not a footnote. `sbom` accepts a plain component list or a CycloneDX document
(raw `syft`/`trivy` output), so real tool output drops in unchanged.

### Closing the loop: drift, detection-as-code, SIEM export

Analysis without action is a report. PerspectiveGraph pushes its findings into
the daily workflow:

- **Drift alerting** - the analyzer diffs each pass and fires a webhook
  (Slack-format or generic JSON for SOAR) when a **new** attack path appears:
  *":rotating_light: 3 new critical attack paths: internet → … → cluster-admin (52%)"*.
  The sticky feature - you hear about a regression the moment a deploy introduces it.
- **Detection-as-code** - every path generates **Falco + Sigma** rules that
  *detect* exploitation of its exposed workload (scoped by container/namespace,
  referencing the path's CVE and crown jewel). Remediation cuts the path;
  detection watches it - closing the offense→defense loop.
- **SIEM enrichment export** - `GET /export/ndjson` streams one record per asset
  on a critical path (`on_critical_path`, `max_path_score`, `kev`,
  `runtime_confirmed`, …) in the NDJSON shape Splunk/Elastic/Sentinel ingest, so
  your SIEM can prioritize alerts about hosts that sit on a reachable path.
- **Verified remediation** - every generated fix records the exact edge it cuts,
  so the API *proves* it works: applying it is simulated (what-if) and the plan
  shows **"✓ verified · removes N paths · −X%"** instead of trusting the
  generator. A scaffold that doesn't actually reduce risk is flagged
  **"⚠ unverified"**.
- **Owned tickets** - raise a tracked, **owned** remediation ticket for a path
  (one open ticket per path, with status), recorded locally and optionally
  dispatched to an external tracker (`TICKET_WEBHOOK_URL` → Jira/GitHub/SOAR;
  dry-run when unset). The dashboard shows **"Ticketed · owner"** and closes it
  when done - the finding→fix→done loop, with accountability.

```bash
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/… make run-backend   # drift → Slack
curl -s $API/export/ndjson | head                                       # SIEM enrichment feed
```

### Choke-point remediation optimizer

Most critical paths share a handful of edges, so the question that matters isn't
"what are the 50 paths" but "what is the *smallest set of fixes* that removes the
most risk". The **Remediation** view answers it: a weighted greedy set-cover over
the generated artifacts ranks them so the top entries are the few fixes that
neutralize the most critical-path risk - e.g. *"5 fixes eliminate 92% of
critical-path risk"* - each with the ready-to-apply Terraform/NetworkPolicy and
an honest residual for paths needing manual review. The artifact catalog covers
the full ontology, including the newer edge types: an **IAM privilege-escalation**
path (`CAN_ESCALATE_TO`) yields a deny-the-primitive policy, and a **cloud
lateral-movement** edge (`CONNECTS_TO`) yields a security-group segmentation rule.

### Ask your attack surface (AI-native - Claude or HuggingFace)

Set `ANTHROPIC_API_KEY` and the dashboard grows an **AI assistant** powered by
Claude (`claude-opus-4-8`):

- **Natural-language Q&A** - *"which internet-exposed path reaches customer PII
  fastest?"* - answered from the live graph.
- **Executive summary** - a board-ready brief of the current posture: the headline
  risk, what's actively exploited, the top fix.
- **Explain (AI)** - a plain-English walk-through of any single path and the one
  most effective fix, on the path detail.

Every answer is **grounded** in the tenant's actual attack paths - the model is
handed a compact, capped context, so it summarizes your data rather than inventing
assets. The transport is a **hand-rolled** call to Anthropic's `/v1/messages` (no
SDK, no new dependencies - the engine stays pure-Go and auditable).

**Prefer a free model?** If you don't set `ANTHROPIC_API_KEY` but set `HF_TOKEN`
(a free [HuggingFace](https://huggingface.co/settings/tokens) access token), the
same features run against HuggingFace's OpenAI-compatible Inference router instead.
Pick the chat model with `HF_MODEL` (default `meta-llama/Llama-3.1-8B-Instruct`),
and point `HF_BASE_URL` at any OpenAI-compatible endpoint (Together, Groq, a local
Ollama, …) to use those. Anthropic takes precedence when both are set; everything
else (grounding, audit, the dashboard UI) is identical.

Because the graph *is* the org's attack map, sending a compacted view of it to an
external model is a deliberate opt-in: the feature is off until you set the key,
and **every AI call is audited** (`ai.query` / `ai.summary` / `ai.explain`) into
the same tamper-evident log as the rest of the read path.

### Honest probabilities: provenance, not false precision

A CISO who asks "why 58%?" deserves better than "we multiplied some estimates".
Every edge weight now declares **where it came from**, and every path a
**confidence band** built from that provenance:

- **kev / epss / runtime** - evidence: observed exploitation (CISA KEV), a
  data-driven prediction (FIRST EPSS), or a live Falco runtime alert.
- **cvss / severity / heuristic** - estimate: a CVSS-anchored guess, a bare
  severity label, or an assumed topology/identity default.

> **Known input caveat (the kind calibration is built to surface):** EPSS is a
> *marginal* probability - P(any exploitation activity in the wild within 30 days) -
> not the conditional P(an attacker traverses *this* edge in *this* environment) the
> score needs. It's a global base rate (usually small), so taking it as `p(e)` tends
> to *understate* a present attacker. We feed it as-is on purpose and let the
> calibration loop reveal/correct the bias on real verdicts (rather than transforming
> it on a hunch); the `severity → p` anchors (0.9/0.7/0.4/0.2) are deliberate
> heuristics too, which is why they carry low-confidence bases. See
> [`internal/threatintel`](./backend/internal/threatintel) and `internal/ingestion/severity.go`.

Each hop in the kill chain is tagged (**KEV**/**runtime** green, **assumed** grey)
and mapped to a **MITRE ATT&CK technique + tactic** (`T1190 · Initial Access`,
clickable to the ATT&CK page; also shown on the highlighted graph edges) - so a
probability-ranked route reads as a recognizable kill chain a defender can map to
detections and controls. The path also carries `confidence` + a `confidenceLabel`
(**high / medium / low**)
- the mean trustworthiness of its hops. So *"58%, **low confidence** - rests
mostly on severity heuristics, here are the assumed hops to validate"* replaces a
falsely-precise number. A path resting on a KEV CVE and a runtime alert reads as
**high confidence** even at the same score as an all-heuristic one. The score
itself is unchanged - what's added is the honesty about how much to trust it.

The same honesty applies to the **independence assumption** baked into `∏p`: the
product treats every hop as independent, which understates the risk when several
hops share a common cause (one weakness gating multiple steps). So each path also
carries `scoreUpperBound` - the weakest hop, `min p`, the score if the hops are
perfectly correlated - and a `correlatedHops` flag when two or more hops rest on
the same weight basis. The real exploitability lives in **`[score, scoreUpperBound]`**,
and the UI shows *"↑ up to X% if correlated"* instead of pretending the point
estimate is exact.

There is a second, orthogonal uncertainty: not *"are the hops correlated?"* but
*"how well do we even know each `p`?"*. So each edge's probability is treated as a
**Beta posterior** whose width is set by its evidence - tight for a KEV/runtime hop,
wide for a heuristic guess - and propagated through the product to a **90% credible
interval** on the score (`scoreCiLow`/`scoreCiHigh`, the UI's *"90% CI 39-71%"*).
The same per-edge posteriors feed the Monte Carlo headline: instead of a flat ±30%
"sensitivity" wiggle, the band is now an outer epistemic loop that resamples every
edge from its posterior, so *"modeled X-Y%"* is the spread the evidence justifies.
Point estimates are unchanged; what's quantified is how far they could honestly move.

Finally, the deepest fix: `∏p`'s independence assumption is wrong because attack
steps are correlated through a latent variable - **the attacker's capability**. So
the score is also marginalized over a small set of **attacker profiles** (commodity
/ criminal / APT), each with a threat-model prior `P(c)` and a skill that shifts each
hop's odds by how much it actually depends on skill (a public KEV exploit barely, a
heuristic topology guess a lot): `S(P) = Σ P(c)·∏ p(e|c)`. *Within* a profile the
independence is honest; *marginalizing* reintroduces the positive correlation the bare
product drops. The payoff is the per-profile breakdown a SOC triages on -
*"72% vs an APT, 18% vs commodity"* - surfaced on each path. Retune the priors to
your own threat model with `ATTACKER_PROFILE_PRIORS` (the naive score is kept as the
independent baseline; the mixture is the sharper lens on top).

### Triage priority: what to fix first, not 500 findings

A 2-person security team can't act on every reachable path. The raw exploit score
answers *how easy*; it doesn't answer *how much should I care*. So each path also
gets a composite **triage priority** (0–100, banded **P1 / P2 / P3**) that blends
the signals an analyst actually weighs:

- exploitability (`score`) and how much to trust it (`confidence`),
- **runtime-confirmed** (a live Falco alert - it's not theoretical, it's happening),
- a **KEV** weakness anywhere on the route (known-exploited in the wild),
- **target sensitivity** (a classified-PII jewel outranks a name-heuristic guess),
- **blast radius** (an internet entry that opens many paths is higher leverage).

Paths come back **priority-first**, so `attackPaths(limit:5)` *is* the "fix these
today" list, and every priority is **explainable** - it carries the factors
(`"runtime-confirmed (active)"`, `"KEV on path"`, `"classified PII target"`,
`"entry shared by 4 paths"`) rather than a black-box rank. The effect is the
honest re-ranking you want: a **runtime-confirmed path to PII at 36%** outranks an
**uncorroborated 90%** one. (Weights and bands are documented and tunable.)

### Data hygiene: a map of the attack surface, never a vault of secrets

PerspectiveGraph ingests raw scanner output, which can incidentally carry a **live
credential** - a hardcoded AWS key in a Semgrep snippet, a token on a Falco
command line. The graph is a map of *how to attack the org*, so the one thing it
must never become is a store of those secrets: a single read of the attack map
would otherwise hand an attacker working keys. At ingest, high-precision secret
patterns (AWS/GitHub/Slack/Google tokens, PEM private keys, JWTs, `secret=…`
assignments) are **redacted out of property values** before they reach the store -
you still learn *"an AWS key is hardcoded in `config.py:7`"*, you just never store
the key (`***redacted:aws-access-key***`, node stamped `secrets_scrubbed`).
Identifiers the graph joins on (ids, names, commit SHAs, image digests, refs) are
deliberately left untouched. On by default (`SCRUB_INGEST`); retention of the
scrubbed findings is governed by `GRAPH_TTL` - the graph is derived and
re-seedable, so nothing sensitive needs to live there long-term.

### Multi-tenant isolation & SSO login

This tool is, literally, a map of how to attack each customer - so the one thing
it must never do is leak across tenants. Every tenant gets its **own** AGE graph
and search index, and **every** API read funnels through `snapshot(tenantOf(ctx))`,
so a principal scoped to tenant A can never see tenant B's graph or attack paths.
That's the load-bearing security claim, so it's **proven by an end-to-end test**
(two tenants stay disjoint, the default tenant sees neither, id normalization
doesn't break the boundary), with per-tenant + per-app + role (viewer/operator/
admin) RBAC on top.

Login is **runtime, not baked in**. The dashboard reads a public `GET /auth/config`
(auth mode + the IdP's public coordinates - no secrets) and renders the right gate,
so a *single* build serves an open, token-secured, or SSO-secured backend with no
rebuild:

```bash
curl -s localhost:8080/auth/config
# open:  {"authRequired":false,"mode":"none"}
# secured: {"authRequired":true,"mode":"both","oidc":{"clientId":"…","authorizeUrl":"…"}}
```

A user pastes a token or clicks **Sign in with SSO**, which runs the full **OIDC
Authorization-Code + PKCE** flow (S256 challenge, `state` CSRF check, code→token
exchange at `OIDC_TOKEN_URL` - no client secret in the browser; the RFC 7636
derivation is unit-tested). The credential lives only in the tab's `sessionStorage`
and rides as a Bearer - never written to disk or the bundle. Token validation
stays on the JWKS / issuer / audience the backend already enforces (fail-closed:
it refuses to start with a JWKS URL but no `iss`/`aud`).

### Validated against reality (precision & recall)

A modeled attack path is a hypothesis until something walks it. PerspectiveGraph
takes the verdict back in: a **red-team or BAS platform** (Caldera, AttackIQ,
SafeBreach, Cymulate…) - or a human - records whether a path is **confirmed**
(exploitable end-to-end), **refuted** (a false positive - tested, not
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
ground truth) - it's "here's the evidence on what was actually tested", which is
how trust is earned. The dashboard shows a **Validation** card (precision) and a
**✓ validated real / ✗ refuted** badge on each tested path; set `VALIDATIONS_PATH`
to persist. `make seed-validation` records sample verdicts against the live paths.

#### Calibration: does the score mean anything? (the demo→production gate)

precision/recall tell you whether a *surfaced* path was real. Calibration asks the
harder, production question: does the **number** mean anything - do paths scored
~0.8 actually confirm ~80% of the time? Each verdict is captured **with the model's
predicted score at test time** (server-side, so the tester can't fudge it), turning
the verdict log into a calibration dataset. From it the engine reports the scoring
rules a forecaster is judged by:

```
Brier = mean (p - y)²                          # sharpness+calibration, lower better
ECE   = Σ (nₖ/N)·|meanPredₖ - obsRateₖ|         # binned calibration gap, lower better
```

plus a **reliability diagram** (predicted vs observed per bucket; points on the
diagonal are perfectly calibrated), an honest **verdict** (well-calibrated /
overconfident / underconfident), and an **advisory rescale** (`observed/predicted` -
surfaced, *not* silently applied, since rescaling on a thin sample is fitting noise).

```bash
curl -s "$API/validations" | jq .calibration   # brier, ece, verdict, reliability bins
# GraphQL: { calibration { samples brier ece verdict bins { low meanPredicted observedRate } } }
```

This is the artifact that lets an operator stand behind "55%" as a *probability*,
not a vibe - the line between a demo and a risk tool you can put in front of an
auditor. The dashboard renders it as a **Calibration** panel on the Overview.

##### Calibration diagnostics: "and therefore what should we build?"

Knowing you're miscalibrated isn't enough - you need to know *why*, so you don't
build the wrong fix. The report adds three diagnostic lenses over the same verdicts
and folds them into one **diagnosis**:

- **Recalibration** - a **cross-validated** isotonic (monotone) fit gives
  `brierRecalibrated`, the Brier a pure rescale can reach *out-of-sample* (k-fold, so it
  doesn't overfit exactly when data is thin - the real-world case). If it's good, you
  just apply the published `recalibrationMap` (raw → calibrated); the engine never
  silently rewrites scores. A `brierRecalibrated` that stays high means the model lacks
  *resolution* (can't separate real from fake) - the line past which a rescale can't help.
- **Segments** - calibration split by path structure (`correlated-hops` vs
  `independent`, `long` vs `short`). Residual error that concentrates on correlated or
  long paths is *structural* - the independence assumption - and points at a
  correlation-aware model (**#6**, Bayesian Attack Graph).
- **Detection** - of reachable (confirmed) paths an operator can report `detected`
  (caught/blocked). A high catch rate on high-score paths means the score over-predicts
  *undetected* compromise - the signal for a detection axis (**#7**, `P(reach ∧ ¬detect)`).

So the gate is honest and self-directing: `recalibrate-first` (apply the map) /
`structural (#6)` / `detection-axis (#7)` / `low-resolution` - you build #6 or #7
only when the evidence on real verdicts says the simpler fixes won't do.

If the diagnosis ever points at #6, `make and-probe` (the `andprobe` decision tool)
answers the question that actually decides a Bayesian Attack Graph: does your
environment have real **AND semantics** (a compromise needing several distinct
prerequisites at once) or pure OR-reachability the Monte Carlo already models? It
counts the critical-path nodes whose incoming edges span multiple prerequisite
categories - an *upper-bound heuristic* (a plain graph can't tell AND from OR; that's
what a BAG adds), so it names candidates for your `refuted` verdicts to confirm. Near
zero means #6 is a no-op - fix `p(e)` instead. (`--all-nodes` inspects the whole
topology, not just attack-path nodes.)

AND-semantics is a property of **topology**, not of CVEs - so feed it *real* topology:
`make ingest-k8s` snapshots your current `kubectl` context
(`Ingress/Service/Pod/SA/RBAC → exposure + privilege-escalation + container-escape`
edges - the collector takes native `kubectl get ... -o json`) and ingests it. Point
`kubectl` at a local **kind + kubernetes-goat** cluster for a deliberately-vulnerable
one, then `make and-probe` reads the AND-signal off real cluster structure. (A
locked-down cluster - e.g. a default Docker Desktop k8s - yields zero AND candidates,
which is itself the answer: no #6 needed.)

Run as a **program, not a snapshot**: set `VALIDATIONS_PATH` so verdicts survive
restarts (the report flags an `in-memory` dataset otherwise), and watch the
`calibrationTrend` (Brier/ECE/sample-count sampled each pass) on the Overview to see
the evidence accumulate and the scores improve over time.

```bash
curl -s "$API/validations" | jq '.calibration | {verdict, brier_recalibrated, diagnosis, segments, detection}'
# Record whether a confirmed attempt was caught, for the detection axis:
curl -s -X POST "$API/validations" -H 'Content-Type: application/json' -d '{
  "pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","detected":true}'
```

##### Self-test without real infrastructure

You don't need a deliberately-vulnerable environment to *exercise and test the
instrument itself*. `make calibration-selftest SCENARIO=...` (the `genverdicts`
subcommand) draws verdicts from a **known reality you control** and checks the
diagnostics name the right cause - exactly how you'd integration-test a calibration
system. It validates the *instrument*, never the engine's scores against the real
world (that still needs real verdicts):

```bash
make calibration-selftest SCENARIO=overconfident   # → "recalibrate-first"
make calibration-selftest SCENARIO=correlated      # → "structural (#6)"
make calibration-selftest SCENARIO=low-resolution  # → "low-resolution"
make calibration-selftest SCENARIO=detection       # → "detection-axis (#7)"
# scenarios: calibrated | overconfident | underconfident | correlated | low-resolution | detection
```

Each scenario injects a specific flaw (reality harder than predicted, correlated
hops, no resolution, heavy detection) and the gate must name it - so the tool both
seeds the dashboard and proves the diagnostics actually distinguish #6 from #7.
(Synthetic verdicts post their own calibration features; for a *live* path the
server-captured prediction always wins, so a real tester still can't fudge it.)

The same scenarios run as a deterministic **in-process CI test**
(`TestCalibrationScenarioDiagnosesEndToEnd`), so a regression in the gate logic fails
the build instead of surfacing months later on real data.

##### The on-ramp to *real* verdicts (the BAS bridge)

When you're ready to leave synthetic data, point the engine at a **deliberately
vulnerable target** (CloudGoat via the AWS connector, a local OWASP Juice Shop, a
manual pentest) - all authorized, your-own/sandbox infrastructure - and feed the
results back with zero custom integration. `make import-verdicts FILE=report.json`
(the `importverdicts` subcommand) reads a **tool-agnostic** attack report and matches
each finding to a live path by its target (crown-jewel name) and optional entry, so a
tester reports *"I confirmed a path to account-admin"* without knowing internal ids:

```jsonc
{ "source": "pacu", "findings": [
  { "target": "account-admin", "from": "public-deployer", "outcome": "confirmed",
    "detected": false, "evidence": "iam privesc via CreatePolicyVersion" },
  { "target": "cluster-admin", "outcome": "refuted", "evidence": "SG blocks egress" },
  { "route": "s3-public -> export", "outcome": "missed", "evidence": "not modeled" } ]}
```

That's the whole loop closed on reality: **vulnerable target → ingest (AWS connector
`fixtures`/`sdk`, or a scanner) → live paths → BAS → `import-verdicts` → calibration**.
Set `VALIDATIONS_PATH` so the verdicts persist across a real engagement, and the
diagnosis - now on real data - decides whether #6/#7 are actually warranted.

**Zero-cost, real, in ~15 minutes (Trivy → log4shell).** No cloud spend, no AWS
account - just a genuinely exploitable local target. `make ingest-real IMAGE=<img>`
(the `ingestreal` subcommand) scans a vulnerable image with **Trivy** (real CVEs,
real CVSS; real KEV/EPSS with `THREATINTEL=on`) and wires the minimal topology so the
CVE sits *on* an internet → crown-jewel path:

```bash
# stand up a real, exploitable log4shell (free), then ingest its real CVEs:
git clone https://github.com/vulhub/vulhub && cd vulhub/log4j/CVE-2021-44228 && docker compose up -d
make ingest-real IMAGE=<the vulhub image>          # → internet-lb → image → log4j-core → CVE-2021-44228 → crown-jewel
# ...exploit the running target for real, then record the verdict:
make import-verdicts FILE=my-report.json           # {"target":"secrets-vault","outcome":"confirmed"}
```

The CVE, its severity and its KEV/EPSS are **real** (only the deployment topology is
modeled - use the `k8s` collector on a local cluster to make that real too). Now the
score rests on a CVE you can actually exploit, so the verdict calibrates the real thing.

### Quantified risk, what-if & compliance export

A path score answers "how exploitable is *this* route". Boards and auditors ask
harder questions, and PerspectiveGraph answers them:

- **Monte Carlo risk quantification** (`riskSimulation`) - each trial realizes
  every edge independently, then checks crown-jewel reachability. Over thousands
  of trials it estimates **P(crown jewel compromised)** with a 95% confidence
  interval, plus **P(at least one crown jewel compromised)** and the expected
  number that fall. Unlike `∏p`, it accounts for the many routes that share edges
  - in the demo, *P(account compromise) ≈ 1.0, ~5 crown jewels expected to fall*.
  The headline is honest about its own uncertainty: alongside the sampling CI it
  reports a **sensitivity band** (the answer when the heuristic per-edge
  probabilities are scaled ±30%), shown as *“modeled X–Y%”* - a tight band means
  trust the number, a wide one means treat it qualitatively.
- **K-shortest paths** (`kShortestPaths`) - Yen's algorithm lists the top-K routes
  to a crown jewel, so you see the near-best alternates a single edge-cut would
  leave standing.
- **What-if simulation** (`whatIf`) - propose a set of edges to cut and get the
  surviving paths and the **residual risk** (before → after, with enough trials
  to make the delta meaningful): *"cut this edge → account compromise 100% →
  99.9%, 11 paths remain"*. Available right in the dashboard: hit **“what-if”**
  on any hop of a kill chain to simulate cutting it.
- **OSCAL compliance export** - `GET /export/oscal` renders the posture as a NIST
  **OSCAL 1.1.2 assessment-results** document: each attack path becomes an
  observation + risk, and each undermined **NIST 800-53 control** (SC-7, AC-6,
  RA-5, SI-2, AC-2 for IAM privesc, SI-4/IR-4 when runtime-confirmed, …) a
  not-satisfied finding - the language GRC tooling and auditors actually consume.

Both exports - OSCAL and the SIEM NDJSON enrichment feed - download straight from
the dashboard header (**↓ OSCAL** / **↓ SIEM**), or over HTTP:

```bash
curl -s "$API/export/oscal" > oscal.json   # NIST OSCAL assessment-results
```

### Triage & suppression (close the false-positive loop)

A finding nobody can dismiss is a finding nobody trusts. PerspectiveGraph has a
first-class **triage loop**: from any attack path, record a decision that takes
it off the active board - **accept-risk**, **false-positive**,
**mitigating-control** or **duplicate** - with an **accountable owner**, an
optional note, and an optional **expiry** after which the path automatically
returns to the board (so *"accept for 30 days"* can't silently become *"accept
forever"*). The overview then headlines **active** paths and shows how many are
suppressed; the list dims and labels them and hides them behind a *Show
suppressed* toggle. The suppression board is the audit of the tool's *own*
findings - who decided what, and why.

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
  `firstSeen`/`openForSeconds`, surfaced as an **"open 5d"** badge - persistence,
  not just existence, is what you triage on.
- **MTTR.** When a path stops appearing (fixed, or its asset went away) it's
  marked resolved; *resolved − first_seen* is its time-to-remediate, rolled up
  into an **MTTR** card - the accountability metric management actually asks for.
- **Regressions.** A path that resolved and came back is flagged **"⟳ reopened
  N×"** - the deploy-introduced-it-again signal, distinct from a brand-new path.
- **Exposure trend.** A sampled (critical-paths, account-compromise %) series
  drives a **sparkline** on the overview: a rising line is a regression to chase,
  a falling one is progress you can show a board.

It's all in GraphQL (`history { trend mttrSeconds openPaths resolvedPaths
oldestOpenSince }`, plus `firstSeen`/`openForSeconds`/`reopens` per path); set
`HISTORY_PATH` so "open for 5 days" survives a restart (else it's in-memory).

### Identity resolution you can trust (confidence + explainability)

Correlation across tools is only as good as the joins underneath it. When the
normalizer **infers** a link rather than reading one a tool asserted - e.g.
stitching a runtime container to the image a scanner reported - it now records
**how** and **how sure**: a digest pin is an exact identity (`1.0`), a tagged
ref is strong (`0.85`), a bare name is a weak correlation worth verifying
(`0.6`), and a weaker join lowers the stitched edge's probability so a path
resting on a shaky correlation scores below one built on a hard identity. The
provenance rides on the node (`resolutionMethod` / `resolutionConfidence` /
`resolutionAlias`) and surfaces in the kill chain as a **"⚠ heuristic join · N%"**
badge - so an analyst can *see, and distrust,* a heuristic correlation instead
of mistaking it for ground truth.

### Threat-intel: KEV + EPSS (optional)

Severity is a label; *exploitation* is a fact. Enable the threat-intel layer and
PerspectiveGraph enriches every CVE with **CISA KEV** (the catalog of
vulnerabilities *known exploited in the wild*) and **FIRST EPSS** (the
probability of exploitation in the next 30 days). KEV/EPSS reweight the `AFFECTS`
edge so path scores reflect real exploitation likelihood, not a severity guess -
and a KEV CVE on a *reachable, runtime-confirmed* path is the strongest
prioritization signal there is: theoretical → exploited-somewhere → exploited-here.

```bash
THREATINTEL=on make run-backend   # fetches live from CISA + FIRST (cached)
```

Disabled by default (zero network); the `AFFECTS` edge then keeps its
severity-derived weight.

### Auth, multi-tenancy & audit (optional, but do it before production)

Every door is open by default for zero-config local dev - and the backend
**logs a loud warning** when it is. The trust layer:

- **Ingest webhooks (write path)** - HMAC-SHA256 of the request body, keyed by a
  **per-tenant** secret that never travels on the wire (GitHub/Stripe model).
  Senders add `X-PerspectiveGraph-Signature: sha256=<hex>` and `X-Tenant: <id>`.
- **GraphQL API (read path)** - a bearer credential: a static token mapped to a
  role+tenant, or an **OIDC/JWT** (RS256, verified against the JWKS; `role` and
  `tenant` claims). RBAC roles are `viewer` / `operator` / `admin`; GraphiQL is
  disabled when auth is on, and the dashboard is built with `VITE_API_TOKEN`.
- **Multi-tenancy** - each tenant's assets live in their **own isolated graph**
  (a separate Apache AGE graph + search index). Ingest routes by the
  authenticated tenant; queries are scoped to it. A tenant can never read or
  write another's data.
- **Immutable audit log - of *reads*, not just writes.** The tool is a map of how
  to breach the org, so *who looked at it* matters as much as who changed it. Every
  request and denial, **every view of the attack paths or the graph**
  (`view.attack_paths` / `view.graph` - with the path ids seen), and **every export**
  (`export.oscal` / `export.ndjson` - the moment the whole map leaves the tool) is
  appended to a **hash-chained** JSONL file (each record links to the previous via
  SHA-256, so tampering is detectable). It answers "who saw - or exfiltrated -
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
pull request - but **only** for findings on a verified attack path, with the
path diagram and a remediation hint. It upserts a single comment per path
(idempotent across the analyzer's repeated passes). Without a `GITHUB_TOKEN` it
runs in **dry-run**, logging exactly what it would post. Set the token to go live:

```bash
GITHUB_TOKEN=ghp_… make run-backend
```

Then open the dashboard at http://localhost:5173 and the GraphQL playground at
http://localhost:8080/graphql. Prefer Postman? Import
[`docs/perspectivegraph.postman_collection.json`](./docs/perspectivegraph.postman_collection.json) -
health checks, every ingest webhook (with the demo payloads embedded) and all
GraphQL queries, ready to run.

Pointing it at a **real environment** (your own scanners, not the demo seed)?
Follow the [onboarding runbook](./docs/ONBOARDING.md) - per-source `curl`/CI
snippets, the identifier-correlation helper, and a "no paths?" troubleshooting
guide.

## Container & compose hardening

The images and the compose stack are built to the bar you'd expect in a review:

- **Tiny, reproducible images.** The backend is a multi-stage build → a static
  (CGO-off, `-trimpath`, stripped) binary on `distroless/static:nonroot` - **~14 MB,
  no shell, no package manager, no root.** The dashboard is a Vite build served by
  nginx-alpine. Every base image (incl. Postgres/AGE, NATS, OpenSearch) is **pinned
  by SHA-256 digest**, not a floating tag - reproducible and tamper-evident.
- **Least privilege at runtime.** Every compose service sets
  `no-new-privileges:true`; the backend additionally runs `read_only: true`,
  `cap_drop: [ALL]`, non-root, with a `tmpfs` `/tmp` - it writes nothing to disk.
- **No accidental exposure.** All published ports bind to `127.0.0.1`, so a laptop
  demo never puts Postgres/NATS/OpenSearch/the API on the LAN. OpenSearch's demo
  security plugin is explicitly disabled only behind the opt-in `search` profile.
- **Real health gating.** The backend ships a `healthz` subcommand (the distroless
  image has no shell/curl) used as its Docker `HEALTHCHECK`; the dashboard waits on
  `condition: service_healthy`, which in turn waits on Postgres/NATS being healthy -
  so `make up-full` comes up in the right order, every time.
- **CI scans the supply chain** - `govulncheck`, `npm audit`, and a Trivy image scan
  gate the build, plus an **AGE store integration job** (Postgres+AGE service
  container) that exercises the real, hand-written Cypher path - including an
  injection round-trip - that unit tests with the in-memory store can't cover
  (see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)).

### Application hardening

Beyond the container surface, the backend itself is built defensively:

- **Cypher injection defense (AGE store).** Values are wrapped in a *randomized*
  dollar-quote tag a value provably can't contain, single-quote-escaped, and
  labels/edge-types are validated against the ontology allowlist (graph names
  against a strict identifier pattern) - so attacker-influenceable scanner output
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
  own Go) and `gitleaks` (secret scan) alongside `govulncheck` + Trivy - a security
  tool held to the bar it sets.
- **At-rest encryption of its own crown-jewel data.** `STORE_ENCRYPTION_KEY`
  encrypts the governance stores (suppressions/tickets/validations/history) **and
  the audit log** with AES-256-GCM, so a stolen volume or backup doesn't hand over
  the attack map plus who-viewed-it in plaintext. (Reads pre-encryption files
  transparently - a one-way migration.)
- **Signed exports.** With `EXPORT_SIGNING_KEY` (Ed25519) the OSCAL/SIEM exports
  carry a detached signature (`X-PerspectiveGraph-Signature`); a consumer fetches
  the public key at **`GET /export/pubkey`** and verifies integrity + origin.
- **Abuse detection on its own data.** Repeated failed auth from one IP triggers a
  temporary **lockout** (`AUTH_LOCKOUT_THRESHOLD`, HTTP 429); an unusual volume of
  attack-path reads/exports by one principal raises an **exfiltration alert**
  (`EXFIL_ALERT_THRESHOLD`) - both logged and written to the audit log.
- **Token lifecycle & object-level RBAC.** API tokens take an optional **expiry**
  (`token:role:tenant:YYYY-MM-DD`) and can be stored **hashed** (`sha256$<hex>`) so
  the live secret never sits at rest; a token (or OIDC `apps` claim) can be scoped
  to a set of **applications**, restricting *reads* (paths, graph, violations,
  exports, search) to those apps - enforced once at the data boundary, no bypass.
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
  finding uses the **in-process Dijkstra by default** - polynomial and bounded. A
  DB-side Cypher finder is an **opt-in** (`ANALYZER_DB_PATHS`): since AGE has no
  weighted shortest-path it *enumerates* paths (unbounded worst-case), so it's
  safe-railed with a `statement_timeout` + `LIMIT` and falls back to Dijkstra on a
  runaway query. Legacy JSON-blob data is still read, so upgrades don't lose paths.
- **Replica-safe side-effects.** Run more than one backend replica and each still
  computes attack paths locally (warm API reads), but **at-most-once** external
  actions - drift webhooks and PR/MR comments - fire only from the **leader**,
  elected via a Postgres advisory lock with automatic failover. No duplicate
  notifications, no external coordinator.

> Hardening is layered, not absolute: the default Postgres password and open
> auth are deliberate **local-dev** defaults (the backend logs a loud warning).
> Set `POSTGRES_PASSWORD`, `INGEST_HMAC_SECRET` and `API_TOKENS`/OIDC before any
> shared or production deployment - see [`.env.example`](./.env.example).

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

### Local cluster (Docker Desktop / kind / minikube) + SSO demo

On a local cluster the images aren't on a registry, so build them and **load them
into the cluster** (its container runtime doesn't share the host Docker daemon):

```bash
make up-full && make down   # quickest way to build perspectivegraph-{backend,dashboard}:local

# Load into the cluster's containerd:
#   Docker Desktop:  docker save <img> | docker exec -i desktop-control-plane ctr -n k8s.io images import -
#   kind:            kind load docker-image <img>
#   minikube:        minikube image load <img>
```

Then install pointing at the local images (and, to try the **SSO login** end-to-end
against a bundled demo Keycloak, with the SSO overlay):

```bash
kubectl create namespace perspectivegraph
kubectl -n perspectivegraph create configmap keycloak-realm \
  --from-file=realm-demo.json=deploy/keycloak/realm-demo.json
kubectl -n perspectivegraph apply -f deploy/keycloak/k8s-keycloak-demo.yaml

helm install perspectivegraph deploy/helm/perspectivegraph \
  -n perspectivegraph -f deploy/helm/perspectivegraph/values-sso-demo.yaml

# Reach it (each in its own terminal): Keycloak for the browser, the dashboard,
# and the ingest port so `make seed` (which posts to localhost:8081) works.
kubectl -n perspectivegraph port-forward svc/keycloak 8088:8080
kubectl -n perspectivegraph port-forward svc/perspectivegraph-perspectivegraph-frontend 3000:80
kubectl -n perspectivegraph port-forward svc/perspectivegraph-perspectivegraph-backend 8081:8081
# open http://localhost:3000 → "Sign in with SSO" → demo / demo
make seed   # and make seed-discovery - they post to localhost:8081 (the ingest port)
```

Full walk-through (incl. why the OIDC URLs differ) in
[GUIDA §9.5.3](./docs/GUIDA.md). Demo only: locally-built images + Keycloak in
`start-dev`.

### Hardening a real deployment (beyond a trusted cluster)

The default chart runs **unauthenticated with in-memory governance** - fine for a
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

- **`auth.apiTokens` / `auth.oidc.*`** - without a token the API is open; set
  static tokens and/or OIDC (`issuer`/`audience`/`jwksUrl`). `auth.apiRateRps` /
  `auth.ingestRateRps` cap per-IP request rates (0 disables).
- **`ingest.hmacSecret` / `ingest.hmacSecrets`** - HMAC-sign ingestion so nobody
  can forge scanner data on the open ingest port.
- **`persistence.enabled`** - mounts a ReadWriteOnce PVC so suppressions, tickets,
  red-team validations, MTTR/posture history and the **tamper-evident audit log**
  survive restarts (in-memory and lost otherwise). Because the stores are
  single-writer, the chart **refuses to render with `backend.replicas > 1`** while
  persistence is on - scale-out would split-brain them.
- The release prints a ⚠ in `NOTES` whenever auth or persistence is left off, so
  an insecure exposure is never silent.
- **Startup ordering** - the backend has `initContainers` that block on the bundled
  Postgres:5432 and NATS:4222 before it boots, so a fresh install connects to
  Apache AGE on the first try instead of crash-looping on NATS or *silently* falling
  back to the in-memory graph when Postgres is slow. (External Postgres/NATS are
  assumed reachable and aren't gated.)

#### Transport security (TLS) & data-in-transit

The app speaks plain HTTP by default and expects TLS to terminate **at the edge** -
turn it on, it isn't hardcoded off:

- **HTTPS at the ingress (recommended):** `--set ingress.tls.enabled=true
  --set ingress.tls.secretName=perspectivegraph-tls`, and let cert-manager issue
  the cert (`--set ingress.annotations."cert-manager\.io/cluster-issuer"=…`).
- **HTTPS in the pod (no proxy):** `--set backend.tls.enabled=true
  --set backend.tls.secretName=<kubernetes.io/tls secret>` - the API + ingest
  servers then serve TLS ≥ 1.2 directly (env `TLS_CERT_FILE`/`TLS_KEY_FILE` for the
  non-Helm/compose case).
- **Database in transit:** the connection carries the attack map, so for a
  managed/external Postgres set `--set postgres.sslMode=verify-full` (the chart
  already defaults an external DB to `require`); the bundled in-cluster DB stays
  `disable` since it has no TLS. Full control (CA path) via `POSTGRES_DSN` +
  `sslrootcert`.
- **NATS in transit:** point `NATS_URL` at a `tls://` endpoint; `NATS_TLS_CA`
  trusts a private CA and `NATS_TLS_CERT`/`NATS_TLS_KEY` add a client cert for
  **mutual TLS** (Helm: `--set nats.tls.enabled=true --set nats.tls.secretName=…`).
- **mTLS for all in-cluster traffic (the easy way):** run a **service mesh**
  (Linkerd / Istio) - it transparently mTLS-wraps every pod-to-pod hop (backend ↔
  Postgres ↔ NATS ↔ dashboard) with automatic cert rotation and **no app changes**;
  the per-component TLS knobs above are for when you *don't* run a mesh.
- **Secrets at rest:** the chart writes credentials to a Kubernetes `Secret`
  (base64, not encrypted in etcd by default). Either enable etcd encryption, or
  manage the Secret externally - `--set secrets.existingSecret=<name>` makes the
  chart **stop creating its own** and read a Secret you supply (External Secrets /
  Sealed Secrets / Vault). App-managed secrets are already encrypted at rest on
  disk via `STORE_ENCRYPTION_KEY`.

Every optional capability is wired through both `docker-compose.yml` (as
`${VAR:-}` passthroughs, off by default) and the chart, so a feature you enable in
code is actually reachable in the running stack:

- **Agentless connectors** - `--set connectors.enabled='{aws}'` pulls cloud posture
  on a schedule (`connectors.interval`); the AWS connector runs from bundled
  fixtures unless `connectors.aws.mode=live` (then `connectors.aws.region` + an
  assumable read-only `connectors.aws.roleArn`).
- **SSO login** - `auth.oidc.clientId` / `authorizeUrl` / `tokenUrl` / `scopes` are
  the SPA-facing coordinates the dashboard login gate reads from `GET /auth/config`
  to run the Authorization-Code + PKCE flow (the `issuer`/`audience`/`jwksUrl` trio
  above does the server-side token verification).
- **Dev workflow** - `github.token` turns the PR comment / merge-gate status and
  remediation-as-PR from dry-run into live; `github.dashboardUrl` is the link those
  comments point back to.
- **AI-native layer (Claude or HuggingFace)** - `ai.apiKey` (Anthropic) enables
  `/ai/*` (NL query, exec summary, path explain); empty keeps it self-gated off.
  `ai.hf.token` is the free OpenAI-compatible alternative, used when `ai.apiKey` is
  empty (`ai.hf.model`/`ai.hf.baseUrl` tune it). Both keys land in the Secret;
  `ai.model`/`baseUrl`/`maxTokens` are optional overrides.
- **Hardening** - `scrubIngest` (on by default) redacts secret-looking values out
  of scanner output before the store; `crypto.storeEncryptionKey` encrypts the
  file-backed governance stores at rest and `crypto.exportSigningKey` signs graph
  exports (both land in the Secret).

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

- **The graph is *derived* state - that's your DR story.** Everything in
  Postgres+AGE is reconstructible by re-ingesting the source feeds, so a lost
  database is a *re-seed*, not a data-loss event. Back up Postgres for history
  and convenience (`pg_dump` of the AGE-extended database, or a managed
  Postgres's PITR/replica); restore, or just re-run the collectors, to recover.
  For HA, run Postgres as a managed/replicated service (the chart can point at an
  external one) - the backend is stateless and horizontally scalable, and
  leader election already ensures only one replica fires side-effects.

### Scaling the analyzer

The per-pass cost stays flat as the graph grows, with three layers you can tune:

- **Change-detection (always on).** A pass is skipped entirely when nothing was
  written since the last one - a steady graph costs almost nothing.
- **Parallel pathfinding (on by default).** Each internet-exposed entry point gets
  an independent shortest-path search, fanned out across `ANALYZER_WORKERS`
  goroutines (default = number of CPUs). The result is identical regardless of
  worker count, so it's a pure speedup - ~2.9× at 8 workers on a 10k-node /
  64-seed benchmark (`make bench`).
- **Incremental snapshotting (opt-in, `ANALYZER_INCREMENTAL=true`).** Instead of
  re-reading the whole graph each pass, the analyzer keeps it resident and patches
  it with just what changed since the last pass (filtered on the same `last_seen`
  the pruner uses, so only the changed slice leaves Postgres). It still recomputes
  all paths, but skips the dominant fetch cost on a large AGE graph; a full re-read
  self-heals the cache on the first pass, after a prune, and periodically. It trades
  memory for fetch cost, so it's off by default.

  ```bash
  ANALYZER_WORKERS=8 ANALYZER_INCREMENTAL=true make run-backend
  ```

  Scale visibility on `/metrics`: graph size (`perspectivegraph_analyzer_graph_{nodes,edges}`),
  snapshot mode (`..._snapshots_total{mode="full|delta"}`), and pathfinding latency
  (`..._pathfind_seconds`). To load-test end-to-end, post a large synthetic attack
  surface with `make seed-load` (or `perspectivegraph genload --seeds 64 --width 1000 …`).

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
and auth-lockout + exfiltration alerting - plus a Helm chart that surfaces all of
it. The graph store defaults to Apache AGE and falls back to in-memory for
zero-dependency dev. See [the roadmap](./ARCHITECTURE.md#roadmap) for what's next.

## License

[Apache License 2.0](./LICENSE).
