# Onboarding runbook — feeding PerspectiveGraph from a real environment

PerspectiveGraph does **not** scan your infrastructure — it *correlates* the
output of the scanners you already run. There are no agents and nothing pulls:
your CI/cron runs the tools and **POSTs** their reports to the ingest webhook.
This runbook is the minimum a tester needs to light up a real attack path.

Set these once for every snippet below:

```bash
export INGEST_URL=http://your-host:8081     # ingestion webhook
export API_URL=http://your-host:8080        # GraphQL / dashboard BFF
export SLUG=acme/payments-api               # forge "owner/repo" (for PR comments)
```

---

## 0. Prerequisites

- The stack is up. Quickest path: **`make up-full`** runs everything in
  containers (infra + backend + dashboard on `:3000`). For the host dev loop use
  `make up` (just **Postgres+AGE** + **NATS**) then `make run-backend`. OpenSearch
  and `THREATINTEL=on` are optional. With `make up-full`, `INGEST_URL` is
  `http://localhost:8081` and `API_URL` is `http://localhost:8080`.
- Network: the tester's CI/cron can reach `INGEST_URL`. ⚠️ **The ingest and API
  endpoints have no authentication in this MVP** — keep them on an isolated
  network or behind an authenticating reverse proxy. Single-tenant.
- You can run **Trivy, Semgrep, Cloud Custodian, Falco** against the target, and
  add one **CI step** for build provenance.
- You can **tag** your sensitive data stores (this is what makes them targets —
  see §3).

Health check first:

```bash
curl -s $INGEST_URL/healthz   # → ok
curl -s $API_URL/healthz      # → ok
```

### Authentication

If the backend runs with auth enabled (it should, outside a laptop), every
request must be signed/authorized — otherwise you get `401`.

- **Ingest** (`INGEST_HMAC_SECRET` set): sign the request **body** with HMAC-SHA256
  and send `X-PerspectiveGraph-Signature: sha256=<hex>`. A reusable helper:

  ```bash
  export INGEST_HMAC_SECRET=...   # the shared secret
  pgsign() {  # usage: pgsign <file>  → prints the signature header value
    printf 'sha256=%s' "$(openssl dgst -sha256 -hmac "$INGEST_HMAC_SECRET" -hex < "$1" | sed 's/^.*= //')"
  }
  # then on every ingest POST add:  -H "X-PerspectiveGraph-Signature: $(pgsign report.json)"
  ```

- **API** (`API_TOKENS` set): send `Authorization: Bearer <viewer-token>` on
  every GraphQL request. The in-browser playground is disabled when auth is on.

- **Multi-tenant** (`INGEST_HMAC_SECRETS` / token `:tenant` suffix): add
  `-H "X-Tenant: <your-tenant>"` to ingest requests and sign with *that tenant's*
  secret; the API token's tenant scopes what you can read. Each tenant's data is
  fully isolated in its own graph.

- **Audit-of-views** (`AUDIT_LOG_PATH` set): the tool is a map of how to breach
  the org, so set this in production — it tamper-evidently records who *viewed*
  the attack paths/graph (with the path ids seen) and who *exported* the map, not
  just who changed it. Check integrity with `perspectivegraph verify-audit <path>`.

The snippets below show the unsigned, single-tenant form for readability; add the
signature / bearer / `X-Tenant` headers when auth and tenancy are enabled.

---

## 1. The order that builds a correct graph

Feed these sources. Order doesn't strictly matter (edges whose endpoints haven't
arrived yet are retried), but this is the logical flow:

| # | Source | Endpoint | Gives the graph |
|---|--------|----------|-----------------|
| 1 | Cloud Custodian | `POST /ingest/custodian` | cloud topology + IAM + the `internet_exposed`/`crown_jewel` markers |
| 2 | Trivy | `POST /ingest/trivy` | images → libraries → CVEs |
| 3 | CI build provenance | `POST /ingest/build` | the **image ↔ repository** link (`BUILT_FROM`) |
| 4 | Semgrep | `POST /ingest/semgrep` | repository → code weaknesses / secrets |
| 5 | Falco | `POST /ingest/falco` | runtime confirmation on containers |
| 6 | Kubernetes dump | `POST /ingest/k8s` | **exposure topology**: Ingress→Service→Pod→SA→Role |
| 7 | Cloud network | `POST /ingest/cloudnet` | **reachability**: internet-facing SGs, SG-to-SG, VPC peering |
| 8 | IAM authorization | `POST /ingest/iam` | **privilege escalation**: `CAN_ESCALATE_TO` edges to account-admin, public-trust roles |

Sources 6–8 are the **discovery** collectors: they extract the network/exposure
topology and IAM privilege-escalation graph automatically, so paths form without
hand-stitched ids.

---

## 2. Per-source snippets

### Trivy (dependency / image CVEs)

The report's `ArtifactName` becomes the Image node — pass the **full image ref**
you actually deploy. `slug`/`pr`/`sha` attach PR context so the action layer can
comment on the right pull request.

```bash
trivy image --format json --output trivy.json registry.example.com/payments-api:1.4.2

curl -sS -X POST "$INGEST_URL/ingest/trivy?slug=$SLUG&pr=42&sha=$(git rev-parse HEAD)" \
  -H 'Content-Type: application/json' --data-binary @trivy.json
```

### CI build provenance (the link that connects code findings)

Emit this from CI **right after pushing the image**. Without it, Semgrep findings
float disconnected from the running workload. `image` must match Trivy's
`ArtifactName`; `repository` must match Semgrep's `repo` (next step).

```bash
curl -sS -X POST "$INGEST_URL/ingest/build" -H 'Content-Type: application/json' -d '{
  "image":      "registry.example.com/payments-api:1.4.2",
  "repository": "payments-api",
  "slug":       "'"$SLUG"'",
  "sha":        "'"$(git rev-parse HEAD)"'"
}'
```

### Supply-chain provenance (cosign / SLSA / SBOM)

Emit this from CI after signing/attesting the image. It stamps the image with
its **trust signals** and **bill of materials**, assembled straight from the
tools you already run — no bespoke format:

```bash
IMG="registry.example.com/payments-api:1.4.2"
syft "$IMG" -o cyclonedx-json > sbom.json                          # SBOM (or: trivy image --format cyclonedx)
cosign verify "$IMG" >/dev/null 2>&1 && SIGNED=true || SIGNED=false # signature
# SLSA level from your attestation policy (cosign verify-attestation --type slsaprovenance "$IMG")
curl -sS -X POST "$INGEST_URL/ingest/supplychain" -H 'Content-Type: application/json' -d '{
  "image":       "'"$IMG"'",
  "signed":      '"$SIGNED"',
  "slsa_level":  3,
  "provenance_builder": "github-actions",
  "source_repo": "payments-api",
  "sbom":        '"$(cat sbom.json)"'
}'
```

`sbom` accepts the raw CycloneDX document above **or** a plain
`[{"name","version","type","purl"}]` list. Each component becomes a
`Library`/`Package` the image `DEPENDS_ON`. Set `signed:false` for an image whose
signature you couldn't verify — if it's reachable from the internet, the
`no-internet-to-unsigned-image` invariant fires (Violations view), and the kill
chain marks it **⚠ unsigned**. Omit `signed` entirely for "not assessed" (no
violation — unknown is not the same as unsigned).

### Semgrep (SAST weaknesses + secrets)

`repo` **must equal** the build provenance `repository`, so findings hang off the
same Repository node that `BUILT_FROM` links to.

```bash
semgrep --config auto --json --output semgrep.json

curl -sS -X POST "$INGEST_URL/ingest/semgrep?repo=payments-api&slug=$SLUG&pr=42&sha=$(git rev-parse HEAD)" \
  -H 'Content-Type: application/json' --data-binary @semgrep.json
```

### Cloud Custodian (cloud inventory + IAM)

The collector consumes a **bundle** that groups Custodian's per-policy
`resources.json` outputs by resource type. Assemble it like this (real AWS field
shapes — EC2 `PublicIpAddress`/`IamInstanceProfile`/`Tags`, ALB `Scheme`, IAM
`AttachedManagedPolicies`, S3 ACL grants, RDS `PubliclyAccessible`):

```bash
curl -sS -X POST "$INGEST_URL/ingest/custodian" -H 'Content-Type: application/json' -d '{
  "provider": "aws",
  "account_id": "123456789012",
  "policies": [
    { "policy": "elb-internet-facing", "resource": "aws.elbv2", "resources": [
      { "LoadBalancerName": "prod-alb", "Scheme": "internet-facing", "Tags": [{"Key":"app","Value":"payments"}] }
    ]},
    { "policy": "ec2", "resource": "aws.ec2", "resources": [
      { "InstanceId": "i-0abc", "PublicIpAddress": "203.0.113.10",
        "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/payments-role"},
        "Tags": [{"Key":"Name","Value":"payments-vm"},{"Key":"app","Value":"payments"}] }
    ]},
    { "policy": "iam-admin", "resource": "aws.iam-role", "resources": [
      { "RoleName": "payments-role", "AttachedManagedPolicies": [
        {"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"} ] }
    ]},
    { "policy": "s3-classified", "resource": "aws.s3", "resources": [
      { "Name": "customer-pii", "Tags": [{"Key":"classification","Value":"pii"}] }
    ]}
  ]
}'
```

### Falco (runtime confirmation)

Point **falcosidekick**'s webhook output at the endpoint, or POST raw Falco JSON
(`-o json_output=true`). Each alert needs `output_fields["container.name"]`
(or `container.id`); include `container.image` so the runtime container links to
the scanned image (its ref must match Trivy's, after registry strip).

```bash
curl -sS -X POST "$INGEST_URL/ingest/falco" -H 'Content-Type: application/json' -d '{
  "rule": "Terminal shell in container",
  "priority": "Warning",
  "output": "A shell was spawned in a container",
  "output_fields": {
    "container.name": "payments",
    "container.image": "registry.example.com/payments-api:1.4.2",
    "k8s.pod.name": "payments-7d9", "k8s.ns.name": "prod"
  }
}'
```

### Kubernetes topology (auto-discovered exposure)

Post a raw cluster dump and PerspectiveGraph discovers the exposure topology —
`Ingress ──ROUTES_TO──▶ Service ──EXPOSES──▶ Pod ──ASSUMES──▶ ServiceAccount
──ASSUMES──▶ Role` — with no hand-stitched ids. Pods carry their image ref, so
they stitch to the scanned image automatically.

```bash
kubectl get ingress,service,pod,serviceaccount,clusterrole,clusterrolebinding,rolebinding \
  -A -o json > cluster.json
curl -sS -X POST "$INGEST_URL/ingest/k8s" -H 'Content-Type: application/json' --data-binary @cluster.json
```

### Cloud network reachability (auto-discovered)

Post security groups + instances + VPC peerings; PerspectiveGraph derives who can
reach whom (`0.0.0.0/0 → internet_exposed`, SG-to-SG ingress → `CONNECTS_TO`).

```bash
# Assemble a bundle from: aws ec2 describe-security-groups / describe-instances /
# describe-vpc-peering-connections (see backend/testdata/cloudnet-sample.json).
curl -sS -X POST "$INGEST_URL/ingest/cloudnet" -H 'Content-Type: application/json' --data-binary @cloudnet.json
```

### IAM privilege-escalation graph (auto-discovered)

Post the account's IAM reality and PerspectiveGraph builds the "BloodHound for
cloud" view: it flattens each principal's **effective** allowed actions (managed
+ inline + group policies, resolving the default policy version) and matches them
against known escalation primitives — `iam:PassRole` paired with a compute action
(`lambda:CreateFunction`, `ec2:RunInstances`, …), `iam:AttachUserPolicy`,
`iam:PutRolePolicy`, `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`, and
more. Each match draws a `CAN_ESCALATE_TO` edge to a synthetic **account-admin**
crown jewel. A role whose trust policy admits `"Principal":"*"` is marked
`internet_exposed` (publicly assumable) — the seed of a full internet→admin path.

```bash
# One call dumps every user, role, group and policy in the account.
aws iam get-account-authorization-details > iam.json
curl -sS -X POST "$INGEST_URL/ingest/iam" -H 'Content-Type: application/json' --data-binary @iam.json
```

> **Read-only & honest about scope.** The collector needs only the read-only
> `iam:GetAccountAuthorizationDetails` permission. It intentionally ignores
> Resource scoping, Condition keys and explicit Deny, so it **over-reports rather
> than misses** an escalation — treat its findings as "worth confirming", the
> same trade PMapper makes. See `backend/testdata/iam-sample.json` for the shape.

### SSO / IdP federation (Okta → cloud — the modern front door)

Phishing/credential-stuffing an SSO user inherits every cloud role they federate
into. Post a directory export (Okta/Entra admin API) and PerspectiveGraph models
`IdentityProvider(internet) → User → ASSUMES → IAM_Role`. Set `federated_roles`
to the **role ARNs** each user can assume — they converge with the roles the IAM
collector discovered, so a no-MFA user federating into an admin/escalation role
completes the chain *internet → Okta → user → cloud admin*.

```bash
curl -sS -X POST "$INGEST_URL/ingest/sso" -H 'Content-Type: application/json' -d '{
  "provider": "okta",
  "users": [
    {"email":"alice@acme.com","mfa":false,"groups":["cloud-admins"],
     "federated_roles":["arn:aws:iam::123456789012:role/admin-role"]}
  ]
}'
```

`mfa:false` weights the IdP→user hop as easily phishable; `internet_login`
(default true) makes the IdP a seed. Build the payload from your IdP's API —
e.g. Okta `/api/v1/users` + the AWS-federation app's role mappings.

---

## 3. The two markers that make paths appear

The analyzer looks for routes from an **`internet_exposed`** node (seed) to a
**`crown_jewel`** node (target). **No marker on either side → no paths, empty
dashboard.** They are derived for you, but only if your data carries the signal:

- **`internet_exposed`** ← Custodian: ALB `Scheme: internet-facing`, EC2
  `PublicIpAddress`, S3 ACL granting `AllUsers`, RDS `PubliclyAccessible: true`.
- **`crown_jewel`** ← **tag your sensitive stores** with one of
  `classification` / `data-classification` / `data` / `sensitivity` =
  `pii | sensitive | confidential | restricted | secret`, or literally
  `crown-jewel=true`; or an IAM role with the `AdministratorAccess` policy.

If your real export doesn't carry these, set them directly on a node via
`/ingest/events` (see §5).

---

## 4. Identifier correlation (the make-or-break detail)

A path forms only when every source names the *same real asset* with the *same
node id*. The collectors compute it as:

```
<Label>:<first 16 hex of sha1( lowercase(name) )>
```

Use this helper to compute an id when you reference a node by hand:

```bash
pgid() { printf '%s' "$2" | tr 'A-Z' 'a-z' | shasum | cut -c1-16 | sed "s|^|$1:|"; }

pgid Image     "payments-api:1.4.2"   # → Image:98b06dcdd2c1656f
pgid Container "payments"
pgid IAM_Role  "web-admin"
```

Practical rules:

- Use the **same image ref** in Trivy, build provenance and Falco. Registry
  prefixes are stripped automatically (`registry/…/payments-api:1.4.2` ≡
  `payments-api:1.4.2`), and Docker Hub `library/` is normalized — but anything
  more exotic must match exactly.
- Keep Semgrep `repo` == build provenance `repository`.
- Prefer setting markers through the native source (Custodian tags) so you don't
  have to hand-compute ids at all.

---

## 5. Network topology — now auto-discovered

Earlier this needed hand-stitched `/ingest/events`. It no longer does: the
**`/ingest/k8s`**, **`/ingest/cloudnet`** and **`/ingest/iam`** collectors (§2)
extract exposure, reachability and privilege escalation for you —
Ingress→Service→Pod, Pod→ServiceAccount→Role, internet-facing security groups,
SG-to-SG reachability, VPC peering, and `CAN_ESCALATE_TO` edges to account-admin.
Feed the raw `kubectl get -o json`, AWS `describe-*` and
`get-account-authorization-details` output and the topology appears.

You can still hand-author edges via `/ingest/events` for anything the collectors
don't cover (computing endpoint ids with the `pgid` helper from §4):

```bash
LB=$(pgid LoadBalancer ingress-prod); C=$(pgid Container payments)
curl -sS -X POST "$INGEST_URL/ingest/events" -H 'Content-Type: application/json' -d '{
  "source": "topology", "kind": "relationship",
  "nodes": [{ "id": "'"$LB"'", "label": "LoadBalancer", "name": "ingress-prod",
              "properties": { "internet_exposed": true } }],
  "edges": [{ "type": "EXPOSES", "from": "'"$LB"'", "to": "'"$C"'", "exploit_probability": 0.9 }]
}'
```

Edge types: `EXPOSES`, `ROUTES_TO`, `HOSTS`, `CONNECTS_TO`, `ASSUMES`,
`HAS_PERMISSION`, `BUILT_FROM`, `DEPENDS_ON`, `AFFECTS`. Labels: `LoadBalancer`,
`VirtualMachine`, `Container`, `VPC`, `Database`, `Bucket`, `Repository`,
`Image`, `Library`, `User`, `IAM_Role`, `ServiceAccount`, `CVE`, `Weakness`,
`Misconfiguration`, `Secret`.

---

## 6. Verify a path formed

Wait one analyzer interval (`ANALYZER_INTERVAL`, default 30s) after ingest, then:

```bash
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ posture { criticalPaths kevOnPaths runtimeConfirmed } attackPaths { score nodes { name label } } remediationPlan { title coveragePct } }"
}' | jq
```

`criticalPaths > 0` means correlation worked. Open the dashboard for the kill
chains, the graph, and the **Remediation** plan. (See the Postman collection in
this folder for ready-made queries.)

### Quantify risk, simulate fixes, export for compliance

Once paths exist, four analyses turn "here are the routes" into decisions:

```bash
# Monte Carlo: P(crown jewel compromised) with a 95% CI, over the whole graph.
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ riskSimulation(iterations: 5000) { anyCompromiseProbability expectedCompromised crownJewels { name compromiseProbability ciLow ciHigh } } }"
}' | jq

# K-shortest: the top routes to one crown jewel (id or name), best first.
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ kShortestPaths(target: \"customers-db (PII)\", k: 5) { score nodes { name } } }"
}' | jq

# What-if: cut an edge (from/to accept id or name) and see the residual risk.
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ whatIf(cuts: [{from: \"public-deployer\", to: \"account-admin (effective)\", type: \"CAN_ESCALATE_TO\"}]) { removedEdges riskReduction afterRisk { anyCompromiseProbability } } }"
}' | jq

# OSCAL: the posture as a NIST 800-53 assessment-results document for GRC tooling.
curl -s "$API_URL/export/oscal" | jq '.["assessment-results"].results[0].findings[].title'
```

`riskSimulation` is reproducible per `seed`; what-if shares the seed across
before/after so the delta is the cut's effect, not Monte Carlo noise.

Each path also reports the **provenance** of its score so it isn't false
precision: `confidence` + `confidenceLabel` (high/medium/low) summarize how its
hops were weighted, and each `steps { weightBasis }` is `kev`/`epss`/`runtime`
(observed evidence) or `cvss`/`severity`/`heuristic` (an estimate). Turn on
`THREATINTEL=on` to upgrade CVE hops from severity guesses to KEV/EPSS evidence —
which raises the confidence of paths that rest on really-exploited CVEs.

### Close the loop: verify a fix, then own it

A remediation you can't trust is a scaffold. Each generated fix records the edge
it cuts, so the API *verifies* it by simulating the removal — the plan shows
`verification { verified pathsEliminated riskReductionPct }`, i.e. "this provably
removes N paths and drops risk by X%", not just "here's a YAML". Then turn a path
into an **owned, tracked ticket** so it actually gets done:

```bash
# Open a ticket (admin when auth is on). One open ticket per path; with
# TICKET_WEBHOOK_URL set it's also POSTed to your tracker (Jira/GitHub/SOAR).
curl -s -X POST "$API_URL/tickets" -H 'Content-Type: application/json' \
  -d '{"pathId":"ap-1a2b-3c4d","owner":"secops@acme"}' | jq
curl -s "$API_URL/tickets" | jq                        # the work board
curl -s -X POST "$API_URL/tickets/tk-abc123/close"      # mark it done
```

### Validate against reality (red-team / BAS)

A modeled path is a hypothesis. Feed the verdict back so the engine earns trust
with evidence — wire your BAS platform (Caldera, AttackIQ, SafeBreach…) or a
human to post the result of testing a path:

```bash
# outcome ∈ confirmed | refuted | partial (reference a path id), or missed
# (a real path the engine didn't surface — describe it in route). source required.
curl -s -X POST "$API_URL/validations" -H 'Content-Type: application/json' -d '{
  "pathId":"ap-1a2b-3c4d","outcome":"confirmed","source":"caldera","evidence":"atomic T1190"}' | jq
curl -s "$API_URL/validations" | jq .metrics    # precision / recall over the tested subset
```

Each tested path then shows a **✓ validated real / ✗ refuted** badge, and the
overview a **Validation** precision card. It's evidence on what was *actually*
tested — not a global precision/recall claim. Set `VALIDATIONS_PATH` to persist.

### Triage a path you've decided about

Not every path is a fire to fight — some you accept, some are false positives,
some a control outside the graph already covers. Record that decision so the
board reflects reality (and so the next analyst sees *who* decided and *why*):

```bash
# Suppress a path (admin when API auth is on). reason ∈
# accept-risk | false-positive | mitigating-control | duplicate. owner required.
curl -s -X POST "$API_URL/suppressions" -H 'Content-Type: application/json' -d '{
  "pathId": "ap-1a2b-3c4d", "reason": "mitigating-control",
  "owner": "secops@acme", "note": "WAF blocks this", "ttlDays": 30 }' | jq

curl -s "$API_URL/suppressions" | jq            # the triage board (incl. expired)
curl -s -X DELETE "$API_URL/suppressions/ap-1a2b-3c4d"   # un-suppress
```

`pathId` is the `attackPaths { id }` value (stable for a seed→crown-jewel pair).
Suppressed paths drop out of the overview's **active** count and the
`riskSimulation` doesn't change — suppression is a *view* decision, not a graph
edit. Set `SUPPRESSIONS_PATH` so decisions survive a restart (otherwise they are
in-memory only). In the dashboard, use **⊘ suppress / triage** on any path and
the **Show suppressed** toggle on the list.

> Tip: when a kill chain shows a **"⚠ heuristic join · N%"** badge, the link was
> *inferred* (e.g. container→image by tag/name, not digest) — verify it before
> acting, or mark the path **false-positive** if the correlation is wrong.

---

## 7. Troubleshooting — "I see no attack paths"

Work down this list; it is almost always one of these:

1. **No seed** — nothing is `internet_exposed`. Check §3; mark an entry point.
2. **No target** — nothing is `crown_jewel`. Tag a sensitive store (§3).
3. **Seed and target exist but aren't connected** — the topology edge between
   them is missing (the §5 gap). Add the `EXPOSES`/`ROUTES_TO` edge.
4. **Ids don't match across sources** — the image ref or repo name differs. Use
   `pgid` to compare; align Trivy/build/Falco image refs and Semgrep `repo`.
5. **Ingest returns 5xx** — check the backend logs; a malformed payload is
   rejected per-source, an unknown collector name 404s.
6. **Data is in but stale** — give it one `ANALYZER_INTERVAL`; the analyzer only
   recomputes when the graph changed.

---

## 8. Run it continuously

A pilot is a few manual POSTs; production is the scanners wired to fire on their
own cadence:

- **CI (per PR / per build):** add the Trivy + build-provenance + Semgrep POSTs
  as a job step after you build the image, passing `?slug=&pr=&sha=` from the CI
  context. PR comments then land only on findings that sit on a real path.
- **Cloud (hourly/daily cron):** run Custodian, assemble the bundle, POST to
  `/ingest/custodian`. Re-posting is idempotent (deterministic ids + upserts).
- **Discovery (daily cron):** dump `kubectl get -o json`, the AWS `describe-*`
  bundle and `aws iam get-account-authorization-details`, POST to `/ingest/k8s`,
  `/ingest/cloudnet` and `/ingest/iam`. Each re-post is idempotent, so drift in
  exposure or IAM escalation surfaces as new/closed paths between runs.
- **Runtime (continuous):** point falcosidekick's HTTP output at
  `/ingest/falco`.

Start narrow — one app with a known internet entry point and a known sensitive
store — confirm a path end-to-end, *then* widen the scanners' scope.

**Deploying it on Kubernetes.** The Helm chart in `deploy/helm/perspectivegraph`
brings up backend + dashboard + Postgres+AGE + NATS in one command (or point it at
managed Postgres/NATS with `postgres.enabled=false`/`nats.enabled=false`). The
default install is *unauthenticated with in-memory governance* — fine for a demo
inside a trusted cluster, but for anything reachable beyond it, turn the controls
on: `--set auth.apiTokens="$(openssl rand -hex 16):admin"` (bearer auth),
`--set ingest.hmacSecret=…` (signed ingestion), and `--set persistence.enabled=true`
so suppressions, tickets, validations, MTTR history and the **audit log** persist
across restarts. The stores are single-writer, so the chart refuses to render with
`backend.replicas > 1` while persistence is on, and the post-install notes flag any
control you left off. Full hardening recipe: the "Hardening a real deployment"
section of the [README](../README.md).

### Keep it fresh (so it can't drift into fiction)

Once feeds run on a cadence, set **`GRAPH_TTL`** to a few feed-cycles (e.g.
`168h`). Each observation stamps `last_seen`; the analyzer then removes anything
not re-seen within the window, so a deleted pod or torn-down security group stops
producing a **phantom path** instead of lingering forever. Make the TTL
comfortably longer than your slowest feed's interval, so one briefly-missed scan
doesn't evict a still-present asset. Watch it via `status { prunedNodes
prunedEdges lastPrunedAt }`, the dashboard footer (*“pruned N stale”*), or
`perspectivegraph_graph_pruned_{nodes,edges}_total`. The graph is **derived**
state — rebuildable by re-ingesting the feeds — so a lost AGE database is a
re-seed, not data loss; back Postgres up (`pg_dump`) for history.

### Manage on trends, not snapshots

Once it runs continuously, the temporal layer turns passes into a history. Set
**`HISTORY_PATH`** so it survives restarts, then track exposure over time:

```bash
curl -s -X POST "$API_URL/graphql" -H 'Content-Type: application/json' -d '{
  "query": "{ history { openPaths resolvedPaths mttrSeconds oldestOpenSince trend { at criticalPaths riskPct } } }"
}' | jq
```

Each path also exposes `openForSeconds` (the dashboard's *“open 5d”* badge) and
`reopens` (*“⟳ reopened N×”* — a path that came back after being fixed, i.e. a
deploy reintroduced it). **MTTR** is the mean *resolved − first_seen* over paths
that closed — the accountability number for management reporting. The overview
plots the trend as a sparkline: chase a rising line, show a board a falling one.
