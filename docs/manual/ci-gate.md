# Attack paths in the pull request

*Part of the [PerspectiveGraph manual](../MANUAL.md).* The merge gate - GitHub Action, CLI and Trivy plugin - and what a developer sees on the pull request.

## The wedge: attack paths in your pull request

This is the one to try first - everything else exists to make it accurate. A
finding only changes behavior if it reaches the person who can fix it, where they
already work, so PerspectiveGraph plugs straight into the PR:

- **A PR comment** on the change that sits on a critical path (the kill chain +
  the one-edge fixes).
- **A merge-gate status** - a GitHub commit status `perspectivegraph/attack-paths`
  that goes **red** when the change opens an internet→sensitive-asset path and **green**
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

**The comment and the status count what the merge gate counts** (below): the routes a change
opened or made likelier, not every route through an asset it touched. They run after the
report has landed, so the comparison is between analysis passes. A route between an entry and a
sensitive asset that is new, or likelier, since the previous pass belongs to the pull-request
commits on it that arrived in between - the previous pass is the estate the change found. A
route that was already there gets no comment and keeps the status out of it. When a change makes
a route red, the status says how many routes were already there, and the comment says whether
the change opened the route or made it likelier, with both figures. Every commit on a route is
judged, not only the first one found on it.

A route that appears through a commit's assets *after* it arrived belongs to the pull request
that arrived with it: a second request putting a load balancer in front of a rescanned image is
the second request's doing, not the rescan's. If no pull request arrived with it - the rest of a
report too large to land at once, a change made outside any pull request - it counts against
the commits already on it, and the status says "since this change arrived" rather than claiming
the change opened it.

This state is kept in memory on every replica, so a new leader has it. A restart loses it, and
a commit already in the graph when the engine starts is judged by the per-commit rule. The
status says so ("in the graph before the engine was watching"), as the gate does for a commit
the engine already holds. `PR_ATTRIBUTION=commit` (Helm `prAttribution: commit`) keeps the
rule before 1.22: every route through the commit counts.

**`REPO_ALLOWLIST` is required for any of it to write.** That routing context is a node
property, and node properties arrive on the ingest path - which every scanner holding
the shared HMAC key can reach. Without a bound, one planted node redirects a write to
any repository the token can reach, and a `success` commit status in a repository where
this check is *required* opens a merge gate rather than closing one. So the operator
names the destinations, as exact slugs or an owner wildcard:

```bash
REPO_ALLOWLIST=acme/payments-api,acme/*
```

Empty means every real write is refused (dry-run still logs what it would do), and a
refusal is logged with the slug it declined.

Everything below - the connectors, topology discovery, scoring, runtime
confirmation, the dashboard - exists so that red check is *true*: a real, reachable
path, not noise.

### The merge gate: GitHub Action, CLI and Trivy plugin

**What counts against the change.** The gate applies this pull request's report to a copy of
the estate - through the same normalizer the ingest path runs - and compares the critical paths
of the copy with the estate's own. A route between an entry and a sensitive asset that did not
exist before is one the change **opens**; one that became likelier, it **worsens**. Those count.
A route that was there before does not, even when it runs through an asset the change touches -
the rescanned image, the re-rendered deployment - and the verdict reports how many there were
(`preexisting`) rather than hiding them. Nothing is written into the live graph.

Before 1.22 the gate counted every route through an asset stamped with the commit, and so
blocked a change for routes it did not cause: in the demo lab, nine where the change opened two.
That rule is still there, by name: `attribution: commit` (CLI `-attribution commit`). The gate
also falls back to it by itself - and says so - when it has no report to compare (poll-only), or
the engine predates the comparison. And when the engine *already* holds the commit (`persist` on
an earlier run, or another step posting the same scan to the webhook), the comparison cannot
tell its routes from older ones, so routes through it count per commit: conservative on purpose,
it can block a change the comparison would pass, never the reverse.

When none of the change's assets can be reached from an attack seed at all, a clean verdict says
so. That is fine for a service that is not deployed; for one that is, the usual cause is a scan
naming the image differently from the workload that runs it.

**Local mode needs no deployment.** The runner reads your estate read-only, applies this pull
request's scan, and answers in-process with the same engine:

```yaml
- uses: luiacuaniello/perspectivegraph@v1
  with:
    mode: local
    aws-region: eu-west-1     # read-only; give the job an OIDC role with SecurityAudit
    report: trivy.json
    base-reports: |           # the scan of what runs now - the base branch
      trivy=trivy-base.json
```

`base-reports` is what makes the comparison fair. Without it the estate knows nothing of the
scanned image's findings, so every route through them counts as the change's - the same answer
the per-commit rule gives.

An estate is not optional, and that is the point: without one there are no attack paths, only
a flat list of findings - the thing this replaces. If you collect your estate on its own
schedule, pass `estate: estate.json` (what `perspectivegraph awscollect -json` writes) instead
of `aws-region`.

**Server mode points at a running engine**, which keeps the graph across pull requests, plus
triage, history and the dashboard. The comparison is an API call (`POST /gate/impact`, the same
query parameters as the ingest webhook, the report as the body), so it takes the API token:

```yaml
- uses: luiacuaniello/perspectivegraph@v1
  with:
    api: https://perspectivegraph.internal
    token: ${{ secrets.PG_API_TOKEN }}
    report: trivy.json
```

The baseline is the graph as it stands - what runs now, as your main-branch pipeline and
connectors last described it. To also record the pull request's scan in the live graph (the
engine's own PR comments and commit status are driven by what is ingested), add
`persist: true` with `ingest` and `hmac-secret`; the verdict is computed first, without it. A
proxy in front of the API must pass `/gate/` and let a report through, up to the 32 MiB the
backend accepts, as for `/ingest`. The bundled dashboard does, and so does the Helm ingress: it
raises the nginx-based controllers' 1 MiB default (`ingress.maxBodySize`, rendered as the
ingress-nginx and F5 NGINX annotations; one you set yourself wins). Any other proxy needs the
same.

Both modes run the same comparison (package `impact`), the same normalizer, the same pathfinder
and the same triage priority. Under `attribution: commit` they return the same per-commit
verdict - a test asserts they agree path-for-path on identical input.

The scan is not the only thing a pull request can send: a rendered manifest set
(`helm template`, `kustomize build`) as the report with `source: k8s` is compared the same way,
so a change that publishes a Service fails the check the same way a vulnerable dependency does -
and one that re-renders every manifest unchanged passes. That matters because manifests are how
most routes actually open.

If the estate holds more than one cluster, its dumps are sent with `?cluster=` (see
[onboarding](onboarding.md#kubernetes-topology-auto-discovered-exposure)), and the gate must name
the same cluster: `cluster: prod-eu` on the Action, `-cluster prod-eu` on the CLI. Kubernetes names
repeat across clusters, so the cluster is part of every object's identity; a manifest sent under
another name, or none, meets nothing in the estate and passes as clean. The Action stops with an
error when `cluster` is set and the gate binary is older than 1.28.0, rather than drop it.

**A Terraform plan is judged before anything is deployed.** Most routes into an AWS account
are opened by infrastructure code: a security group rule, a policy attachment, a bucket policy.
`source: terraform` reads the plan as `terraform show -json` writes it:

```yaml
- run: |
    terraform plan -out tfplan
    terraform show -json tfplan > plan.json
- uses: luiacuaniello/perspectivegraph@v1
  with:
    mode: local
    source: terraform
    report: plan.json
    aws-region: eu-west-1   # optional: routes through what the configuration does not manage
```

A plan carries the state it starts from and the state it would leave, so the gate compares the
two and needs no estate of its own; with `aws-region` or `estate` it also sees routes that run
through what the configuration does not manage - a role defined elsewhere, an image, a cluster.
Server mode takes plans too, the engine's graph joining the plan's starting state.

Nothing in the plan is judged by rules of its own. Each state is written in the shapes the AWS
API returns and read by the collectors that read a live account, so a planned instance is judged
exposed by the same code - security groups, public address, route to an internet gateway - as a
running one, and is keyed the same way. A resource the plan creates has no identifier yet: it
gets a placeholder that keeps the prefix AWS will give it (`sg-`, `i-`, `igw-`) and names its
block in the configuration, and the configuration's references say what each identifier not
assigned yet will be. Read: security groups and their rules, subnets, route tables and routes,
internet gateways, Elastic IPs, EC2 instances and their instance profiles, IAM roles and users
with their policies, attachments and permissions boundaries, S3 buckets with their policies, ACLs
and Block Public Access, and Lambda functions with their URLs and permissions. Not read yet: load
balancers, API Gateway, ECS, EKS and network ACLs.

Some of a plan is known only after apply: a bucket policy that names its own bucket's ARN, when
the plan creates the bucket. A route through it can be neither found nor ruled out, so a run
that finds no route is `unknown`, and says which values were missing; plan again once the
resource exists, or set `allow-unknown`. The plan alone also has limits worth knowing. A rule
added to a security group the configuration does not manage reaches only the instances it
manages. An AWS managed policy's text is not in the plan: AdministratorAccess, PowerUserAccess
and IAMFullAccess are read from a copy built into the engine, any other as granting nothing. An
instance in a subnet the configuration does not describe is judged by its security groups alone,
erring toward reporting - unless the estate is read too and the plan leaves the instance's
exposure as it was, in which case the account's own verdict stands. And a plan whose resources
are all new names no account: a live read supplies it, and otherwise `account` (`-account`)
does, so its instances meet the estate's. A plan is never written into the live graph - the
ingest webhook does not take one, and `persist` is refused - because it describes what does not
exist yet.

**It has three outcomes, and the third is the point.** Every two-state gate gives a pipeline
whose scanner output never arrived the same green tick as one that is genuinely clean. Here
that is `unknown`, and it fails the build by default:

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `clean` | 0 | The engine analysed this change: it opens or worsens no critical path |
| `blocked` | 1 | It opens or worsens critical attack paths - the check names each, and why |
| `unknown` | 2 | **Nobody analysed it.** The scan, the ingest or the SHA is wrong - or no route was found in an estate read only in part, or in a plan part of which is known only after apply |

Set `allow-unknown: true` while you roll the gate out. Leaving it on afterwards turns a broken
ingest back into a green check, which is the one thing this gate is for.

**Without GitHub Actions**, the action is a thin wrapper over one command:

```bash
perspectivegraph gate -local -aws-region eu-west-1 \
  -report trivy.json -slug owner/name -sha "$COMMIT_SHA"
```

**As a Trivy plugin**, the answer arrives where the CVE list does:

```bash
trivy plugin install github.com/luiacuaniello/perspectivegraph
trivy image -f json myapp:pr-42 | trivy perspectivegraph gate -local -aws-region eu-west-1 -report -
```

Run like that, it keeps the gate's exit codes. As an output plugin
(`-o plugin=perspectivegraph --output-plugin-arg "gate ..."`) it works the same way, but Trivy
folds every verdict other than clean into exit 1.

**Two things to settle before wiring it up.**

- **Fork pull requests.** The gate needs secrets, and GitHub gives a fork's `pull_request` run
  none - so a fork PR cannot be analysed and fails closed as `unknown`. Do **not** reach for
  `pull_request_target` to work around it: that event runs with your secrets against the
  contributor's code, and in local mode your secrets are cloud credentials. Run the gate on
  `push` to your own branches instead, and let fork PRs go without it.
- **Public repositories.** When it blocks, the check prints the route - real asset names, the
  CVE linking them, the sensitive asset at the end - into the job log and summary, which on a
  public repository are public. Use `soft-fail` and post the detail somewhere private, or keep
  the gate on a private repository.

Full input reference in [`action.yml`](../../action.yml). The comparison is `POST /gate/impact`;
the per-commit rule's query is `prVerdict` in the [API schema](../api/schema.graphql), unchanged
for the gates built on it.

## Developer feedback on the PR

When a scan is fed with PR context (the `make seed` demo passes
`?slug=acme/payments-api&pr=42`), the action layer comments on the originating
pull request - but **only** for findings on a verified attack path, with the
path diagram and a remediation hint. It upserts a single comment per path
(idempotent across the analyzer's repeated passes). Without a `GITHUB_TOKEN` it
runs in **dry-run**, logging exactly what it would post. Set the token *and* the
allowlist that bounds where it may write (see above) to go live:

```bash
GITHUB_TOKEN=ghp_… REPO_ALLOWLIST=acme/payments-api make run-backend
```

Then open the dashboard at http://localhost:5173 and the GraphQL playground at
http://localhost:8080/graphql. Prefer Postman? Import
[`docs/perspectivegraph.postman_collection.json`](../perspectivegraph.postman_collection.json) -
health checks, every ingest webhook (with the demo payloads embedded) and all
GraphQL queries, ready to run.

Pointing it at a **real environment** (your own scanners, not the demo seed)?
Follow the [onboarding runbook](onboarding.md) - per-source `curl`/CI
snippets, the identifier-correlation helper, and a "no paths?" troubleshooting
guide.
