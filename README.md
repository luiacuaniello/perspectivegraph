# <img src="docs/logo.svg" alt="PerspectiveGraph logo" width="32" height="32"> PerspectiveGraph

[![CI](https://github.com/luiacuaniello/perspectivegraph/actions/workflows/ci.yml/badge.svg)](https://github.com/luiacuaniello/perspectivegraph/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/luiacuaniello/perspectivegraph?sort=semver)](https://github.com/luiacuaniello/perspectivegraph/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Live demo](https://img.shields.io/website?url=https%3A%2F%2Fdemo.a3thinker.it&label=live%20demo&up_message=online&down_message=offline)](https://demo.a3thinker.it)

> **Your scanners find issues. This finds the way in.**

PerspectiveGraph joins what you already run - Trivy, Semgrep, Cloud Custodian, Falco, plus your
AWS and Kubernetes state - into one graph of your *real* environment, and asks a single question
of it:

> *can someone get from the internet, through privilege that is too broad, to something worth
> stealing?*

On a pull request it asks that question **before the merge**: the check goes red only when *this
change* opens a route, and the fix comes back as its own pull request. Open source (Apache 2.0),
runs on your infrastructure, collects no telemetry.

![PerspectiveGraph: from the day's exploitable routes to a generated fix](docs/demo.gif)

*Twelve seconds of `make demo`: what is exploitable now → the ranked routes → one route's kill
chain and the fix it generates → whether the scores can be trusted. Sample scanner output and
seeded verdicts, not a real environment.*

- **[See it running](https://demo.a3thinker.it)** - the same dashboard, published read-only. Nothing to install.
- **[Check your own AWS account](#check-your-own-account-in-30-seconds)** - one read-only command, thirty seconds, no deployment.
- **[Put it on your pull requests](#block-the-pull-request-that-opens-the-path)** - ten lines of YAML.

A score here is what the model concludes from the evidence it was given, not a measured
frequency: **nothing has been calibrated against field data yet**, and the engine says so itself
rather than rounding up. [What is measured, and what is not](#project-status--maturity).


## Check your own account in 30 seconds

No deployment, no Docker, nothing ingested. One static binary asks **AWS's own policy
evaluator** which of your roles can reach administrator - applying the service control
policies, permission boundaries and condition keys that a policy reader on its own does
not see:

```bash
# macOS (Apple silicon); swap darwin_arm64 for linux_amd64, linux_arm64 or darwin_amd64
curl -sSL https://github.com/luiacuaniello/perspectivegraph/releases/latest/download/perspectivegraph_darwin_arm64.tar.gz | tar xz
./perspectivegraph redteam -roles -region eu-west-1
```

It is **read-only and free**: every check is one `iam:SimulatePrincipalPolicy` call, a
dry run that evaluates policy without performing anything, so it creates nothing and
costs nothing. It needs `iam:SimulatePrincipalPolicy` and `iam:ListRoles` - both inside
`SecurityAudit`. Binaries for linux/macOS (amd64, arm64) and Windows are on the
[releases page](https://github.com/luiacuaniello/perspectivegraph/releases/latest), signed
with cosign and carrying SLSA build provenance - two commands
[verify both](SECURITY.md#our-own-supply-chain) before you run anything.

Add `-compare` and it also runs the engine over the same account and **exits non-zero
where the two disagree** - each disagreement is a false positive or a miss, in the
engine or in your assumptions. That check is how the permission-boundary bug described
in the [manual](docs/MANUAL.md) was found, and how it stays closed.

That command is also stage 0 of a fuller trial: [how to evaluate this](docs/EVALUATION.md)
walks from here to a verdict in stages that each end in an answer - and says what the
trial will *not* tell you before you spend a fortnight finding out.

## See the whole engine in 90 seconds

```bash
make demo
```

Pulls the **published, cosign-signed images**, feeds them sample Trivy / Semgrep /
Custodian / Falco / Kubernetes / IAM / SSO output, waits for the analyzer, and prints the
top attack path with its generated fix. Dashboard on **http://localhost:3000**. Needs
Docker, `jq` and `curl` - no Go or Node toolchain, and nothing is compiled: measured at
**23 seconds** from an empty image cache. Tear down with `make down`.

Building it yourself instead is `make demo-build`, which is the same demo from your
working tree. The images the fast path runs are the release artefacts, so you can check
what you are about to run before you run it - the `cosign verify` command is at the top of
[`docker-compose.demo.yml`](docker-compose.demo.yml).

Prefer not to build? The release images are published to GHCR (`latest` also tracks the
newest release; the pinned tag is the one to use if you care about reproducibility):

```bash
docker pull ghcr.io/luiacuaniello/perspectivegraph:v1.17.0 # x-release-please-version
docker pull ghcr.io/luiacuaniello/perspectivegraph-dashboard:v1.17.0 # x-release-please-version
docker pull ghcr.io/luiacuaniello/perspectivegraph-postgres:v1.17.0 # x-release-please-version
```

On Kubernetes, the Helm chart is published the same way - no clone needed, and a version
you can pin and verify. It is listed on
[Artifact Hub](https://artifacthub.io/packages/helm/perspectivegraph/perspectivegraph) as an
**official** package from a verified publisher - Artifact Hub's way of saying it comes from the
people who wrote the software rather than a third party repackaging it:

```bash
helm install perspectivegraph oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  --version 1.17.0 # x-release-please-version
```

Images and chart are signed with cosign keyless and carry an SPDX SBOM plus a SLSA build
provenance attestation - [verify them](SECURITY.md#our-own-supply-chain) rather than taking the
supply chain on trust.

The dashboard opens on the decision, not the inventory: what is being exploited right
now, the fewest changes that remove the most risk, and how much the numbers can be
trusted.

![The day's decision surface](docs/screenshot-overview.png)

Routes are ranked by a composite triage priority - what the route reaches, whether
runtime confirmed it, how exposed the entry is - not by raw exploit score, so a
lower-scoring route can and does outrank a higher-scoring one.

| | |
|---|---|
| ![Attack path detail](docs/screenshot-paths.png) | ![Score calibration](docs/screenshot-trust.png) |
| Every hop, its probability, where that probability came from, and the ATT&CK technique. | Whether the engine's own scores held up against recorded outcomes. |

*Every screenshot on this page is `make demo`, signed in with a token: sample scanner output and **seeded**
verdicts, not a real environment. That is why the calibration panel returns a verdict of
"underconfident" - across 14 seeded outcomes the engine predicted 60% where 71% held up.
Those outcomes were generated to exercise the instrument, not to flatter it. On a fresh
install the same page reads **"insufficient data"** and withholds a verdict until real
outcomes exist, because a risk score you cannot check is worth less than an honest blank. The
public demo at [demo.a3thinker.it](https://demo.a3thinker.it) is this same dashboard with no
seeded verdicts at all, so its Trust page reports insufficient data; it runs on a single free
VM, so treat it as best-effort - the badge at the top says whether it is up.*

## Why?

Modern security teams don't suffer from a lack of tools - they suffer from **noise,
fragmentation and missing context**. A scanner reports that a container carries a critical CVE.
It cannot report that the container sits behind an internet-facing load balancer, runs with a
role that reads the production database, and is therefore the one finding out of ten thousand
worth doing something about this week. That second question needs the other tools' output in
the same graph, which is what this builds.

| Role | Pain today | What PerspectiveGraph gives them |
| --- | --- | --- |
| **Developer** | CI/CD blocked by thousands of irrelevant CVEs | A PR check that goes red *only* when the change opens a real internet→sensitive-asset path - plus the fix as a one-click PR |
| **Security** | Triage on flat lists of 10,000 findings | A ranked list of ~5 critical **attack paths**, queryable like a database |
| **Architect** | No live view of how IaC becomes attack surface | Auto-generated, always-current architecture & data-flow maps + drift detection |

It answers that question **in the developer's workflow** rather than in a console someone logs
into afterwards: the reachable path is caught and closed in code review, where it is cheapest,
not months later in production. This is shift-left attack-path analysis - not a scanner bolted
onto CI, and not a runtime CNAPP you log into after the fact.

The gate is powered by a full attack-path correlation engine, so the same graph also gives you
the rest: a queryable dashboard of your **~5 critical attack paths** (not 10,000 flat findings),
triage, runtime confirmation, an AI summary, and always-current architecture maps. **But the
wedge is the pull request.**


## Block the pull request that opens the path

**No deployment required.** The runner reads your estate read-only, ingests this pull
request's scan, and answers in-process with the same engine:

```yaml
- uses: luiacuaniello/perspectivegraph@v1
  with:
    mode: local
    aws-region: eu-west-1     # read-only; give the job an OIDC role with SecurityAudit
    report: trivy.json
```

The scan is not the only thing a pull request can send: a rendered manifest set
(`helm template`, `kustomize build`) posted to `/ingest/k8s?slug=&sha=` attributes the
objects it contains to that commit, so a change that publishes a Service fails the check
the same way a vulnerable dependency does. That matters because manifests are how most
routes actually open.

An estate is not optional, and that is the point: without one there are no attack paths,
only a flat list of findings - the thing this replaces. If you collect your estate on its
own schedule, pass `estate: estate.json` (what `perspectivegraph awscollect -json` writes)
instead of `aws-region`.

Already running the engine? Point at it and it keeps the graph across pull requests, plus
triage, history and the dashboard:

```yaml
- uses: luiacuaniello/perspectivegraph@v1
  with:
    api: https://perspectivegraph.internal
    ingest: https://perspectivegraph.internal:8081
    report: trivy.json
    hmac-secret: ${{ secrets.PG_INGEST_HMAC }}
```

Both modes run the same normalizer, the same pathfinder and the same triage priority, and
return the same verdict - a test asserts they agree path-for-path on identical input.

The check goes red when *this commit* puts a sensitive asset within reach. Not when it
adds a critical CVE - a critical on a host nothing routes to does not fail the build, and
a medium on a container that now reaches the production database does. That is a
different question from the one your other scanners answer, and answering it needs a live
estate, which is why the action talks to a running engine instead of scanning the runner.

**It has three outcomes, and the third is the point.** Every two-state gate ever written
gives a pipeline whose scanner output never arrived the same green tick as one that is
genuinely clean. Here that is `unknown`, and it fails the build by default:

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `clean` | 0 | The engine analysed this commit and found no path through it |
| `blocked` | 1 | Critical attack paths run through it - the check names them |
| `unknown` | 2 | **Nobody analysed it.** The scan, the ingest or the SHA is wrong |

Set `allow-unknown: true` while you roll the gate out. Leaving it on afterwards turns a
broken ingest back into a green check, which is the one thing this gate is for.

The same thing without GitHub Actions - the action is a thin wrapper over one command:

```bash
perspectivegraph gate -local -aws-region eu-west-1 \
  -report trivy.json -slug owner/name -sha "$COMMIT_SHA"
```

Already running Trivy? The same gate installs as a Trivy plugin, so the answer arrives
where the CVE list does:

```bash
trivy plugin install github.com/luiacuaniello/perspectivegraph
trivy image -f json myapp:pr-42 | trivy perspectivegraph gate -local -aws-region eu-west-1 -report -
```

Run like that, it keeps the gate's exit codes. As an output plugin
(`-o plugin=perspectivegraph --output-plugin-arg "gate ..."`) it works the same way, but
Trivy folds every verdict other than clean into exit 1.

> **Two things to settle before wiring it up.**
>
> **Fork pull requests.** The gate needs secrets, and GitHub gives a fork's `pull_request`
> run none - so a fork PR cannot be analysed and fails closed as `unknown`. Do **not**
> reach for `pull_request_target` to work around it: that event runs with your secrets
> against the contributor's code, and in local mode your secrets are cloud credentials.
> Run the gate on `push` to your own branches instead, and let fork PRs go without it.
>
> **Public repositories.** When it blocks, the check prints the route - real asset names,
> the CVE linking them, the sensitive asset at the end - into the job log and summary,
> which on a public repository are public. Use `soft-fail` and post the detail somewhere
> private, or keep the gate on a private repository.

Full input reference in [`action.yml`](action.yml); the underlying query is `prVerdict`
in the [API schema](docs/api/schema.graphql).


## Let an agent query it

A language model is weak at exactly what this engine is good at: it cannot enumerate
fourteen thousand edges reliably, it does not run Dijkstra, and asked for "the attack
paths in my account" it will produce plausible routes that do not exist. So the engine
speaks [MCP](https://modelcontextprotocol.io) - an agent calls it and reasons over
answers it could not have invented.

```bash
make mcp    # or: perspectivegraph mcp --api http://localhost:8080
```

No engine running? Point it at the live demo instead: `perspectivegraph mcp --api
https://demo.a3thinker.it` answers every tool - `simulate_fix` included - from the sample
data, with no credential.

```json
{"mcpServers": {"perspectivegraph": {
  "command": "perspectivegraph",
  "args": ["mcp", "--api", "http://localhost:8080"]}}}
```

Eight tools: `get_posture`, `list_attack_paths`, `explain_attack_path`,
`routes_to_target`, `list_fixes`, **`simulate_fix`**, `search_assets`,
`get_score_trust`. The one worth the integration is `simulate_fix` - it re-runs the
whole simulation with the given edges cut and reports what actually changes, settling
"would this help" with a deterministic counterfactual instead of an argument.

The surface is **read-only**: nothing suppresses a path, opens a PR or records a
verdict, because an agent that can silently accept a risk is a liability rather than a
feature. Every tool declares that on the wire (`readOnlyHint`), so a host can decide what
to run unattended without taking this paragraph's word for it - and a test fails if a
tool is ever added without that decision. The descriptions also tell the model the scores
are expert estimates, and to call `get_score_trust` before quoting one as a probability.
Every tool is also run against the real engine in the test suite, not only a stub, so a
query naming a field the schema lacks fails the build instead of an agent's call.
`search_assets` asks the engine whether full-text search is on: without OpenSearch an agent
is told so, instead of receiving an empty result that reads as "no asset by that name".

The server is in the official [MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.luiacuaniello/perspectivegraph`, published from every stable release, and on
[Glama](https://glama.ai/mcp/servers/luiacuaniello/perspectivegraph), which builds it,
inspects the tools it exposes and grades their definitions - a grade of the MCP surface,
not of the engine's scores:

[![PerspectiveGraph MCP server on Glama](https://glama.ai/mcp/servers/luiacuaniello/perspectivegraph/badges/score.svg)](https://glama.ai/mcp/servers/luiacuaniello/perspectivegraph)

## Project status & maturity

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13828/badge)](https://www.bestpractices.dev/projects/13828)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/perspectivegraph)](https://artifacthub.io/packages/helm/perspectivegraph/perspectivegraph)
[![Go](https://img.shields.io/github/go-mod/go-version/luiacuaniello/perspectivegraph?filename=backend%2Fgo.mod)](backend/go.mod)

**The short version, if you read nothing else.** The engine and its public API are complete,
documented and tested, and the AWS connector is verified against a real account. What is **not**
done is calibration: the path *scores*, and the *order* they produce, have not been graded
against real exploited outcomes. Nobody has yet run this over a real estate, tested the paths it
surfaced and fed the verdicts back. The machinery for that loop is built and tested; the loop is
not closed.

So read a score as *what this model believes, and how sure it says it is*, not as a measured
frequency. A path at 0.7 has not been shown to be exploited seven times in ten - it is what the
model concludes from the evidence it was given, with an interval beside it saying how thin that
evidence is. On a fresh install the calibration page reports **insufficient data** and withholds
a verdict, because a risk score you cannot check is worth less than an honest blank. Use this to
find and cut routes; don't put its percentage in front of a board. What is and isn't claimed is
spelled out in [positioning](docs/POSITIONING.md). It collects **no telemetry**: out of the box
it opens no outbound connection at all - GitHub, the AI assistant and the KEV/EPSS feeds each
stay dark until you set a key or a flag (`THREATINTEL` is `off` by default).

**What is measured today, as of v1.17.0.** <!-- x-release-please-version --> Two things, both
reproducible without taking anyone's word for them.

`make bench-cloudgoat` runs four [CloudGoat-shaped scenarios](backend/testdata/cloudgoat/README.md)
in CI and grades the engine on each:

| Scenario | Expects | Result |
|---|---|---|
| `ec2_ssrf` | a path | found it, invented none |
| `iam_privesc_by_attachment` | a path (leaked-credential origin) | found it, invented none |
| `ec2_private_subnet_no_path` | **no** path (open SG, private subnet) | produced none |
| `iam_privesc_denied_by_guardrail` | **no** path (explicit Deny wins) | produced none |

Precision and recall are 1.00 on all four. Read that for what it is: four scenarios, two of them
negative controls - a regression gate against known shapes, not a measurement of field accuracy
on your estate. On real AWS, `make reachability-lab-aws` makes the same kind of check for free:
two instances behind one wide-open security group, only one routed to an internet gateway, and
only that one may be reported as exposed.

`make redteam-aws` grades the engine's privilege-escalation claims against **AWS's own policy
evaluator** - read-only, free, and it applies the service control policies, permission boundaries
and condition keys the engine's policy reader skips. That grading has already paid for itself: it
caught the engine reporting an escalation a permissions boundary made impossible. The bug is
fixed, and `make boundary-lab-aws` is now its regression test - engine and AWS side by side on a
real account, **exiting non-zero when they disagree** in either direction. It deliberately does
not rescale the path scores, and
[the manual explains why it cannot](docs/MANUAL.md#closing-the-loop-calibration-against-observed-outcomes):
those verdicts are one-sided, and a censored sample is not a measurement.

**The long version.** PerspectiveGraph is **1.x and in active development**, built in the open.
[What is next](ROADMAP.md) - and read this before you rely on it:

- **Engine: feature-complete.** Correlation, agentless connectors, triage, SSO, the merge gate,
  the AI assistant and the scale work are implemented and covered by tests. The GraphQL schema is
  frozen and drift-guarded, so a breaking change goes through a major version rather than
  arriving in a patch - [API stability policy](docs/API-STABILITY.md).
- **Clouds: AWS is live, Azure is fixtures only, there is no GCP connector.** The connector, its
  read-only `SecurityAudit` grant, cross-account `AssumeRole` and the network↔identity join
  (`instance --ASSUMES--> role`) are verified against a real account - that last edge was a gap
  only real-account testing exposed. Closing the calibration loop on your own estate is what
  `make validate-aws` and the [evaluation guide](docs/EVALUATION.md) are for.
- **Deployment: demo-grade defaults, with a production switch.** The backend is hardened wherever
  it runs (distroless, non-root, read-only rootfs, digest-pinned 0-CVE images, opt-in TLS) and
  under Helm every workload satisfies the `restricted` Pod Security Standard, asserted in CI. The
  compose defaults are deliberately open; `PG_ENV=production` makes the backend refuse to start
  unless API and ingest are both authenticated. A real rollout needs more - external
  PostgreSQL+AGE (**managed only on Azure**), secrets in a manager, TLS, backups, and
  `TRUSTED_PROXY_CIDRS` set, or per-IP limits key on your proxy for everybody:
  [operations runbook](docs/OPERATIONS.md), [`SECURITY.md`](SECURITY.md),
  [threat model](docs/THREAT-MODEL.md).
- **Support: the newest release, and nothing behind it.** No backports, no LTS branch - at six
  minor releases in the eight days after 1.0, a maintenance branch is a promise one maintainer
  breaks. Promised instead: a clock on security fixes (Critical 7 days, High 30) and an upgrade
  specified rather than hoped for. [SUPPORT.md](SUPPORT.md) is the policy.
- **Scope.** It answers the reachable attack-path question in the developer workflow. Not a
  scanner, a CNAPP or a compliance product, and it replaces none of them.
- **How it is written.** Developed by a human working with Claude (Anthropic): the design
  decisions and what ships are the maintainer's, a large share of the implementation and its
  tests came out of that collaboration. Said plainly for the same reason the engine reports its
  own calibration - a claim you can check beats one you have to accept: `make test`,
  `make bench-cloudgoat`, `govulncheck ./...`. See [CONTRIBUTING](CONTRIBUTING.md).

Issues and PRs are welcome. Nothing here is claimed beyond what the tests and the listed
validation cover.


## Documentation

The [manual](docs/MANUAL.md) is the full reference: the scoring model, every
integration, deployment, hardening and the runbook for pointing it at your own
environment.

- [Evaluation](docs/EVALUATION.md) - trying it on your own estate, in stages that each end in an answer
- [Manual](docs/MANUAL.md) - architecture, scoring, quick start, deploy, operate
- [Positioning](docs/POSITIONING.md) - what is claimed, what is **not**, and how to check
- [Support](SUPPORT.md) - which versions get fixes, how fast, and how to run this under change control
- [Upgrading](docs/UPGRADING.md) - the releases that need an action from you, and what it is
- [Roadmap](ROADMAP.md) - what's next, and what it deliberately isn't becoming
- [Threat model](docs/THREAT-MODEL.md) · [Operations](docs/OPERATIONS.md) · [API stability](docs/API-STABILITY.md) · [Scale](docs/SCALE.md)
- [Governance](GOVERNANCE.md) · [Maintainers](MAINTAINERS.md) · [Adopters](ADOPTERS.md) - who decides, who maintains, who runs it
- [Attack-path benchmark](backend/testdata/cloudgoat/README.md) - the CI-gated precision/recall battery

Verify the claims rather than taking them: `make test`, `make bench-cloudgoat`
(precision/recall against known-vulnerable scenarios), `govulncheck ./...`.

## License

[Apache License 2.0](./LICENSE).
