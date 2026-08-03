# <img src="docs/logo.svg" alt="PerspectiveGraph logo" width="32" height="32"> PerspectiveGraph

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


![PerspectiveGraph: from the day's exploitable routes to a generated fix](docs/demo.gif)

*Twenty seconds of `make demo`: what is exploitable now → the ranked routes → one route's
kill chain and its generated Terraform fix → whether the scores can be trusted. Sample
scanner output and seeded verdicts, not a real environment.*

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
[releases page](https://github.com/luiacuaniello/perspectivegraph/releases/latest),
signed with cosign and carrying SLSA build provenance. The signature covers `SHA256SUMS`,
so one check covers every archive:

```bash
cosign verify-blob --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp 'https://github.com/luiacuaniello/perspectivegraph/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS && sha256sum -c SHA256SUMS --ignore-missing
```

Add `-compare` and it also runs the engine over the same account and **exits non-zero
where the two disagree** - each disagreement is a false positive or a miss, in the
engine or in your assumptions. That check is how the permission-boundary bug described
in the [manual](docs/MANUAL.md) was found, and how it stays closed.

## See the whole engine in 90 seconds

```bash
make demo
```

Builds the stack, feeds it sample Trivy / Semgrep / Custodian / Falco / Kubernetes /
IAM / SSO output, waits for the analyzer, and prints the top attack path with its
generated fix. Dashboard on **http://localhost:3000**. Needs Docker, `jq` and `curl`;
first run takes a couple of minutes to build the images. Tear down with `make down`.

Prefer not to build? The release images are published to GHCR (`latest` also tracks the
newest release; the pinned tag is the one to use if you care about reproducibility):

```bash
docker pull ghcr.io/luiacuaniello/perspectivegraph:v0.9.4 # x-release-please-version
docker pull ghcr.io/luiacuaniello/perspectivegraph-dashboard:v0.9.4 # x-release-please-version
```

They are signed with cosign keyless and carry an SPDX SBOM plus a SLSA build
provenance attestation - verify before you run, rather than taking the supply chain
on trust:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/luiacuaniello/perspectivegraph/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/luiacuaniello/perspectivegraph:v0.9.4 # x-release-please-version
```

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

*Every screenshot on this page is `make demo`: sample scanner output and **seeded**
verdicts, not a real environment. That is why the calibration panel returns a verdict of
"underconfident" - across 14 seeded outcomes the engine predicted 60% where 71% held up.
Those outcomes were generated to exercise the instrument, not to flatter it. On a fresh
install the same page reads **"insufficient data"** and withholds a verdict until real
outcomes exist, because a risk score you cannot check is worth less than an honest blank.*

## Why?

Modern security teams don't suffer from a lack of tools - they suffer from **noise, fragmentation,
and missing context**.

| Role | Pain today | What PerspectiveGraph gives them |
| --- | --- | --- |
| **Developer** | CI/CD blocked by thousands of irrelevant CVEs | A PR check that goes red *only* when the change opens a real internet→sensitive-asset path - plus the fix as a one-click PR |
| **Security** | Triage on flat lists of 10,000 findings | A ranked list of ~5 critical **attack paths**, queryable like a database |
| **Architect** | No live view of how IaC becomes attack surface | Auto-generated, always-current architecture & data-flow maps + drift detection |


## Let an agent query it

A language model is weak at exactly what this engine is good at: it cannot enumerate
fourteen thousand edges reliably, it does not run Dijkstra, and asked for "the attack
paths in my account" it will produce plausible routes that do not exist. So the engine
speaks [MCP](https://modelcontextprotocol.io) - an agent calls it and reasons over
answers it could not have invented.

```bash
make mcp    # or: perspectivegraph mcp --api http://localhost:8080
```

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

## Project status & maturity

**The short version, if you read nothing else.** The engine and its public API are
complete, documented and tested. The AWS connector is verified against a real account.
The path *scores* are **not** calibrated against real exploited outcomes yet - read them
as a ranking, not as probabilities. So: use it to find and cut routes, and don't put its
risk percentage in front of a board. What is and isn't claimed is spelled out in
[positioning](docs/POSITIONING.md). It collects **no telemetry**: out of the box it opens
no outbound connection at all - GitHub, the AI assistant and the KEV/EPSS feeds each stay
dark until you set a key or flag (`THREATINTEL` is `off` by default).

**The benchmark, as of v0.9.4.** <!-- x-release-please-version --> `make bench-cloudgoat`
runs four CloudGoat-shaped scenarios in CI and grades the engine on each:

| Scenario | Expects | Result |
|---|---|---|
| `ec2_ssrf` | a path | found it, invented none |
| `iam_privesc_by_attachment` | a path (leaked-credential origin) | found it, invented none |
| `ec2_private_subnet_no_path` | **no** path (open SG, private subnet) | produced none |
| `iam_privesc_denied_by_guardrail` | **no** path (explicit Deny wins) | produced none |

Precision and recall are 1.00 on all four. Read that for what it is: four scenarios, two
of them negative controls - a regression gate against known shapes, not a measurement of
field accuracy on your estate.

The long version follows. PerspectiveGraph is **0.x, in active development** - the version
number means the API can still change - and built in the open. What's next is in the
[roadmap](ROADMAP.md); read this before you rely on it:

- **Engine: feature-complete.** The correlation engine, agentless connectors, triage,
  SSO, the PR merge-gate, the AI assistant, and the scale work are all implemented and
  covered by tests. The public API contract (GraphQL, ingest events, config, CLI) is
  documented and the GraphQL schema is frozen + drift-guarded - see the
  [API stability policy](docs/API-STABILITY.md).
- **Connector: validated against a real AWS account; scores: not yet field-calibrated.**
  The live connector, its read-only grant (`SecurityAudit` covers every call), cross-account
  `AssumeRole`, and the network↔identity join (`instance --ASSUMES--> role`) are **verified
  against a real account** - that last edge was in fact a gap only real-account testing
  exposed (the fixtures already contained edges AWS makes you derive). The
  reachability-precision claim is verified there too: `make reachability-lab-aws` stands up
  two instances behind **the same wide-open security group**, one in a subnet routed to an
  internet gateway and one in a subnet with no default route, and the engine marks only the
  first as exposed - suppressing the second with the reason, on real AWS rather than
  fixtures. What is **not** yet
  done is calibrating the path *scores* against real exploited outcomes: the self-calibration
  flywheel has run end-to-end only on deliberately-vulnerable synthetic targets (a log4shell
  app, a `kind` RBAC scenario). Treat the scores as **directionally honest, not
  production-calibrated**. One half of that gap is now closed against real AWS for free:
  `make redteam-aws` grades the engine's privilege-escalation claims with AWS's own policy
  evaluator - a read-only dry run that creates nothing and applies the SCPs and condition keys
  the engine's policy reader skips. That grading has already paid for itself: `make
  boundary-lab-aws` stands up two roles with an identical privesc policy that differ only in a
  permissions boundary, and it caught the engine calling both escalating where AWS allowed one
  and denied the other. **That false positive is now fixed** - the connector carries the
  boundary through and the evaluator intersects it - and the lab is the regression test,
  running the engine and AWS side by side on a real account and failing if they disagree.
  It deliberately does **not** rescale the path scores, and
  [the manual explains why it cannot](docs/MANUAL.md#closing-the-loop-calibration-against-observed-outcomes):
  those verdicts are one-sided, and a censored sample is not a measurement. The `make validate-aws`, `make validate-harness-aws`, and
  `make validate-harness*` harnesses are the path to closing that on your own environment.
  For an offline, CI-gated check that the engine actually finds the *right* paths, `make
  bench-cloudgoat` grades it against a battery of [CloudGoat-shaped ground-truth
  scenarios](backend/testdata/cloudgoat/README.md) (precision/recall) - including the
  reachability-precision case (an open SG on a private-subnet box must **not** form a path)
  and the credential-origin case (a leaked-key privesc is invisible until `SEED_IAM_USERS`
  is on). It runs under `make test`, so a regression that loses or invents a path fails the build.
- **Deployment: demo-grade defaults, with a production switch.** The bundled `docker
  compose` / Helm setup is hardened for a demo (distroless, non-root, read-only rootfs,
  digest-pinned 0-CVE images, opt-in TLS) and is deliberately open so `make demo` is one
  command. Set **`PG_ENV=production`** and the backend **refuses to start** unless both the
  API and ingest are authenticated - the permissive default cannot be reached by forgetting
  to configure it. A production rollout still needs your own hardening beyond that: an
  external managed PostgreSQL+AGE, secrets in a manager (not env vars), TLS on by default,
  backups, and HA for the leader-gated scheduler. For people use OIDC, so revoking access is
  your IdP's job rather than a token rotation - see the
  [operations & hardening runbook](docs/OPERATIONS.md), [`SECURITY.md`](SECURITY.md), and the
  [threat model](docs/THREAT-MODEL.md).
- **Scope.** It answers the reachable attack-path question in the developer workflow. It is
  not a scanner, a CNAPP, or a compliance product, and it does not replace them.

- **How it is written.** Developed by a human working with Claude (Anthropic): the design
  decisions and what ships are the maintainer's, a large share of the implementation and its
  tests came out of that collaboration. Said plainly for the same reason the engine reports its
  own calibration - a claim you can check beats one you have to accept. Check it:
  `make test`, `make bench-cloudgoat`, `govulncheck ./...`, `gosec ./...`. See
  [CONTRIBUTING](CONTRIBUTING.md).

Issues and PRs are welcome. Nothing here is claimed beyond what the tests and the listed
validation cover.


## Documentation

The [manual](docs/MANUAL.md) is the full reference: the scoring model, every
integration, deployment, hardening and the runbook for pointing it at your own
environment.

- [Manual](docs/MANUAL.md) - architecture, scoring, quick start, deploy, operate
- [Positioning](docs/POSITIONING.md) - what is claimed, what is **not**, and how to check
- [Roadmap](ROADMAP.md) - what's next, and what it deliberately isn't becoming
- [Threat model](docs/THREAT-MODEL.md) · [Operations](docs/OPERATIONS.md) · [API stability](docs/API-STABILITY.md) · [Scale](docs/SCALE.md)
- [Attack-path benchmark](backend/testdata/cloudgoat/README.md) - the CI-gated precision/recall battery

Verify the claims rather than taking them: `make test`, `make bench-cloudgoat`
(precision/recall against known-vulnerable scenarios), `govulncheck ./...`.

## License

[Apache License 2.0](./LICENSE).
