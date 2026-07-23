# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0](https://github.com/luiacuaniello/perspectivegraph/compare/v0.3.0...v0.4.0) (2026-07-23)


### Features

* API stability policy with a frozen, drift-guarded GraphQL schema ([7d2255b](https://github.com/luiacuaniello/perspectivegraph/commit/7d2255be1f453c80018bc19f9b9b7970f01913b0))
* API stability policy with a frozen, drift-guarded GraphQL schema ([a88d105](https://github.com/luiacuaniello/perspectivegraph/commit/a88d1057491f178f657bafb45e176dc412f4b29b))
* CloudGoat attack-path calibration harness for real AWS ([136b40f](https://github.com/luiacuaniello/perspectivegraph/commit/136b40fe1b3e5887d6e3ad032e371a8eb01449ec))
* CloudGoat attack-path calibration harness for real AWS ([6cc6912](https://github.com/luiacuaniello/perspectivegraph/commit/6cc691275c877230f3fc7b0ad8db4748a7f345ec))
* CodeQL analysis and fuzzing of the ingest parse boundary ([9cb3b50](https://github.com/luiacuaniello/perspectivegraph/commit/9cb3b50e2d0c11801f121fde3fb188c5995aa78e))
* CodeQL analysis and fuzzing of the ingest parse boundary ([8eecb58](https://github.com/luiacuaniello/perspectivegraph/commit/8eecb589a43640376093ee586a35c7d4eb5478c8))
* **dashboard:** restructure around the decision, not the engine's mo… ([aaaf698](https://github.com/luiacuaniello/perspectivegraph/commit/aaaf6987db8aff3febee0e21cccb3084dd27b9e7))
* **dashboard:** restructure around the decision, not the engine's modules ([5c02813](https://github.com/luiacuaniello/perspectivegraph/commit/5c028139013857b7663ac3250a48220371ac7b78))
* **iam:** honor explicit Deny and resource scoping in privesc detection ([a0c1c33](https://github.com/luiacuaniello/perspectivegraph/commit/a0c1c33f3d39cc0c44893a1da866aa46da4b68c9))
* **iam:** honor explicit Deny and resource scoping in privesc detection ([1caab9f](https://github.com/luiacuaniello/perspectivegraph/commit/1caab9fccd06cbd057a17e2b8ca897696bd90f6b))
* link EC2 instances to their instance-profile role (the IMDS hop) ([f30ee16](https://github.com/luiacuaniello/perspectivegraph/commit/f30ee1676c72b7e862a93b7dacea06345fe49914))
* link EC2 instances to their instance-profile role (the IMDS hop) ([8c569a4](https://github.com/luiacuaniello/perspectivegraph/commit/8c569a43cacc57e263c6adabc6ae85086e18d3b2))
* **mcp:** serve the engine as tools an AI agent can call ([499b42c](https://github.com/luiacuaniello/perspectivegraph/commit/499b42cb939a948e920c06277a83e1a83c92c78a))
* **mcp:** serve the engine as tools an AI agent can call ([8aac837](https://github.com/luiacuaniello/perspectivegraph/commit/8aac837c09c9373ed31aa6eda1560f6a0d5f7e1c))
* observability dashboard + alerts and a scale-test harness ([cda5cd9](https://github.com/luiacuaniello/perspectivegraph/commit/cda5cd9a806f9393dec5e6102cabe992881b5047))
* observability dashboard + alerts and a scale-test harness ([ec499f1](https://github.com/luiacuaniello/perspectivegraph/commit/ec499f17945f1177d9d281c899290d1afd6d4ee0))
* **redteam:** AWS-oracle harness that generates independent calibrat… ([17b7fc1](https://github.com/luiacuaniello/perspectivegraph/commit/17b7fc12f1c7aa24df944939c971741103aadc9c))
* **redteam:** AWS-oracle harness that generates independent calibration verdicts ([7b5c5df](https://github.com/luiacuaniello/perspectivegraph/commit/7b5c5df1b5db7bf306d773f7186026c5de7b82c1))
* secure-by-default production deployment profile ([9b4b1ac](https://github.com/luiacuaniello/perspectivegraph/commit/9b4b1acdb28d1a3fc3085f974e86f1b8dae9adbe))
* secure-by-default production deployment profile ([9219870](https://github.com/luiacuaniello/perspectivegraph/commit/9219870209cdc26334249d51b7b6af0432464558))


### Bug Fixes

* **ci:** stop piping an unpinned install script into sh, drop ambient token permissions ([9d138b5](https://github.com/luiacuaniello/perspectivegraph/commit/9d138b5f50662e831e6e5bcd1722ac5a3f26d568))
* **ci:** stop piping an unpinned install script into sh, drop ambient… ([d4307c0](https://github.com/luiacuaniello/perspectivegraph/commit/d4307c09c17a194babf6c8184fa326da3ee60fd5))
* **dashboard:** stop polling two unbounded collections and one full s… ([3ed6202](https://github.com/luiacuaniello/perspectivegraph/commit/3ed620213c87606459d6d980924b37d1ad95b314))
* **dashboard:** stop polling two unbounded collections and one full simulation ([18c31c4](https://github.com/luiacuaniello/perspectivegraph/commit/18c31c42f0ba222b700df4742b7af2acb0515eb9))
* harden the AWS harness against real-scenario quirks ([0e05e98](https://github.com/luiacuaniello/perspectivegraph/commit/0e05e98dc405ff0b2284d12b9ec9382b37780b98))
* harden the AWS harness against real-scenario quirks ([f831964](https://github.com/luiacuaniello/perspectivegraph/commit/f831964250b03d456db75216344b1fb7c502d4de))
* harden the AWS harness against real-scenario quirks ([d008658](https://github.com/luiacuaniello/perspectivegraph/commit/d008658c955235144d5a5ee0a9d354ac17599d2e))
* harden the AWS harness against real-scenario quirks ([b13ed63](https://github.com/luiacuaniello/perspectivegraph/commit/b13ed635e123198802bd30c1132d6a20aed9a3f6))
* **sast:** suppress gosec G101 false positive on credential_exposed label ([a53229b](https://github.com/luiacuaniello/perspectivegraph/commit/a53229b679eb59af4b12cba53ddc2885f34f3501))
* **ui:** close the explainer by default, honour browser back, disclos… ([85bc9a6](https://github.com/luiacuaniello/perspectivegraph/commit/85bc9a6b9cbade720360dd1e7e6931675cd2f813))
* **ui:** close the explainer by default, honour browser back, disclose how this is built ([293e98c](https://github.com/luiacuaniello/perspectivegraph/commit/293e98c6a2c8e6aa4033ddf0bd5d2b610f976ed2))

## [0.3.0](https://github.com/luiacuaniello/perspectivegraph/compare/v0.2.0...v0.3.0) (2026-07-11)


### Features

* agentless connectors, triage, SSO login, PR gate, AI, and scale ([80b2b11](https://github.com/luiacuaniello/perspectivegraph/commit/80b2b11503cb0702a10422d4db61bba67ebbe9d1))
* Azure connector, math calibration, UX restyle, doc/screenshot refresh ([394a9f7](https://github.com/luiacuaniello/perspectivegraph/commit/394a9f7cd6440dd1d8bfc22d14e13b86935f68ee))
* initial release of PerspectiveGraph ([a1a901a](https://github.com/luiacuaniello/perspectivegraph/commit/a1a901a79b8a395e4f873ff15cffdfe61655f960))
* real-data validation + cloud network reachability precision ([d1ec584](https://github.com/luiacuaniello/perspectivegraph/commit/d1ec584177a0772d15ba7d1417d8ca3d4d2e1a44))
* sensitive-asset terminology, Azure fix, logo + UX polish, docs into README ([444a5e8](https://github.com/luiacuaniello/perspectivegraph/commit/444a5e86c2726305f2da3ed43872fb771c25b219))


### Bug Fixes

* bump Go toolchain to 1.25.12 to clear two stdlib CVEs ([c628cc1](https://github.com/luiacuaniello/perspectivegraph/commit/c628cc12507d6d8af6521c87b2e6573f2c6954c9))

## [Unreleased]

The "demo → production" line of work: make the attack-path **score honest about its
own uncertainty**, then **validate it against reality** and let that evidence decide
what to build next.

### Added
- **Probability calibration** - every red-team/BAS verdict captures the path's
  predicted score (server-side), turning the verdict log into a calibration dataset.
  The engine grades its own forecasts: Brier, log loss, ECE and a reliability diagram,
  with an honest verdict and an advisory rescale. GraphQL `calibration`; a Calibration
  panel on the Overview. The line between a demo and a risk tool you can put in front
  of an auditor.
- **Calibration diagnostics** - turns "are we calibrated?" into "and therefore what
  should we build?": a **cross-validated** isotonic recalibration (+ a map consumers
  apply out-of-band), calibration **segmented** by path structure (correlated/long ⇒
  structural), a **detection axis** (operator marks a confirmed verdict `detected`),
  and the Murphy resolution term - folded into one `diagnosis`
  (`recalibrate-first | structural (#6) | detection-axis (#7) | low-resolution`).
- **Calibration self-test** - `genverdicts` subcommand + `make calibration-selftest
  SCENARIO=…` draw verdicts from a *known* reality so the diagnostics can be validated
  without real vulnerable infra; the same scenarios run as a deterministic in-process
  CI test (`TestCalibrationScenarioDiagnosesEndToEnd`).
- **Epistemic uncertainty** - each edge is a Beta posterior whose width reflects its
  evidence (KEV/runtime tight, heuristic wide), propagated to a per-path 90% credible
  interval (`scoreCiLow`/`scoreCiHigh`) and a Beta-resampled headline risk band
  (replacing the flat ±30% sensitivity wiggle). Dependency-free Marsaglia-Tsang sampler.
- **Attacker-profile mixture** - the score is also marginalized over a latent attacker
  capability, `S(P) = Σ P(c)·∏ p(e|c)` (commodity/criminal/apt), reintroducing the
  positive correlation the bare product drops. Per-profile breakdown `mixtureScore` /
  `profileScores`; threat-model priors via `ATTACKER_PROFILE_PRIORS`.
- **Calibration trend** - Brier/ECE/sample-count over time (`calibrationTrend`, sampled
  each analyzer pass, persisted), shown as a "Brier over time" sparkline so a
  calibration program can watch the evidence accumulate.
- **Azure agentless connector** (`azure`) - a second cloud PULL source alongside `aws`,
  broadening the "connect read-only, see attack paths in minutes" reach. Azure's native
  model differs from the collector shape, so a thin mapper turns normalized `az` state
  into the `cloudnet` shape (NSG inbound Allow rules → security groups: CIDR sources →
  IpRanges with the `Internet` service tag normalizing to `0.0.0.0/0` so exposure is
  detected, and **ASG** sources → SG-to-SG `UserIdGroupPairs`, Azure's east-west
  micro-segmentation; VMs → instances bound to their NSGs **and ASGs** + tags; VNet
  peerings → VPC peerings), then the **same** `cloudnet` collector parses it - identity
  resolution, graph and analyzer run unchanged. The ASG mapping is what lets the exposed
  tier actually reach the crown jewel (without it the web VM dead-ends). Transport is
  `fixtures` today (normalized `az network`/`az vm -o json`, no credentials), with
  `azure-sdk-for-go` the wired extension point. `CONNECTORS_ENABLED=aws,azure`,
  `AZURE_CONNECTOR_MODE`/`AZURE_FIXTURES_DIR`, wired through compose + Helm; covered by a
  fixtures test (Internet-open NSG → internet-exposed web VM → ASG east-west → crown-jewel
  DB, the full internet → jewel path).

### Changed
- **Cloud network reachability precision: route tables + NACLs.** An open security
  group is necessary but not sufficient to reach an instance - it also needs a route
  to an internet gateway and a permitting network ACL. The `cloudnet` collector now
  accepts optional `subnets` / `route_tables` / `network_acls` (real `describe-subnets`
  / `describe-route-tables` / `describe-network-acls` shapes): an SG-open instance is
  flagged `internet_exposed` only if its subnet has a `0.0.0.0/0` → `igw-*` route AND
  its NACL admits internet ingress (evaluated in ascending rule order, first
  `0.0.0.0/0` match wins). This removes the classic false positive - an open SG on an
  instance in a *private* subnet (routed only through a NAT) - which is exactly the
  reachability-precision frontier where trust is won or lost. Backward-compatible: with
  no subnet/route/NACL data the SG-only heuristic stands, so existing feeds are
  unchanged; a blocked instance carries a `net_reachability` note explaining why. The
  live AWS connector (`sdk` mode) now fetches it too - `DescribeRouteTables` /
  `DescribeNetworkAcls` / `DescribeSubnets`, resolving each subnet to its route table
  (explicit association or the VPC's main) and NACL - so the agentless PULL produces the
  enriched bundle directly (grant adds `ec2:DescribeRouteTables`/`DescribeNetworkAcls`/
  `DescribeSubnets`, all in SecurityAudit/ViewOnlyAccess). Hardened for real VPCs before
  first contact: the default route's target is classified (NAT / transit-gateway / VPC
  peering / egress-only-IGW are all private egress, only `igw-*` is internet), IPv6
  (`::/0`) public subnets are handled, and terminated/shutting-down instances are dropped
  instead of emitting phantom seeds; the `net_reachability` note now names the egress
  path. Covered by fake-client + collector tests.
- **k8s escalation scoring gains resolution (a calibration-driven fix).** The
  `CAN_ESCALATE_TO` edge was a flat `0.9` for every RBAC primitive, so the path score
  couldn't tell a genuinely-exploitable escalation from a false positive. A
  real-topology calibration run (a `kind` cluster with misconfigured RBAC, exploited
  live, verdict taken from the API server's own RBAC decision) diagnosed exactly this
  as `low-resolution`. `escalationProb` now weights each primitive by how reliably it
  actually reaches cluster-admin: `bind` on rolebindings drops to `0.4` (Kubernetes'
  own anti-privilege-escalation usually refuses it - the common false positive), while
  `escalate`/`impersonate`/`secrets/read`/`serviceaccounts/token` stay high (0.85-0.9)
  and `workloads/create` sits at `0.6`. The score now discriminates (a secrets/read
  path at ~0.49 vs a bind path at ~0.23), and re-calibration moves the diagnosis off
  `low-resolution` to the fixable `recalibrate-first` - the calibration flywheel closing
  on the model's own behavior. Added the repeatable harnesses that surface this
  (`make validate-harness` / `make validate-harness-k8s`) and default-on verdict
  persistence in `docker compose` (a `perspective-govdata` volume + a `gov-init`
  ownership fix so the non-root backend can write it).
- **Real-account validation for the live AWS connector.** A new `awscollect`
  subcommand (and `make validate-aws`) runs the `sdk` connector once against a real
  read-only account (`describe-*` only, no writes) and prints what it discovered - the
  internet-exposed seeds vs the SG-open instances the route/NACL layer suppressed, each
  naming why. It's the first-contact check for reachability precision on data you didn't
  design; `-json` dumps the raw events and `-ingest <url>` pushes them into a running
  stack for full path scoring. Read-only grant: SecurityAudit / ViewOnlyAccess.
- **Terminology + UX polish.** The user-facing vocabulary drops "crown jewel" for the
  plainer, more neutral **sensitive asset** across the whole product surface - the
  dashboard (labels, tooltips, legends, hero and per-path copy), the triage priority
  factors (`sensitive asset target`), the policy invariant (`no-internet-to-sensitive-asset`
  + description), the OSCAL export, the GitHub PR comment / merge-gate status, and the
  product docs (README, ARCHITECTURE, GUIDA, DEMO, ONBOARDING). The gem glyph stays as
  the marker. The graph property key (`crown_jewel`), the operator
  tag (`crown-jewel: true`) and the API field names are unchanged (data contract). Two
  small simplifications rode along: the policy-violations view dropped a paragraph that
  duplicated its own subtitle, and the attack-path header no longer shows a
  "runtime-confirmed" priority chip next to the identical "ACTIVELY EXPLOITED" status
  badge.
- **Dashboard restyle - minimal over decorative.** The overview went from nine co-equal
  rainbow stat cards to a single hero metric (account compromise, with the calibration
  verdict beside it and a plain-language read) over a compact secondary strip. Surfaces
  are now flat (dropped the glass blur, the tactical grid mesh, the accent glows, and the
  neon text glow), colour is monochrome with one indigo accent and semantic red/amber
  reserved for real risk, and every label is sentence case. The primitives changed once
  (`index.css`, `tailwind.config.js`) so the whole app - sidebar, buttons, path list and
  detail, remediation, legend - flattened together. Dark stays the default; light is
  refined to match. Per-view simplifications followed: policy violations group by rule
  (the description shown once with an instance count, not repeated per offending subgraph),
  and the attack-path detail folds the score's four separate readouts into one coherent
  line (score + 90% credible interval + confidence, with the correlation ceiling as a
  subtle note) and drops the node chain the kill chain already shows.
- The path score `∏p` is now framed as the **baseline**, with three honest uncertainty
  views layered on (correlation band `[score, scoreUpperBound]`, the credible interval,
  and the attacker-profile mixture); the README "core idea" reflects this.
- `brierRecalibrated` is **k-fold cross-validated** (out-of-sample, so it doesn't
  overfit on thin real data); the calibration report carries `persistent` and the
  dashboard flags an `in-memory` verdict store (`VALIDATIONS_PATH` to persist).
- Documented the **EPSS input-provenance caveat** (a marginal exploitation rate, not a
  conditional per-edge traversal probability) at the source - fed as-is on purpose so
  calibration reveals/corrects the bias rather than a silent transform.

- **EPSS conditional-traversal map (P4, opt-in)** - EPSS is a *marginal* 30-day
  exploitation-in-the-wild rate, not the conditional a positioned attacker's traversal
  needs (`P(traverse this edge | already on the path)`), so feeding it as `p(e)` tends to
  understate a present attacker. `threatintel.EdgeProbability` now routes EPSS through an
  explicit `TraversalFromEPSS(epss) = epss^gamma` hook: `gamma < 1` lifts the marginal
  toward the conditional, `gamma = 1` (default) keeps EPSS as-is - the honest baseline the
  calibration loop still grades. Configurable via `EPSS_TRAVERSAL_GAMMA` (config ->
  compose -> Helm). It is a documented *prior*, not a fitted map: fitting `p(traverse|EPSS)`
  needs per-edge verdict ground truth (path-level verdicts don't isolate one edge), so the
  engine never rewrites the input silently - the operator opts in. The KEV branch (observed
  exploitation) is left untouched.
- **Common-cause correlation in the risk Monte Carlo (P3)** - the headline compromise
  probability sampled every edge independently, so two attack routes that both rest on
  the *same* weakness (one CVE, one leaked credential) counted as real redundancy and
  overstated reachability. Edges can now carry a `weight_cause` (the shared CVE/credential
  id); the Monte Carlo couples same-cause edges comonotonically - one draw per cause per
  trial - so a shared weakness's failure knocks out all its routes together (P(all) = min
  p, the Fréchet coupling). Applied consistently across the point, credible-band, and
  attacker-mixture reachability passes; deterministic (reproducible seed) and a no-op for
  edges without a cause. Collectors stamping `weight_cause` is the remaining data task; the
  model is ready. (For a single path the Fréchet ceiling `scoreUpperBound = min p` already
  captured this; P3 adds it to the multi-route aggregate.)
- **One coherent score posterior (P2)** - the per-path uncertainty was four numbers
  describing different quantities: the point `score` (independent `∏p`), a `scoreUpperBound`
  (Fréchet correlation ceiling), a credible interval computed on the *independent product*,
  and a separate attacker-`mixtureScore`. They didn't nest. P2 replaces the interval with a
  single Monte Carlo that composes epistemic uncertainty (each hop a Beta posterior) with
  the attacker-capability mixture in one pass, exposing `posteriorMean` (the coherent point
  estimate the interval now brackets, correcting the Jensen gap the plug-in mixture ignores)
  with `[scoreCiLow, scoreCiHigh]` around it. Beta concentration is now evidence-count-derived
  when an edge carries an `evidence_count` (`κ = count + prior`), falling back to the
  basis-confidence heuristic otherwise. Deterministic (seeded per path id), so parallel
  pathfinding stays byte-identical.
- **Per-basis recalibration (P1)** - the global isotonic map is monotone in the raw
  score, so it can't fix a bias *structured by evidence provenance*: if EPSS-derived
  hops run hot and heuristic hops run cold at the same score, no single curve corrects
  both, and they can even cancel at the aggregate so the global report reads
  "well-calibrated" while the model is badly miscalibrated per class. The engine now
  buckets each verdict by the path's weakest-evidence basis and fits a per-basis Platt
  correction (ridge-shrunk toward identity so thin buckets stay near the raw score),
  cross-validated. `brierRecalibratedByBasis` vs the global `brierRecalibrated`
  quantifies how much the miscalibration is provenance-structured; `basisSegments`
  shows which basis is off; `recalibrationByBasis` is the per-basis map to apply; and
  the `diagnosis` recommends per-basis recalibration when it materially wins. A
  `per-basis` self-test scenario (`make calibration-selftest SCENARIO=per-basis`) and a
  CI test guard the machinery.
- **Automatic BAS verdict import** - `POST /validations/import` is the push path a
  red-team/BAS platform's post-run webhook calls: it takes a whole report (a source +
  many findings), matches each finding to a live path server-side (by engine path id,
  or by crown-jewel target + optional entry name), captures the prediction, records it,
  and returns `{recorded, unmatched}` - no per-finding round-trips, no client-side
  matching. Findings carry `scope` (path|target) so they feed the right calibration
  track; the `importverdicts` CLI still works for file-based imports.

### Fixed
- **Helm persistence was silently broken.** `persistence.enabled: true` mounted an RWO
  PVC at `/data` and pointed the governance stores (validations/history/suppressions/
  tickets/audit) at it, but with no pod `fsGroup` the volume stayed root-owned and the
  nonroot (65532) distroless backend could not write - the first verdict failed. Added a
  pod `securityContext` (`fsGroup`/`runAsNonRoot`/`runAsUser` 65532) so the PVC is
  writable, a container `securityContext` (drop ALL caps, no privilege escalation,
  read-only rootfs) matching the compose hardening, and a `/tmp` emptyDir for the
  read-only rootfs. This makes the durable validation store - the calibration dataset
  the whole demo→production story rests on - actually persist.
- **Calibration graded the wrong event.** A single track paired every verdict's
  outcome with the path score `S(P)`, but a "the crown jewel was reached" verdict is
  an *any-route* event, not "this exact path was traversable" - conflating them biased
  the report. Verdicts now carry a `scope`: **path**-scoped grade `S(P)` (this path),
  **target**-scoped grade the per-target Monte Carlo compromise probability (the jewel
  reached at all), captured server-side. They run as two independent tracks
  (`calibration` and the nested `calibration.target`). `POST /validations` and
  `importverdicts` accept `scope: path|target` (default `path`, back-compatible); a
  path may carry one verdict of each scope.
- **K8s RBAC Group/User subjects** - a `(Cluster)RoleBinding` whose subject was a
  `Group` or `User` (not a `ServiceAccount`) drew no edge, so binding a group to a
  powerful role - e.g. `system:serviceaccounts:<ns>` or `system:authenticated` to
  cluster-admin, a common real-world misconfig - was invisible (a real `missed`
  verdict, precision/recall's false-negative, surfaced it on a live cluster). The
  collector now expands serviceaccount groups to the pods they cover, binds
  `system:unauthenticated`/`system:anonymous` to an internet-exposed anonymous
  principal, and records named/OIDC groups/users as standalone principals.
- **`make ingest-k8s` now fetches namespaced `role`** (not just `clusterrole`) so a
  namespaced escalation Role is visible to the collector (which already handled it).
- **Container-escape via added Linux capabilities** - `escapeReason` read only
  `privileged`/`hostPID`/`hostNetwork`/`hostIPC`/`hostPath`, so a non-privileged pod
  that adds a host-breaking capability (`SYS_ADMIN` and friends, or `ALL`) drew no
  escape edge and its *internet → pod → host* path was invisible. The collector now
  inspects `securityContext.capabilities.add` (CAP_ prefix / casing normalized) and
  emits `ESCAPES_TO` cluster-admin for the privileged-equivalent set.

### Security
- **Go toolchain 1.25.11 → 1.25.12** to clear two standard-library CVEs that the CI
  govulncheck + Trivy gates flagged: `GO-2026-5856` (Encrypted Client Hello privacy
  leak in `crypto/tls`, reachable via the NATS TLS handshake, HTTPS server and HTTP
  client) and `CVE-2026-39822` (HIGH - `os.Root` symlink-following directory traversal).
  Both are fixed in go1.25.12; no application-code change. Pinned consistently across
  `go.mod` (`toolchain`), CI (`go-version`), the backend Dockerfile (digest-pinned
  `golang:1.25.12-alpine`), the dev/harness scripts and CONTRIBUTING. Verified locally:
  govulncheck now reports 0 affected vulnerabilities.
- **Release-readiness hardening for going public.** Added `CODEOWNERS` and a `NOTICE`
  file; pinned every GitHub Actions dependency to a commit SHA (Dependabot's
  `github-actions` updates keep them current); added an OpenSSF Scorecard workflow; and
  a candid "Project status & maturity" section to the README that scopes exactly what is
  feature-complete, what is only calibrated on synthetic topology, and what still needs
  operator hardening before production. Published a [threat model](docs/THREAT-MODEL.md)
  (trust boundaries, assets, STRIDE walk with residual risk, and an operator checklist),
  linked from the README and SECURITY.md.
- **Signed, SBOM'd, provenanced release images.** A `publish-images` workflow (called
  by release-please when a release is cut, so it fires without a PAT) builds and pushes
  both images to GHCR, **signs them with cosign keyless** (Sigstore/OIDC, no long-lived
  keys), generates an **SPDX SBOM** per image (attested to the image and attached to the
  GitHub release), and attaches a **SLSA build-provenance** attestation. SECURITY.md now
  documents how to verify all three before running an image.
- **Operations & production-hardening runbook** ([docs/OPERATIONS.md](docs/OPERATIONS.md)) -
  what changes from the demo defaults for a real deployment: the secure-config env
  reference (auth, ingest HMAC + rate limit, TLS, `POSTGRES_SSLMODE`), external managed
  Postgres+AGE, **backup & restore** of the graph, upgrades, observability/SLOs, HA notes,
  and a pre-production checklist. Linked from the README maturity section.

## [0.2.0] - 2026-06-23

### Added
- **Agentless connectors** - a PULL ingestion framework plus an AWS connector
  (bundled fixtures and a live `aws-sdk-go-v2` EC2/IAM path via AssumeRole),
  leader-gated with a per-collect timeout (`CONNECTORS_ENABLED`, `AWS_*`).
- **Triage priority** - a composite per-path priority `[0,100]` (P1/P2/P3) with
  explainable factors; paths are returned priority-first so `attackPaths(limit:N)`
  is the actionable Top-N.
- **SSO login** - public `GET /auth/config` and a dashboard login gate running the
  full OIDC Authorization-Code + PKCE flow (RFC 7636) with a token fallback;
  per-tenant isolation proven by an end-to-end test. A bundled Keycloak demo
  (`docker compose --profile sso`, user `demo/demo`) exercises it locally.
- **Dev workflow** - a GitHub PR merge-gate commit status (red on an
  internet→crown-jewel path) and `POST /remediation/pr` that opens a branch +
  commit + pull request with the generated fix.
- **AI-native layer** - natural-language query, executive summary, and path
  explanation, grounded in the live attack paths; backed by Claude **or**
  HuggingFace / any OpenAI-compatible endpoint, self-gated and fully audited.
- **Scale** - parallel per-seed pathfinding (`ANALYZER_WORKERS`, byte-identical
  output), opt-in incremental snapshotting (`ANALYZER_INCREMENTAL`), benchmarks
  (`make bench`), and a `genload` load generator.
- Deployment: every feature env var wired through `docker-compose.yml` and the
  Helm chart; at-rest encryption, signed exports, and abuse detection surfaced
  as first-class config.

### Changed
- Dashboard image hardening: distroless backend stays at 0 CVEs; the dashboard
  drops `curl` + its dependency chain and bumps the nginx base, reaching 0
  critical / 0 high.

### Fixed
- Dashboard nginx now proxies `/auth/config`, `/ai/`, and `/remediation/` to the
  backend, so the login gate, AI assistant, and open-fix-PR work same-origin in
  the container (previously only reachable on `:8080` directly).
- JWKS cache refetches on an unknown `kid` (rate-limited), so an IdP key rotation
  is picked up promptly instead of rejecting valid tokens until the TTL lapses.
- The brute-force lockout now counts only a *rejected credential*, not anonymous
  requests or a valid token with an insufficient role - so a login-gated SPA
  polling before sign-in can no longer trip the lockout on itself.

## [0.1.0] - 2026-06-22

### Added
- Initial release of PerspectiveGraph: the DevSecOps attack-path correlation
  engine - graph core (Apache AGE), ingestion + normalization, the analyzer
  (critical paths, risk, policy invariants, temporal history), GraphQL API +
  React dashboard, exports, and the security/governance baseline.

[Unreleased]: https://github.com/luiacuaniello/perspectivegraph/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/luiacuaniello/perspectivegraph/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/luiacuaniello/perspectivegraph/releases/tag/v0.1.0
