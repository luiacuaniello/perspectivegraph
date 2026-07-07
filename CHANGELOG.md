# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  into the `cloudnet` shape (NSG inbound Allow rules → security groups, VMs → instances
  bound to their NSGs + tags, VNet peerings → VPC peerings; the `Internet` service tag
  normalizes to `0.0.0.0/0` so exposure is detected), then the **same** `cloudnet`
  collector parses it - identity resolution, graph and analyzer run unchanged. Transport
  is `fixtures` today (normalized `az network`/`az vm -o json`, no credentials), with
  `azure-sdk-for-go` the wired extension point. `CONNECTORS_ENABLED=aws,azure`,
  `AZURE_CONNECTOR_MODE`/`AZURE_FIXTURES_DIR`, wired through compose + Helm; covered by a
  fixtures test (Internet-open NSG → internet-exposed VM, PII VM as crown jewel).

### Changed
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
