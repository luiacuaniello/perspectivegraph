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

### Changed
- The path score `∏p` is now framed as the **baseline**, with three honest uncertainty
  views layered on (correlation band `[score, scoreUpperBound]`, the credible interval,
  and the attacker-profile mixture); the README "core idea" reflects this.
- `brierRecalibrated` is **k-fold cross-validated** (out-of-sample, so it doesn't
  overfit on thin real data); the calibration report carries `persistent` and the
  dashboard flags an `in-memory` verdict store (`VALIDATIONS_PATH` to persist).
- Documented the **EPSS input-provenance caveat** (a marginal exploitation rate, not a
  conditional per-edge traversal probability) at the source - fed as-is on purpose so
  calibration reveals/corrects the bias rather than a silent transform.

### Fixed
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
