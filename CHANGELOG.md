# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
