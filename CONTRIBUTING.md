# Contributing to PerspectiveGraph

Thanks for your interest! PerspectiveGraph is Apache-2.0 and built to be extended.

**Looking for somewhere to start?** The
[`good first issue`](https://github.com/luiacuaniello/perspectivegraph/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
label marks work that is scoped, self-contained and does not need any prior knowledge of
the engine — each one says what "done" looks like. For anything on the
[roadmap](ROADMAP.md), open an issue first so we can agree on the shape before you write
code.

## Layout

```
backend/                 Go backend (CGO_ENABLED=0 → static binary, pure-Go resolver)
  cmd/perspectivegraph/  entry point; wires every layer. Also the `healthz` and
                         `verify-audit <file>` subcommands.
  internal/
    ingestion/           webhook server + collectors: trivy, semgrep, custodian,
                         falco, build, supplychain, k8s, cloudnet, iam, sso
    broker/              NATS JetStream wrapper (stream/consumer, dead-letter, backoff)
    normalization/       identity resolution (join confidence) → graph upsert
    graph/               Store interface + memory & Apache AGE backends + per-tenant Manager
    analyzer/            path traversal, scoring, Monte Carlo risk, k-shortest, what-if,
                         history/MTTR, TTL pruning, leader-gated side effects
    policy/              architectural invariants (forbidden graph shapes)
    attck/               MITRE ATT&CK technique mapping per edge type
    remediation/         K8s NetworkPolicy / Terraform generation (rule + hint registries)
    detection/           Falco + Sigma detection-as-code generation
    compliance/          NIST OSCAL assessment-results export
    action/              GitHub/GitLab PR/MR commenters (shared base)
    notify/              drift-alert webhook (Slack/generic)
    threatintel/         CISA KEV + FIRST EPSS enrichment
    search/              optional OpenSearch full-text index
    api/                 GraphQL BFF + REST (suppress/ticket/validation/export), CORS
    auth/                ingest HMAC, bearer tokens (hash/expiry/app-scope), OIDC/JWT, RBAC
    audit/               tamper-evident hash-chained audit log
    cryptostore/         AES-256-GCM at-rest encryption for the stores + audit log
    exportsign/          Ed25519 detached signatures for OSCAL/SIEM exports
    secwatch/            sliding-window detector (auth lockout + exfiltration alerts)
    suppress/ ticket/    file-backed governance stores (triage, ticketing,
    validation/ history/   red-team verdicts, posture/MTTR trend)
    ratelimit/ metrics/  per-IP token bucket; Prometheus metrics
    httpx/ leader/       shared JSON-HTTP client; Postgres advisory-lock leader election
    config/              env-based config (12-factor)
  pkg/ontology/          shared node/edge vocabulary + Event envelope
  testdata/              sample scanner output for `make seed` (+ Go fuzz corpus)
frontend/                React + Vite + Tailwind + Cytoscape dashboard
                         (light/dark theming via CSS vars; inline SVG icon set, no emoji)
deploy/postgres/         Postgres+AGE init SQL
deploy/helm/perspectivegraph/  Helm chart (auth / persistence / export-signing knobs)
```

## Dev loop

```bash
make up              # Postgres+AGE + NATS via docker compose
make run-backend     # Go backend (falls back to in-memory graph if no Postgres)
make run-frontend    # Vite dev server on :5173
make seed            # feed sample data → ranked attack paths appear
make seed-discovery  # K8s + cloud-network + IAM + SSO topology (auto-discovered)
make test            # Go tests (CGO disabled for static, portable binaries)
```

> The backend builds with `CGO_ENABLED=0` (see the Makefile) for static binaries
> and Go's pure-Go resolver. Keep new dependencies pure-Go so this holds.

### Checks CI runs - run them locally before a PR

```bash
# Backend (go1.26): build, vet, tests, dependency vulns, and SAST
cd backend
GOTOOLCHAIN=go1.26.7 CGO_ENABLED=0 go build ./... && go vet ./... && go test ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude=G104,G404,G401,G505,G304 ./...

# Frontend: types, build, unit tests
cd ../frontend && npx tsc --noEmit && npm run build && npm test
```

CI also runs **gitleaks** (secret scan), `npm audit`, a Trivy image scan, and an
AGE-store + leader-election integration job against a real Postgres.

## Adding a new collector

This is the most common contribution. The `trivy` and `semgrep` packages are
worked examples. To add, say, a Checkov (IaC) collector:

1. Create `backend/internal/ingestion/checkov/checkov.go`.
2. Implement the `ingestion.Collector` interface: `Source() string` and
   `Parse(io.Reader, ingestion.Options) ([]ontology.Event, error)`. Use
   `Options.Repository`/`RepoSlug` when the tool's output doesn't self-identify the asset.
3. Map the tool's findings onto the **ontology** (`pkg/ontology`) - reuse
   existing node labels and edge types; propose new ones in a PR if needed
   (e.g. Semgrep added `Weakness`). Keep edges oriented in the direction of
   attack progression. If the hop is an adversary action, add its MITRE ATT&CK
   mapping in `internal/attck`.
4. Register it in `cmd/perspectivegraph/main.go` alongside the others:
   `ingestion.NewServer(bus, trivy.New(), semgrep.New(), …, checkov.New())`.
5. Add a sample report under `testdata/`, a **table test**, and a **`FuzzParse`**:
   a parser eats untrusted webhook bytes, so it must never panic and never emit a
   malformed node/edge (see `internal/ingestion/trivy/trivy_test.go`).

Collectors must produce **stable node IDs** (`ontology.NewID`) so the graph
deduplicates instead of creating parallel nodes. That is what lets findings from
different tools correlate onto the same asset.

## How this project is written

PerspectiveGraph is developed by a human working with Claude (Anthropic). Design
decisions, the threat model and what ships are the maintainer's; a large share of
the implementation and its tests were written in that collaboration.

That is stated here for the same reason the engine reports its own calibration:
you should not have to take a claim on trust when it can be checked. Every gate is
reproducible on your machine, and they are what the project actually asks to be
judged on:

```bash
make test              # backend + frontend suites
make bench-cloudgoat   # precision/recall against known-vulnerable scenarios
cd backend && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd backend && go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet -exclude=G104 ./...
```

Contributions written the same way are welcome; hold them to the same gates.

## Signing your work

Every commit must carry a `Signed-off-by:` line. It is the
[Developer Certificate of Origin](DCO) - the full text is in this repository, so what you
are certifying is not behind a link - and it says, in short, that you wrote the change or
otherwise have the right to submit it under this project's licence.

```bash
git commit -s -m "fix: ..."     # appends the line using your git user.name / user.email
```

A DCO rather than a CLA on purpose: a CLA is a document somebody's legal team has to
approve before a first contribution, which is where most drive-by fixes die. A DCO is a
statement you make in the commit, with nothing to sign and nobody to email.

CI checks it on every pull request. If you forgot, repair the branch rather than adding a
new commit on top:

```bash
git rebase --signoff origin/main
git push --force-with-lease
```

Bot commits are exempt: Dependabot signs its own, and release-please's release commits
carry no human authorship to certify - failing every release on a certification nobody is
making would be theatre rather than provenance.

## Dependency licences

CI fails on a dependency whose licence is outside a permissive allowlist (Apache-2.0, MIT,
BSD-2-Clause, BSD-3-Clause, ISC) - for Go and for the frontend's production dependencies
alike. This project ships binaries and images under Apache-2.0, so what it redistributes
has to be checkable rather than assumed, and a transitive copyleft dependency normally
arrives in a routine bump rather than in a reviewed decision.

Anything outside that list stops the build so a human decides. If your change needs such a
dependency, say why in the pull request rather than widening the list quietly.

## Conventions

- **Go:** `gofmt`, `go vet`, **`gosec`** clean. Justify an unavoidable gosec
  finding inline with `// #nosec Gxxx -- why it's safe`, never a blanket exclude.
  Tests (and a fuzz test for parsers) for new logic. New deps must be pure-Go.
- **Frontend:** must pass `tsc`, `build`, and `vitest`. Use the inline SVG icon
  set (`components/icons.tsx`) - **no emoji in the UI**; colors come from the
  CSS-variable design tokens (so light/dark both work), not hardcoded hex.
- **Running the stack while you work:** `make demo` runs the *published* images, so it
  will not show your changes. Use **`make demo-build`** (or `make up-full`), which builds
  the backend and dashboard from your working tree.
- **Frontend dependencies:** install with `npm ci` (`make install-frontend`), and to
  add or update one, edit `package.json` and run **`make lockfile`** - never a bare
  `npm install`. CI and the release image both use `npm ci`, so the build is
  reproducible and the SBOM and SLSA provenance describe what is actually shipped.
  `make lockfile` regenerates the lockfile inside the same Linux image the release
  build uses, because npm records the transitive dependencies of optional
  platform-specific packages only for the platform it runs on: regenerating on macOS
  silently drops entries the Linux build needs, and `npm ci` then fails in CI.
- **Node is pinned, and npm comes with it.** CI pins an exact `node-version`, and the
  release Dockerfile and `make lockfile` pin the same image by digest - Node 24.20.0,
  which ships npm 11.19.0. Nothing installs npm over it: `npm install -g npm@x` pins a
  version but fetches it unauthenticated, which is a supply-chain regression (OpenSSF
  Scorecard reports it as an unpinned dependency) where the image digest is a
  cryptographic pin. A Go test fails if any of those surfaces drifts, or if a global npm
  install comes back. `engines.npm` records what that Node ships, so if your own npm
  differs you get an `EBADENGINE` warning - the intended signal.
- **Docs + Postman:** every user-facing feature updates the docs and
  `.env.example` **and** the Postman collection
  (`docs/perspectivegraph.postman_collection.json`). `README.md` is the landing
  page - keep it short; the depth (architecture, scoring, deploy, onboarding
  runbook) lives in [`docs/MANUAL.md`](docs/MANUAL.md).
- **Security:** this tool is a map of how to attack the org, so don't weaken its
  own controls (ingest HMAC, API auth/RBAC, audit log, at-rest encryption,
  export signing). Never commit secrets - the gitleaks gate enforces it. Found a
  vulnerability? Report it privately - see [SECURITY.md](SECURITY.md), not a public
  issue or PR.
- **Commits & releases:** [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `docs:`, `chore:`, …) - they drive the automated CHANGELOG and
  versioning (release-please). One fact per message line; explain the *why*.
  Enable the bundled git hooks once so a bad commit message or a stray secret is
  caught before it leaves your machine:

  ```bash
  git config core.hooksPath .githooks   # commit-msg (conventional) + pre-push (gitleaks)
  ```
```
