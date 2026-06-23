# Contributing to PerspectiveGraph

Thanks for your interest! PerspectiveGraph is Apache-2.0 and built to be extended.

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
# Backend (go1.25): build, vet, tests, dependency vulns, and SAST
cd backend
GOTOOLCHAIN=go1.25.11 CGO_ENABLED=0 go build ./... && go vet ./... && go test ./...
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

## Conventions

- **Go:** `gofmt`, `go vet`, **`gosec`** clean. Justify an unavoidable gosec
  finding inline with `// #nosec Gxxx -- why it's safe`, never a blanket exclude.
  Tests (and a fuzz test for parsers) for new logic. New deps must be pure-Go.
- **Frontend:** must pass `tsc`, `build`, and `vitest`. Use the inline SVG icon
  set (`components/icons.tsx`) - **no emoji in the UI**; colors come from the
  CSS-variable design tokens (so light/dark both work), not hardcoded hex.
- **Docs + Postman:** every user-facing feature updates the relevant `.md`
  (`README.md`, `ARCHITECTURE.md`, `docs/GUIDA.md` / `docs/ONBOARDING.md`,
  `.env.example`) **and** the Postman collection
  (`docs/perspectivegraph.postman_collection.json`).
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
