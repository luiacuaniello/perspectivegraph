# Contributing to AegisGraph

Thanks for your interest! AegisGraph is Apache-2.0 and built to be extended.

## Layout

```
backend/                 Go backend
  cmd/aegisgraph/        entry point, wires the layers together
  internal/
    ingestion/           collectors (trivy, semgrep, custodian, falco) + webhook
    broker/              NATS JetStream wrapper
    normalization/       identity resolution → graph upsert
    graph/               Store interface + memory & Apache AGE backends
    analyzer/            attack-path traversal, scoring & runtime confirmation
    policy/              architectural invariants (forbidden graph shapes)
    action/              GitHub/GitLab PR/MR commenters (shared base)
    remediation/         K8s NetworkPolicy / Terraform generation
    search/              optional OpenSearch full-text index
    api/                 GraphQL BFF
    config/              env-based config
  pkg/ontology/          shared node/edge vocabulary + Event envelope
  testdata/              sample scanner output for `make seed`
frontend/                React + Vite + Tailwind + Cytoscape dashboard
deploy/postgres/         Postgres+AGE init SQL
deploy/helm/aegisgraph/  Helm chart for cluster deploy
```

## Dev loop

```bash
make up              # Postgres+AGE + NATS via docker compose
make run-backend     # Go backend (falls back to in-memory graph if no Postgres)
make run-frontend    # Vite dev server on :5173
make seed            # feed sample data → an attack path appears
make test            # Go tests (CGO disabled for static, portable binaries)
```

> The backend builds with `CGO_ENABLED=0` (see the Makefile) for static binaries
> and Go's pure-Go resolver. Keep new dependencies pure-Go so this holds.

## Adding a new collector

This is the most common contribution. The `trivy` and `semgrep` packages are
worked examples. To add, say, a Checkov (IaC) collector:

1. Create `backend/internal/ingestion/checkov/checkov.go`.
2. Implement the `ingestion.Collector` interface: `Source() string` and
   `Parse(io.Reader, ingestion.Options) ([]ontology.Event, error)`. Use
   `Options.Repository` when the tool's output doesn't self-identify the asset.
3. Map the tool's findings onto the **ontology** (`pkg/ontology`) — reuse
   existing node labels and edge types; propose new ones in a PR if needed
   (e.g. Semgrep added `Weakness`).
4. Register it in `cmd/aegisgraph/main.go`:
   `ingestion.NewServer(bus, trivy.New(), semgrep.New(), checkov.New())`.
5. Add a sample report under `testdata/` and a golden test.

Collectors must produce **stable node IDs** (`ontology.NewID`) so the graph
deduplicates instead of creating parallel nodes. That is what lets findings from
different tools correlate onto the same asset.

## Conventions

- `gofmt` / `go vet` clean; tests for new logic.
- Keep edges oriented in the direction of attack progression (see the note in
  `internal/ingestion/trivy/trivy.go`).
- One fact per commit message line; explain the *why*.
