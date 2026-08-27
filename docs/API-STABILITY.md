# API stability and compatibility

PerspectiveGraph follows [Semantic Versioning](https://semver.org). This document
declares the **stable public surface** and the compatibility rules that govern it, so you
can build on it and know what a version bump means.

> **As of 1.0 these rules are in force.** The surface below will not break without a
> **major** bump, and every change is called out in the [CHANGELOG](../CHANGELOG.md).
> The GraphQL schema was already held to them before 1.0 - it is machine-guarded, see
> "Enforcement" - so this is a promise the tests have been keeping for some time, not one
> made on the day.
>
> 1.0 is a statement about the **interface**, not about the model's accuracy. The engine's
> probabilities have still not been calibrated against field outcomes (the
> [README](../README.md) says so up front, and the reliability panel withholds a verdict
> until real outcomes exist). A stable API and an unvalidated model are different claims,
> and only the first is being made here.

## The stable surface

1. **GraphQL query API** (`POST /graphql`). The contract is frozen in
   [`docs/api/schema.graphql`](api/schema.graphql). Adding a type, a field, or an
   *optional* argument is backward-compatible (**minor**). Removing or renaming a field,
   removing an enum value, making an argument required, or narrowing a return type is
   **breaking** (**major**).
2. **Ingest event contract.** The JSON accepted by `POST /ingest/events` - the
   `ontology.Event` / `Node` / `Edge` shape - and the scanner endpoints
   `POST /ingest/<source>` (trivy, semgrep, custodian, falco, k8s, cloudnet, iam, sso,
   build, supplychain, dataclass). New *optional* fields are minor; removing or renaming a
   field, or changing its meaning, is breaking.
3. **Operational endpoints.** `GET /healthz`, `GET /metrics` (the `perspectivegraph_*`
   metric names), and `GET /auth/config` (the fields the dashboard login gate reads).
4. **Configuration.** The environment-variable **names and semantics** documented in
   [`.env.example`](../.env.example). A new opt-in knob with a safe default is minor;
   renaming or removing a variable, or changing a default in a way that alters behavior, is
   breaking.
5. **CLI.** The documented subcommands and their core flags: `healthz`, `verify-audit`
   (`<file>` or `-postgres`), `ingestreal`, `importverdicts`, `awscollect`, `genload`,
   `genverdicts`.

## Not covered (may change without a major bump)

- **Anything marked experimental** in the schema or the docs.
- **The Go packages under `internal/`** - implementation detail, not an importable API. No
  source-compatibility guarantee for code that imports them.
- **Exact scores, orderings, and AI-generated wording.** The numbers move as the models and
  calibration improve; the *shape* of the response is what is stable, not the values.
- **Log lines, the demo seed data, Helm chart internals, and metric label cardinality.**

## Deprecation policy

Before a stable field, endpoint, flag, or variable is removed:

1. it is marked deprecated - GraphQL fields with `@deprecated`, everything else with a note
   in the docs and the CHANGELOG;
2. it keeps working for **at least one minor release**;
3. it is removed only in a **major** version bump.

Deprecations and removals are always listed in the [CHANGELOG](../CHANGELOG.md).

## Enforcement

The GraphQL schema is the one part of the contract that is **machine-guarded today**:
`docs/api/schema.graphql` is a snapshot, and `TestGraphQLSchemaSnapshot`
(`backend/internal/api`) re-renders the live schema and fails CI on any drift. A contract
change is therefore always a deliberate, reviewed act - regenerate the snapshot on purpose
with:

```bash
cd backend && UPDATE_SCHEMA=1 go test ./internal/api -run TestGraphQLSchemaSnapshot
```

Review the resulting diff: an additive change is fine on a minor bump; a removal, rename, or
narrowing is breaking and waits for a major.

The other stable surfaces (event contract, endpoints, config, CLI) are governed by this
policy and by code review; extending the machine guard to them is tracked as follow-up work.

## Raising a compatibility concern

If a release breaks something you depended on that this document calls stable, please open
an issue - that is a bug, not an expected change.
