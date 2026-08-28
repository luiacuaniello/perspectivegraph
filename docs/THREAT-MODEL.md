# Threat model

This document states what PerspectiveGraph protects, what it assumes, and how the
main threats are mitigated. It is written for operators deciding whether and how to
deploy the engine, and for security researchers reviewing it.

Method: enumerate the trust boundaries and assets, then walk each attack surface with
STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege), recording the existing control and the residual risk.

> Honesty note: the bundled `docker compose` / Helm defaults are **demo-grade**. Several
> controls below (HMAC on ingest, auth on the API, TLS, encryption at rest) are opt-in
> and off in the demo. A production deployment must turn them on - see the "Operator
> assumptions" section and [Project status & maturity](../README.md#project-status--maturity).

## System overview and trust boundaries

```
            (untrusted)                          (semi-trusted, outbound)
Internet ─► Dashboard :3000 ─► API :8080 ─┬─► Postgres + Apache AGE   (B6 store)
                (nginx SPA)   (GraphQL,    ├─► NATS bus               (B6 bus)
                              auth gate)   ├─► Cloud accounts (AWS/Azure, read-only)  (B3)
Scanners/CI ─► Ingest :8081 ──────────────┼─► External LLM (Claude / HF)             (B4)
             (HMAC per tenant)            └─► GitHub (open remediation PRs, write)    (B5)
```

- **B1 - Internet ↔ dashboard/API.** Untrusted clients reach the SPA and the GraphQL API.
- **B2 - Ingest.** Scanners and CI push findings/topology to `/ingest/*`.
- **B3 - Connectors → customer cloud.** Agentless pull with read-only credentials.
- **B4 - Engine → external LLM.** Optional AI features send attack-path context out.
- **B5 - Engine → GitHub.** Remediation-as-PR uses a token with write scope.
- **B6 - Engine ↔ datastore/bus.** Graph in Postgres+AGE; events on NATS.
- **B7 - Tenant ↔ tenant.** Multi-tenant graphs must stay isolated.
- **B8 - CI runner (the merge gate).** In `mode: local` the gate runs the engine *inside
  the runner*: it reads the estate with a cloud read-only credential and computes the
  verdict there, so B3 moves into a job that also builds and tests the pull request's own
  code. Anything that PR can execute during the build can read that credential. Keep the
  gate in a job of its own with minimal `permissions:`, and never on `pull_request_target`
  - that event hands your secrets to a contributor's code. Fork PRs get no secrets at all
  and correctly fail closed as UNKNOWN.

## Assets to protect

| # | Asset | Why it matters |
|---|-------|----------------|
| A1 | The topology graph (assets, identities, IAM/RBAC, CVEs, attack paths) | It is a map of the customer's attack surface and privilege - high value to an attacker |
| A2 | Credentials the engine holds (cloud read-only role, GitHub token, LLM API key, OIDC/JWKS, per-tenant HMAC secrets, DB DSN) | Their compromise pivots into other systems |
| A3 | Audit log integrity | Detection and non-repudiation depend on it |
| A4 | Integrity of the PR merge-gate verdict | A forced-green gate would let a real attack path merge |

## Threats and mitigations

| Surface | STRIDE | Threat | Control today | Residual risk |
|---|---|---|---|---|
| B2 ingest | S/T | Forge scanner data to poison the graph or hide a path | Per-tenant HMAC verifier, body-size cap, audit on deny | HMAC is **opt-in**; off in the demo. Enable it in prod |
| B3 connectors | T | **Crown-jewel promotion.** What makes a target worth attacking is usually a tag, and `ec2:CreateTags` is granted freely because tagging looks harmless - so an attacker with a foothold can mark junk `classification: pii` and manufacture paths that dilute a board whose promise is "~5 routes that matter" | The analyzer ranks crown-jewel *provenance*: an authoritative classifier (Macie/DLP) outranks a tag outranks a name heuristic, and ingestion now records `crown_jewel_basis: tagged` so that ranking actually sees the attacker-writable case. The weight and its reason both surface in the path's priority factors, so an operator reads "tagged sensitive asset" rather than an unexplained number | Ordering bounds the damage but does not remove it: fabricated jewels still inflate path *counts* and compete for attention below the top slot. An estate that classifies with a real tool is materially harder to poison than one that relies on tags alone |
| B3 connectors | T | **Crown-jewel demotion** - remove the tag so a real target stops being one and its path leaves the board | Not possible today: the property is only ever written `true`, and the store's merge contract accumulates (`MergeProps`, later writes win *per key*, nothing is deleted), so a jewel survives the tag being removed | The same contract makes promotion **irreversible**: an attacker needs tagging rights for one collection cycle, and the fabricated jewel then persists with no operator action that removes it. Legitimate declassification is equally stuck. Fixing it means changing the store's merge contract - which exists to stop a partial collector erasing another's data - so it is a deliberate separate change, not a bolt-on |
| B1 API | I/E | Unauthenticated read of attack paths / tenant data | GraphQL requires a bearer credential (≥ viewer); OIDC Authorization-Code + PKCE login gate; JWKS with key-rotation refetch; brute-force lockout. When `OIDC_JWKS_URL` is set the binary **refuses to start** without `OIDC_ISSUER` and `OIDC_AUDIENCE`: a verifier that skips `aud` accepts any token its IdP ever minted, including one issued to a different application sharing the same JWKS | Auth is **opt-in**; a demo left public exposes A1. The brute-force lockout is **durable with `GOVERNANCE_BACKEND=postgres`** - a lockout already earned survives a restart, a deploy or an OOM, and every replica enforces it - but only the LOCKOUT is stored, not the counter behind it, so partial progress toward the threshold is still forgiven by a restart (a write per failed login would let the abuse drive the writes). On the file backend it remains per-process and per-replica. A lockout set by another replica is seen within 30s, since the request path reads a cached snapshot rather than the database. Its key space is capped (50k) so a flood evicts the oldest rather than growing without bound - which also means a large enough flood can push a real attacker's counter out. None of this is a substitute for lockout at the IdP |
| B7 tenants | I/E | One tenant reading another's graph | Tenant stamped from the authenticated principal; isolation covered by tests | Depends on auth being enabled; verify per deployment |
| B6 store/bus | I/T | Read/modify the graph or events directly | Network isolation; TLS to Postgres (`POSTGRES_SSLMODE`) and in-app TLS are configurable | TLS + at-rest encryption are the operator's job (use a managed DB); demo runs plaintext local |
| B3 connectors | E | Over-broad cloud credentials pivoted from the engine | Read-only model, AssumeRole, least-privilege grant (`ec2:Describe*`, `iam:GetAccountAuthorizationDetails` ≈ SecurityAudit) | An operator can still attach an over-broad role - document and review the grant |
| B4 LLM | I | Topology context sent to a third-party LLM | AI is self-gated on an API key (off by default); every call audited; secrets scrubbed on ingest | When enabled, attack-path context leaves your boundary. Opt-in and operator-owned |
| B5 GitHub | E/T | Misuse of the write-scoped token to push to repos | Single purpose (branch+commit+PR); token supplied by operator | Token has write scope - store it in a secret manager, scope to the target repo |
| ingest | I | Secrets embedded in scanned artifacts land in the graph | Secret scrubbing on ingest | Best-effort; do not rely on it as the only control |
| B4 AI | T | Prompt injection via ingested content steering the AI summary. An asset's name is an AWS `Name` tag and `ec2:CreateTags` is widely granted, so the attacker this tool exists to detect can write text into the prompt that produces the executive briefing | Environment-derived strings are collapsed to a single bounded line (no line breaks, control characters stripped, length capped, fence tags neutralised), the context arrives inside `<environment-data>` tags, and every system prompt tells the model that block is data and never instructions. Applied on **both** routes - the summary's path context and `/ai/explain`'s remediation hints, which embed asset names in prose. The hostile inputs are a permanent test (`internal/api/injection_test.go`), which failed before the containment existed | **Containment, not elimination.** No escaping makes a model immune to persuasive text - a name reading "decommissioned" may still colour an answer. What is removed is the ability to forge *structure* (a forged turn, a fake list entry, an early fence close) and to spend the context window on one tag. Treat AI output as advisory, not authoritative |
| B1/B2 | D | Denial of service via large or frequent payloads | Body-size limits on ingest and API; per-client-IP token buckets on both (`API_RATE_RPS`, `INGEST_RATE_RPS`, default 60/30) with the limiter as the outermost middleware and a capped client table; connectors leader-gated (replicas don't multiply calls) | The limiter keys on the connecting peer, so behind a proxy it limits the proxy: terminate at a gateway that limits per real client. State is in-memory and per-replica |
| B1 API | D | **A cheap request that costs the server a lot.** Depth limits alone do not bound work: a document three levels deep can alias one expensive field thousands of times, and fragments that each spread the next twice expand exponentially with no cycle for a cycle guard to catch | The query guard budgets both **depth** (15) and total **field resolutions** (2000, ~5× the dashboard's heaviest query), and fragment costs are memoised so measuring a document is linear in its size. Regression-tested: a 1.2 KB non-cyclic fragment bomb that previously took the guard **over ten seconds to measure** - before any field resolved - is now rejected in microseconds | The budget is static, not per-resolver cost-aware: 2000 cheap fields and 2000 expensive ones are charged the same. Resolvers read a cached analysis rather than recomputing, which is what keeps that acceptable |
| the tool itself | T | Supply-chain compromise of the build | Digest-pinned base images (distroless, non-root, read-only rootfs), SHA-pinned GitHub Actions, `govulncheck`/`gosec`/CodeQL/`gitleaks`/Trivy gates + parser fuzzing in CI, Dependabot; release images are cosign-signed with an SBOM + SLSA provenance | No formal third-party penetration test yet (automated + community review only) |
| B1 | R | Actions not attributable | Tamper-evident audit log (sealed); `auth.deny` and mutating actions recorded | Strong non-repudiation needs shipping the log to external WORM storage. Every request carries an `X-Request-Id` - taken from the caller when well-formed, generated otherwise - that reaches the structured logs and the audit record's fields alike, so one HTTP call ties to its audit entry without guesswork |
| B1 metrics | I | **`GET /metrics` is open by design** - unauthenticated and unthrottled, so a scrape never starves - but it sits on the same mux and port as the API, and several series carry a `tenant` label: `analyzer_critical_paths`, `analyzer_graph_nodes`, `analyzer_graph_edges`. Anyone who can reach the port therefore enumerates tenant names and learns how large each estate is and how many critical paths it currently has | Path contents, asset names and scores are never exposed - only counts and timings | **Closable**: set `METRICS_ADDR` (e.g. `127.0.0.1:9090`) and /metrics moves to its own listener and LEAVES the API mux entirely - `values-production.yaml` does this. It is off by default because /metrics on the API port is declared stable surface and moving it silently would break every existing scrape config. Left on the API port the residual stands: "which tenants exist, and which has the worst posture right now" is the shape of a targeting signal, so do not expose that port directly |

## Data handling and privacy

The graph in A1 is **sensitive**: it describes how a real environment can be attacked, so
treat the datastore as you would a secrets store. It also contains personal data, and the
AI features send some of it outside your boundary when enabled - both are covered in
detail in the next section, along with retention and the transfer question.

## Personal data and compliance (GDPR / NIS2)

This tool processes personal data. Saying so plainly, and saying exactly which, is
cheaper for everyone than letting a data protection officer discover it during review.

**You are the controller.** The project ships software; the deployment that ingests your
estate decides the purposes and means, and is therefore the controller under GDPR Art. 4.
Nothing is sent to the maintainers - there is no telemetry, no phone-home, no hosted
component.

### What personal data the system holds, and where

| Where | What | Kind |
|---|---|---|
| **Graph** (Postgres/AGE or memory) | IAM user names from the `iam` collector; **email addresses** from the `sso` collector (`{"email":"alice@acme.com"}`); whatever names your estate puts in asset tags | **Directly identifying** |
| **Audit log** | The acting subject per request: `anonymous`, `hmac`, `token:<8-hex SHA-256 fingerprint>` or `jwt:<sub>` (the OIDC subject claim, an opaque identifier) | **Pseudonymous** |
| **Application log** | The same subjects, plus remote IP on `auth.deny` / lockout alerts | Pseudonymous + IP |

The audit log is pseudonymous **by design**: it never records a bearer token, an email or
a user name - only a truncated hash or the IdP's opaque subject. That is the Art. 32
measure it looks like, and it is deliberate. It remains personal data under Recital 26,
but the exposure if the file leaks is materially smaller than the graph's.

The graph is the sensitive artefact, and it holds directly identifying data.

### Lawful basis

Legitimate interest (Art. 6(1)(f)) is the basis that fits, and GDPR **Recital 49 names
network and information security explicitly** as such an interest, including preventing
unauthorised access. Document that assessment; do not leave it to be inferred. If your
organisation treats security tooling under a different basis, nothing here depends on the
choice.

### Retention, and one honest tension

- **Graph**: bounded. `GRAPH_TTL` prunes nodes and edges not re-observed within the
  window, so an identity that leaves your estate leaves the graph.
- **Audit log**: bounded **when you set a window**, and unbounded until you do. On the
  Postgres-backed chain, `AUDIT_RETENTION` prunes records older than the window. On the
  file-backed chain there is no automatic pruning: rotate it (see the
  [operations runbook](OPERATIONS.md#retention-and-rotation)).

The tension worth naming rather than hiding: the audit log is **hash-chained** so that
tampering is detectable, which means **deleting a record from the middle breaks every hash
after it**. Erasure (Art. 17) and tamper-evidence pull in opposite directions.

The answer is truncation, not surgery. Retention removes a **prefix** - the oldest records,
in the order they arrived - and writes a checkpoint holding the sequence number and hash of
the last record it removed. Verification then starts at the first surviving record and
checks that it still links to that hash, so the retained window is exactly as tamper-evident
as the whole chain was. Deleting one record out of the middle remains impossible to do
invisibly, which is the property the chain exists for; the prune itself is recorded in the
chain it shortened. The file-backed chain does the same thing at file granularity: retire
whole files and archive or destroy them intact. Both of which are also why the subjects are
pseudonymous in the first place - there is far less to erase.

### Transfers outside the EEA

**With the AI features enabled, personal data leaves your boundary.** The attack-path
context sent to Anthropic or a HuggingFace-compatible endpoint includes asset names, and
asset names in a real estate routinely carry user names and email addresses. That is a
Chapter V transfer, not merely an architectural preference, and it needs the usual
paperwork (adequacy, SCCs, or a provider inside the EEA).

It is **off by default** and every call is audited (`ai.query` / `ai.summary` /
`ai.explain`). Leave `ANTHROPIC_API_KEY` and the HF endpoint unset and no data leaves.
The HuggingFace path accepts any OpenAI-compatible endpoint, so an EEA-hosted or
self-hosted model keeps the transfer inside your boundary while keeping the feature.

### Data subject requests

- **Access / rectification**: identities live in the graph as nodes; query by name through
  the API and correct them at the source (the graph is derived, so fixing IAM or the IdP
  and letting the next pass re-ingest is the durable fix).
- **Erasure**: remove the identity at the source and let `GRAPH_TTL` prune it, rather than
  editing the graph by hand. For the audit log, see the rotation note above.

### NIS2

For entities in scope (in Italy, D.Lgs. 138/2024), several obligations map onto artefacts
this tool already produces. It does **not** make you compliant - no tool does - but these
are things you would otherwise have to build:

- **Tamper-evident logging of access to security data** - the hash-chained audit log,
  verifiable with `perspectivegraph verify-audit`.
- **Supply-chain security of the tooling itself** - release images and binaries are
  cosign-signed, carry an SPDX SBOM and SLSA build provenance, and can be verified before
  they run.
- **Vulnerability handling and disclosure** - see [SECURITY.md](../SECURITY.md).
- **Risk-management evidence** - the OSCAL assessment-results export (`GET /export/oscal`)
  renders posture in a format an assessor can consume.

## Operator assumptions (what you must do for production)

1. Enable auth on the API (OIDC) and HMAC on ingest.
2. Enable TLS (in-app or at the ingress) and use an external, managed, encrypted
   PostgreSQL+AGE - not the bundled demo database image.
3. Store A2 credentials in a secret manager, not environment variables in plaintext.
4. Grant connectors the minimum read-only role; review the policy.
5. Put the engine behind a gateway/WAF; apply network policy between components.
6. Rotate the GitHub token and LLM key; scope the GitHub token to the target repo.

## Out of scope

Host/OS/hypervisor security; the security of the Kubernetes platform the engine runs on;
physical access; the correctness of the third-party scanners whose output is ingested; and
any threat that assumes an already-compromised operator or CI system. Security review to
date is automated + community-based (CodeQL taint analysis, `gosec`, `govulncheck`, Trivy,
and fuzzing of the ingest parse boundary in CI, plus GitHub Private Vulnerability
Reporting); the engine has **not** yet undergone a formal third-party penetration test (see
the maturity note).

## Reporting a vulnerability

Please use the process in [SECURITY.md](../SECURITY.md) (GitHub Private Vulnerability
Reporting). Do not open a public issue for a security report.
