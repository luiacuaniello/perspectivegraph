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
| B1 API | I/E | Unauthenticated read of attack paths / tenant data | GraphQL requires a bearer credential (≥ viewer); OIDC Authorization-Code + PKCE login gate; JWKS with key-rotation refetch; brute-force lockout | Auth is **opt-in**; a demo left public exposes A1 |
| B7 tenants | I/E | One tenant reading another's graph | Tenant stamped from the authenticated principal; isolation covered by tests | Depends on auth being enabled; verify per deployment |
| B6 store/bus | I/T | Read/modify the graph or events directly | Network isolation; TLS to Postgres (`POSTGRES_SSLMODE`) and in-app TLS are configurable | TLS + at-rest encryption are the operator's job (use a managed DB); demo runs plaintext local |
| B3 connectors | E | Over-broad cloud credentials pivoted from the engine | Read-only model, AssumeRole, least-privilege grant (`ec2:Describe*`, `iam:GetAccountAuthorizationDetails` ≈ SecurityAudit) | An operator can still attach an over-broad role - document and review the grant |
| B4 LLM | I | Topology context sent to a third-party LLM | AI is self-gated on an API key (off by default); every call audited; secrets scrubbed on ingest | When enabled, attack-path context leaves your boundary. Opt-in and operator-owned |
| B5 GitHub | E/T | Misuse of the write-scoped token to push to repos | Single purpose (branch+commit+PR); token supplied by operator | Token has write scope - store it in a secret manager, scope to the target repo |
| ingest | I | Secrets embedded in scanned artifacts land in the graph | Secret scrubbing on ingest | Best-effort; do not rely on it as the only control |
| B4 AI | T | Prompt injection via ingested content steering the AI summary | AI answers are grounded on the live path set, every call audited | Ingested text is untrusted; treat AI output as advisory, not authoritative |
| B1/B2 | D | Denial of service via large or frequent payloads | Ingest body-size limit; connectors leader-gated (replicas don't multiply calls) | No API-level rate limiting yet - put the engine behind a gateway/WAF in prod |
| the tool itself | T | Supply-chain compromise of the build | Digest-pinned base images (distroless, non-root, read-only rootfs), SHA-pinned GitHub Actions, `govulncheck`/`gosec`/`gitleaks`/Trivy gates in CI, Dependabot | SBOM + image signing (cosign) + SLSA provenance are planned, not yet shipped |
| B1 | R | Actions not attributable | Tamper-evident audit log (sealed); `auth.deny` and mutating actions recorded | Strong non-repudiation needs shipping the log to external WORM storage |

## Data handling and privacy

- The graph in A1 is **sensitive**: it describes how a real environment can be attacked.
  Treat the datastore as you would a secrets store.
- Retention: nodes/edges support TTL pruning; audit and validation stores are
  append-only (validation can be in-memory or persisted via `VALIDATIONS_PATH`).
- Egress: with the AI features enabled, attack-path context is sent to the configured
  LLM provider. This is opt-in; if your policy forbids sending topology to a third party,
  leave `ANTHROPIC_API_KEY` / the HF endpoint unset.

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
any threat that assumes an already-compromised operator or CI system. The engine has not
yet undergone a formal third-party penetration test (see the maturity note).

## Reporting a vulnerability

Please use the process in [SECURITY.md](../SECURITY.md) (GitHub Private Vulnerability
Reporting). Do not open a public issue for a security report.
