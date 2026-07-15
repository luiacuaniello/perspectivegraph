# Security Policy

PerspectiveGraph is a DevSecOps tool whose own data - a graph of *how to attack the
org* and a record of who has viewed it - is sensitive. We take the security of the
tool itself seriously and welcome coordinated disclosure of vulnerabilities.

## Supported versions

PerspectiveGraph is pre-1.0 and ships from `main`. Security fixes are applied to
the latest released version and to `main`; there are no long-term support branches
yet. Always run the latest tagged release (or `main`) to receive fixes.

| Version | Supported |
|---------|-----------|
| latest release / `main` | ✅ |
| older tags | ❌ (please upgrade) |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
problem** - that discloses it before a fix exists.

Report privately via one of:

1. **GitHub private vulnerability reporting** (preferred): on the repository, go to
   **Security → Report a vulnerability** (GitHub Security Advisories). This keeps the
   report private to the maintainers until a fix is published.
2. If private reporting is unavailable, open a **minimal** public issue that says only
   *"security report - please provide a private contact"* (no details), and a
   maintainer will reach out.

Please include, where you can:

- a description of the issue and its security impact;
- the affected component (backend service, GraphQL/REST API, auth/HMAC, the AGE
  Cypher layer, governance stores / audit log / at-rest encryption, export signing,
  the frontend, the Helm chart, or the action layer);
- a minimal proof-of-concept or the exact request(s) to reproduce;
- the version / commit and how the instance was configured.

**Do not** run tests against systems you don't own, exfiltrate data, or degrade a
service while investigating. Use a local instance (`make up-full`) for any PoC.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial **assessment / severity triage** within **7 business days**.
- We work with you on a fix and a coordinated disclosure date. We'll credit you in
  the advisory and release notes unless you prefer to remain anonymous.

Please give us a reasonable window to ship a fix before any public disclosure.

## Scope

**In scope** - vulnerabilities in PerspectiveGraph itself, for example:

- authentication/authorization bypass (bearer tokens, OIDC/JWT, per-application
  RBAC), ingest HMAC verification, or the auth-lockout logic;
- Cypher/SQL injection into the Apache AGE store, or any injection via ingested
  scanner data;
- tampering with or forging the tamper-evident audit log, or breaking at-rest
  encryption / export signature verification;
- cross-tenant or cross-application data leakage;
- SSRF, RCE, path traversal, or denial of service in the backend or collectors;
- secrets disclosure (in logs, errors, exports, or the repository).

**Out of scope:**

- vulnerabilities in the *scanners and sources* whose output you ingest (report
  those to their projects) - though a parsing bug in **our** collector is in scope;
- vulnerabilities in third-party dependencies with no demonstrated impact here
  (we track these with `govulncheck` + Trivy in CI);
- findings that require an already-compromised host, a misconfiguration the docs
  explicitly warn against, or physical access;
- missing hardening that is configurable and documented (see below) rather than a
  flaw - e.g. running with auth disabled in an untrusted network.

## Running PerspectiveGraph safely

Because the tool maps how to breach the org, **harden any deployment reachable
beyond a trusted boundary**. See the [threat model](docs/THREAT-MODEL.md) for the
full trust-boundary and asset analysis and the operator checklist. The controls below are built in and documented in the
[README "Application hardening" section](./README.md#application-hardening) and in
[`.env.example`](./.env.example):

- **`API_TOKENS` / OIDC** - bearer auth with role + per-application RBAC (tokens
  support expiry and `sha256$`-hashed-at-rest storage).
- **`INGEST_HMAC_SECRET`** - signed ingestion so scanner data can't be forged.
- **`STORE_ENCRYPTION_KEY`** - AES-256-GCM at-rest encryption of the governance
  stores and the audit log.
- **`EXPORT_SIGNING_KEY`** - Ed25519-signed OSCAL/SIEM exports a consumer can verify.
- **`AUDIT_LOG_PATH`** - tamper-evident, hash-chained audit log of reads and writes
  (verify with `perspectivegraph verify-audit <file>`).
- **`AUTH_LOCKOUT_THRESHOLD` / `EXFIL_ALERT_THRESHOLD`** - brute-force lockout and
  exfiltration alerting.

A default install is unauthenticated by design for a trusted-cluster demo; the
process logs a loud warning, and the Helm chart prints one in its notes, whenever
auth or persistence is left off.

## Our own supply chain

The project holds itself to the bar it sets: CI runs `gosec` (SAST), **CodeQL**
(semantic taint analysis), `gitleaks` (secret scan), `govulncheck`, and a Trivy image
scan; backend images are distroless, non-root, read-only-rootfs, and digest-pinned.
GitHub Actions are pinned to commit SHAs (Dependabot keeps them current) and an OpenSSF
Scorecard workflow tracks the repo's posture.

The collector **parse boundary** - where attacker-influenceable scanner/cloud/cluster
dumps become events - is **fuzzed** (`internal/ingestion/fuzz`, Go native fuzzing, OSS-Fuzz
compatible): the seed corpus runs on every CI build, a scheduled **Fuzz** workflow
explores each target for minutes weekly (and on ingestion changes), and `make fuzz` (or a
deep `go test -fuzz`) hunts panics and unbounded work on malformed input locally.

Released images (`v0.3.0` onward, on `ghcr.io/luiacuaniello/`) are **signed with
cosign keyless**, ship an **SPDX SBOM** (attested to the image and attached to the
GitHub release), and carry a **SLSA build-provenance** attestation. Verify before you
run them:

```bash
IMG=ghcr.io/luiacuaniello/perspectivegraph:v0.3.0
ID_RE="^https://github.com/luiacuaniello/perspectivegraph/.github/workflows/"
ISSUER=https://token.actions.githubusercontent.com

# 1. signature (who built it, in which workflow)
cosign verify --certificate-identity-regexp "$ID_RE" --certificate-oidc-issuer "$ISSUER" "$IMG"

# 2. SBOM attestation
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp "$ID_RE" --certificate-oidc-issuer "$ISSUER" "$IMG"

# 3. SLSA build provenance
gh attestation verify "oci://$IMG" --repo luiacuaniello/perspectivegraph
```
