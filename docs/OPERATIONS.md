# Operations & production hardening

The bundled `docker compose` / Helm defaults are tuned for a **demo**: local database,
no auth, no TLS, best-effort persistence. This runbook is what changes for a real
deployment. It complements, and does not repeat, the [threat model](THREAT-MODEL.md)
(trust boundaries + operator checklist), the README "Application hardening" section, and
[SECURITY.md](../SECURITY.md).

Environment-variable names below are the actual configuration keys (see
`backend/internal/config`).

## 1. Demo vs production - what actually changes

| Concern | Demo default | Production |
|---|---|---|
| Database | bundled Postgres+AGE image | external, managed, encrypted Postgres+AGE |
| API auth | open | `API_TOKENS` and/or OIDC (`OIDC_*`) required |
| Ingest auth | open | per-tenant HMAC (`INGEST_HMAC_SECRETS`) + `INGEST_RATE_RPS` |
| Transport | plaintext | TLS in-app (`TLS_CERT_FILE`/`TLS_KEY_FILE`) or at the ingress; `POSTGRES_SSLMODE`; `NATS_TLS_*` |
| Secrets | env vars in compose | secret manager / mounted files, never inline |
| Exposure | localhost | behind a gateway/WAF; network policy between components |

## 2. Secure configuration reference

Turn these on for any deployment reachable beyond a trusted boundary:

```bash
# API authentication (pick tokens, OIDC, or both)
API_TOKENS=<tenant>:<bearer-token>,...        # static bearer credentials
OIDC_ISSUER=https://idp.example.com/realms/pg # + OIDC_CLIENT_ID, OIDC_JWKS_URL,
                                              #   OIDC_AUDIENCE, OIDC_AUTHORIZE_URL,
                                              #   OIDC_TOKEN_URL, OIDC_SCOPES
AUTH_LOCKOUT_THRESHOLD=5                       # brute-force lockout

# Ingest authentication + throttling
INGEST_HMAC_SECRETS=<tenant>:<hmac-secret>,... # per-tenant webhook HMAC
INGEST_RATE_RPS=50                             # requests/sec cap

# Transport security
TLS_CERT_FILE=/etc/pg/tls/tls.crt              # in-app TLS (or terminate at the ingress)
TLS_KEY_FILE=/etc/pg/tls/tls.key
POSTGRES_SSLMODE=verify-full                   # never `disable` in prod
NATS_TLS_CA=/etc/pg/nats/ca.crt                # + NATS_TLS_CERT, NATS_TLS_KEY

# Data hygiene
SCRUB_INGEST=true                              # scrub secrets out of ingested payloads
CORS_ALLOWED_ORIGINS=https://dashboard.example.com
```

Least privilege for the outbound integrations: give connectors a read-only cloud role
(`AWS_CONNECTOR_MODE=sdk` + a SecurityAudit/ViewOnlyAccess role), scope `GITHUB_TOKEN`
to the target repo only, and leave `ANTHROPIC_API_KEY`/`HF_TOKEN` unset unless you accept
sending attack-path context to that provider.

Two ready-to-use hardened profiles apply all of the above:

- **Kubernetes (recommended):** `deploy/helm/perspectivegraph/values-production.yaml` -
  auth + ingest HMAC on, external Postgres+AGE with `sslMode: verify-full`, TLS at the
  ingress, durable audit log, and secrets sourced from your own manager
  (`secrets.existingSecret`, e.g. Vault / Sealed Secrets / External Secrets).

  ```bash
  helm upgrade --install perspectivegraph deploy/helm/perspectivegraph \
    -f deploy/helm/perspectivegraph/values-production.yaml \
    --set postgres.externalHost=db.internal --set ingress.host=pg.example.com
  ```

- **Docker Compose (single host / on-prem):** `.env.production.example` (copy to `.env`,
  fill in, `chmod 600`) plus the `docker-compose.prod.yml` override for the in-app TLS cert
  mount.

  ```bash
  cp .env.production.example .env   # then fill it in and: chmod 600 .env
  docker compose --profile app -f docker-compose.yml -f docker-compose.prod.yml up -d
  ```

## 3. External PostgreSQL + Apache AGE

The demo runs the `apache/age` image; **do not use it in production** (see the
security-baseline note). Point the backend at your own managed instance:

```bash
POSTGRES_DSN=postgres://user:pass@db.internal:5432/perspectivegraph?sslmode=verify-full
# or the discrete POSTGRES_HOST/PORT/DB/USER/PASSWORD + POSTGRES_SSLMODE keys
```

The instance must have the AGE extension available. On first boot the backend creates its
graph; the role needs `CREATE` on the database plus usage of `ag_catalog`.

## 4. Backup & restore (the graph is sensitive data)

The graph in Postgres+AGE is your source of truth and a map of the attack surface - back
it up and test the restore.

```bash
# Backup: dump the whole database (includes ag_catalog + the graph schema)
pg_dump --format=custom --no-owner --dbname="$POSTGRES_DSN" --file pg-graph.dump

# Restore into a fresh instance that already has the AGE extension loaded
createdb perspectivegraph
psql -d perspectivegraph -c 'CREATE EXTENSION IF NOT EXISTS age;'
pg_restore --no-owner --dbname=perspectivegraph pg-graph.dump
```

Notes:
- Restore into a database where `CREATE EXTENSION age` has run first; AGE graph data lives
  under `ag_catalog` and the graph's own schema, both captured by a full `pg_dump`.
- Store dumps encrypted (they contain A1 from the threat model). Apply the same retention
  and access controls you would to a secrets store.
- Validation/verdict data persists separately via `VALIDATIONS_PATH`; back that path up too
  if you rely on the calibration history.

## 5. Upgrades

1. Read the [CHANGELOG](../CHANGELOG.md) for the target version.
2. Take a backup (section 4).
3. Roll the backend image forward. The graph schema is created/managed by the backend;
   there is no separate migration step, but a major version may re-derive nodes/edges - a
   backup lets you roll back.
4. Verify: `/healthz` returns 200 and `attackPaths` returns after one `ANALYZER_INTERVAL`.

Pin to a signed, digest-referenced image and verify it before rollout (see
[SECURITY.md "Our own supply chain"](../SECURITY.md#our-own-supply-chain)).

## 6. Observability & SLOs

- `GET /healthz` - liveness/readiness (the container HEALTHCHECK uses the `healthz`
  subcommand; distroless has no shell).
- `GET /metrics` - Prometheus metrics: `perspectivegraph_connector_*`,
  `perspectivegraph_analyzer_*`, ingest and auth counters.
- Suggested SLOs to alert on: ingest error rate, analyzer pass duration vs
  `ANALYZER_INTERVAL`, connector `last_error`, and `auth.deny` spikes (possible
  credential stuffing) from the audit log.

## 7. High availability

The analyzer/scheduler and connectors are **leader-gated** - extra replicas do not
duplicate work or multiply API calls, but there is no automatic failover of the leader
yet. For availability today: run the API/ingest stateless tier with multiple replicas
behind a load balancer, keep the database HA at the managed-Postgres layer, and treat the
single active analyzer as a restart-tolerant component (its state is derivable from the
graph). Track true leader-election/failover as a roadmap item.

## 8. Pre-production checklist

- [ ] API auth enabled (`API_TOKENS`/OIDC) and verified from an unauthenticated client.
- [ ] Ingest HMAC (`INGEST_HMAC_SECRETS`) + `INGEST_RATE_RPS` set.
- [ ] TLS everywhere (`TLS_*`, `POSTGRES_SSLMODE=verify-full`, `NATS_TLS_*`).
- [ ] External managed Postgres+AGE; demo image not in the deployment.
- [ ] Secrets in a manager/mounted files, not inline in compose/Helm values.
- [ ] Connector role is read-only and reviewed; `GITHUB_TOKEN` scoped to one repo.
- [ ] Backup scheduled and a restore rehearsed (section 4).
- [ ] `/metrics` scraped; alerts on the SLOs above.
- [ ] Images verified (cosign signature + SBOM + provenance) before rollout.
- [ ] Engine behind a gateway/WAF; network policy between components.

See the [threat model operator assumptions](THREAT-MODEL.md#operator-assumptions-what-you-must-do-for-production)
for the rationale behind each item.
