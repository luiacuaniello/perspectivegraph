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
API_TOKENS=<token>:<role>[:<tenant>[:<YYYY-MM-DD>]],...  # role is viewer|admin
                                              # e.g. API_TOKENS=s3cr3t:admin
                                              # Entries that do not parse are DROPPED,
                                              # so with PG_ENV=production the backend
                                              # refuses to start rather than serve an
                                              # open endpoint. Check startup warnings.
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

### Keeping secrets out of the environment

Every credential above also accepts a **`<KEY>_FILE`** variant holding the *path* to a
file with the value: `API_TOKENS_FILE`, `INGEST_HMAC_SECRET_FILE`,
`POSTGRES_PASSWORD_FILE`, `STORE_ENCRYPTION_KEY_FILE`, `EXPORT_SIGNING_KEY_FILE`,
`GITHUB_TOKEN_FILE`, `GITLAB_TOKEN_FILE`, `ANTHROPIC_API_KEY_FILE`, `HF_TOKEN_FILE`, and
the rest.

Use them. The process environment is one of the least private places on a Unix host:
anything that can read `/proc/<pid>/environ` sees it, `docker inspect` prints it in full
to anyone in the `docker` group, it lands in crash dumps, and every child process
inherits it. A mounted file keeps the value out of all of that, and it is what makes
Docker secrets, Swarm secrets, a Vault Agent sidecar and a Kubernetes Secret mounted as a
volume work without the credential ever passing through the environment.

**Docker.** An overlay ships with the repo:

```bash
mkdir -p secrets && chmod 700 secrets
printf '%s' "$(openssl rand -hex 32)"        > secrets/ingest_hmac_secret
printf '%s' "tok-$(openssl rand -hex 16):admin" > secrets/api_tokens
printf '%s' "$(openssl rand -hex 32)"        > secrets/postgres_password
printf '%s' "$(openssl rand -hex 32)"        > secrets/store_encryption_key
chmod 600 secrets/*

docker compose -f docker-compose.yml -f docker-compose.secrets.yml --profile app up -d
```

It mounts each file at `/run/secrets/…`, points the matching `*_FILE` variable at it,
blanks the environment-borne version so a stale value cannot win, and sets
`PG_ENV=production`. `secrets/` is gitignored. Verify with
`docker inspect perspective-backend | grep -i secret` - you should see only paths.

**Kubernetes.** The chart already provisions a Secret and consumes it with
`secretKeyRef`; set `secrets.existingSecret` to bring your own from External Secrets,
Sealed Secrets or Vault. To go further and avoid the environment entirely, mount that
Secret as a volume and set the `*_FILE` variables to the mounted paths.

**A `<KEY>_FILE` that is set but unreadable stops the process.** That is deliberate: an
operator who mistypes a mount path would otherwise start cleanly with no credential at
all - and "no API token" is not an error, it is the demo profile - which is exactly the
open deployment the mount was meant to prevent. A trailing newline is stripped (secret
managers add one); nothing else is touched, so a passphrase may begin or end with a space.

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
- **Ready-to-use**: [`deploy/observability`](../deploy/observability) ships a Grafana
  dashboard and Prometheus alert rules for exactly these signals - import the dashboard,
  load the rules, point a scrape at `/metrics`. For analyzer load/scale characterization see
  [SCALE.md](SCALE.md) (`make scale-test`).

### Health, and what it now refuses to hide

`GET /healthz` returns **503** when the engine is serving in a reduced mode, and 200
otherwise. The Helm readiness probe hits it, so a degraded pod is taken out of rotation.

That distinction did not exist until it was found by running the stack: `/healthz`
returned 200 unconditionally, so the probe only ever proved the HTTP server was
listening. Meanwhile, when Apache AGE was unreachable at startup the backend **fell back
to in-memory stores** with a single warning - leaving the engine computing over an empty,
volatile graph. An empty graph answers *"no attack paths"*, which reads as good news. So
a database outage presented as a clean bill of health, one layer below where
`ingestCoverage` can see it.

Two changes close that:

- **`PG_ENV=production` now refuses to start** when Apache AGE is unavailable, instead of
  falling back. Set `PG_ENV=demo` if you genuinely want the in-memory store, or
  `GRAPH_STRICT=true` to get the same refusal outside production.
- When the fallback *does* engage (demo profiles), `/healthz` reports 503 with the reason,
  so nothing downstream mistakes it for a working deployment. A deployment that runs
  in-memory **by design** stays healthy - that is the demo working as intended, not a
  failure.

### Logs

- Set **`LOG_FORMAT=json`** in production. The default is `text`, which is what a person
  wants during `make demo` and what no log pipeline wants. `LOG_LEVEL` is
  `debug|info|warn|error`. Both go to stdout; collect them there rather than writing files.
- **Every request carries an id.** It is generated per request (or taken from an inbound
  `X-Request-Id` when that value is short and alphanumeric), returned in the
  `X-Request-Id` response header, attached to log lines made with the request's context,
  and written into the audit record's `fields.request_id`. So one identifier joins what a
  user reports, what the application log says, and what the audit log recorded - which is
  the join you want at the moment you actually need it.
  - It rides in the audit record's `fields`, not in a new column, so the hash chain still
    verifies exactly as before and `verify-audit` is unaffected.
  - Alerts raised by the abuse watchers (`exfil.alert`, `auth.lockout.alert`) deliberately
    carry **no** request id: they describe a window of events crossing a threshold, not
    the one request that happened to be last, and pinning them to it would point an
    investigation at an arbitrary call.
- **`/metrics` is open and unthrottled** - deliberately, so a scrape never starves - and
  it is served on the same port as the API. Series such as
  `perspectivegraph_analyzer_critical_paths` carry a `tenant` label, so reaching that port
  is enough to enumerate tenants and read each one's current path count. Scrape from
  inside the cluster and do not publish the API port directly; see
  [THREAT-MODEL.md](THREAT-MODEL.md).

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
