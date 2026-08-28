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
| Database | bundled Postgres+AGE image | external, encrypted Postgres+AGE - **managed only on Azure**, self-managed elsewhere (§3) |
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
  helm upgrade --install perspectivegraph oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
    -f values-production.yaml \
    --set postgres.externalHost=db.internal --set ingress.host=pg.example.com
  ```

  The chart installs from the registry, so a production cluster needs no git checkout.
  The profiles ship **inside** the chart, so neither does getting them - pull it once and
  the values files are there to edit and keep under your own change control:

  ```bash
  helm pull oci://ghcr.io/luiacuaniello/charts/perspectivegraph --untar
  ls perspectivegraph/values-*.yaml   # production, ha, sso-demo
  ```

  It is cosign-signed; verify it before it runs (see the
  [manual](MANUAL.md#deploy-to-kubernetes)). From a git checkout instead, swap the
  `oci://…` reference for `deploy/helm/perspectivegraph`.

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

## 3. The database: PostgreSQL + Apache AGE

The graph lives in PostgreSQL with the [Apache AGE](https://age.apache.org) extension, and
that extension - not the DSN - is what decides your deployment. **Most managed PostgreSQL
services do not offer AGE**, so "point it at a managed Postgres+AGE" is not advice you can
act on everywhere, and it is worth settling before anything else in this runbook.

### Where you can actually get one

| Where | AGE | What it costs you |
|---|---|---|
| **Azure Database for PostgreSQL flexible server** | **yes** (PostgreSQL 16 and below) | The only managed service that ships it. Turned on with two server parameters (recipe below). Not available on PostgreSQL 17, and AGE is excluded from Azure's in-place major-version upgrade |
| **Self-managed** on Kubernetes or a VM | yes | Backups, failover, patching and TLS become yours. The `apache/age` image already preloads the extension |
| **AWS RDS / Aurora PostgreSQL** | **no** | Not on the extension allow-list. Requests go to `rds-postgres-extensions-request@amazon.com` |
| **Google Cloud SQL / AlloyDB** | **no** | Not in the supported-extensions list |
| The bundled `apache/age` container | yes | **Demo only.** Not sized, backed up, patched or hardened for production |

So on AWS and GCP today the honest choice is to run Postgres+AGE yourself. One thing makes
that a smaller decision than it looks: the graph is **derived** state - every node and edge
is reconstructible by re-ingesting the feeds - so a lost database is a re-seed rather than a
data-loss event (§4). Losing it costs you history, not the map.

### What the engine needs of it

Tested against **PostgreSQL 16 + AGE 1.6.0** - the digest-pinned image the demo and the CI
integration job both run. Other combinations are not tested here.

**The role does not need to be a superuser.** These grants are enough:

```sql
GRANT CONNECT, CREATE ON DATABASE perspectivegraph TO perspective;
GRANT USAGE ON SCHEMA ag_catalog TO perspective;
GRANT SELECT ON ag_catalog.ag_graph, ag_catalog.ag_label TO perspective;
```

What the connection does need is AGE actually loaded, and there are only two ways that
happens:

- the role may run `LOAD 'age'` - a **superuser-only** command, which is what the bundled
  demo does and what no managed service permits; or
- **`age` is in `shared_preload_libraries`**, so the library is present before the session
  opens. The `apache/age` image does this by default; Azure exposes it as a parameter.

The backend works out which of the two it is on the first query and adapts. Check what you
have with:

```sql
SELECT extversion FROM pg_extension WHERE extname = 'age';   -- is it installed
SHOW shared_preload_libraries;                                -- is it preloaded
```

**Let the backend create its own graph.** AGE keeps each graph in a schema owned by
whoever called `create_graph`, and a role that does not own that schema is refused on the
first write with `permission denied for schema ...`. If an administrator pre-creates the
graph, hand it over with `ALTER SCHEMA <graph> OWNER TO <role>` (and the tables in it)
rather than leaving the engine a tenant in someone else's schema.

### Azure Database for PostgreSQL

1. On the server's **Parameters** blade, add `AGE` to **`azure.extensions`** and to
   **`shared_preload_libraries`**, and save. The server restarts to load the library.
2. Connect to the database and run `CREATE EXTENSION IF NOT EXISTS age CASCADE;`.
3. Apply the grants above and point the backend at it.

Do **not** run `LOAD 'age'` by hand there: with the library preloaded it does not quietly
succeed, it fails with a privilege error.

### Self-managed

Run the `apache/age` image (or your own build of the extension) as a StatefulSet, under a
PostgreSQL operator with that image, or on a VM. Whatever you pick, the list of things you
have just taken on is the same, and none of it is optional for production: backups with a
tested restore (§4), a replica and a failover path, patching for both PostgreSQL and AGE,
TLS, and monitoring. §4 covers backup and restore; the demo image is not a starting point
for any of it.

### Pointing the backend at it

```bash
POSTGRES_DSN=postgres://user:pass@db.internal:5432/perspectivegraph?sslmode=verify-full
# or the discrete POSTGRES_HOST/PORT/DB/USER/PASSWORD + POSTGRES_SSLMODE keys
# POSTGRES_PASSWORD_FILE keeps the password out of the environment entirely (§2)
```

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
- **`/metrics` is open and unthrottled** - deliberately, so a scrape never starves.
  Series such as `perspectivegraph_analyzer_critical_paths` carry a `tenant` label, so on
  a reachable port they are enough to enumerate tenants and read each one's current path
  count.
  - **Set `METRICS_ADDR`** to move them off the API port onto their own listener, e.g.
    `METRICS_ADDR=127.0.0.1:9090`. That listener serves `/metrics` and nothing else - no
    GraphQL, no auth config, no exports - and speaks plain HTTP by design, because it is
    meant for an address the outside cannot reach and demanding a certificate there is
    the friction that pushes operators back onto the public port.
    `values-production.yaml` sets it.
  - It is **empty by default**: `/metrics` on the API port is declared stable surface in
    [API-STABILITY.md](API-STABILITY.md), and relocating it silently would break every
    existing scrape config.

## 7. High availability

The analyzer/scheduler and connectors are **leader-gated** - extra replicas do not
duplicate work or multiply API calls - and leadership **fails over on its own**. The
election is a session-scoped PostgreSQL advisory lock: when the holder dies its
connection drops, the lock is released server-side, and another replica takes it on its
next check. No external coordinator, and no operator action.

What pins you to one replica is the **file** governance backend, not the election. With
`GOVERNANCE_BACKEND=postgres` the suppressions, tickets, posture history, validations and
KEV holdout are all shared - and so is the **audit log**: the chain moves into the
database, where each append takes a transaction-scoped advisory lock, reads the tail and
writes in the same transaction, so several replicas extend one chain instead of forking
it. Keep the database HA at the managed-Postgres layer.

So the Kubernetes recipe for more than one backend is `governanceBackend: postgres` **and**
`persistence.enabled: false` - the PVC then holds nothing, and its ReadWriteOnce mode would
otherwise leave every pod scheduled off the first node hanging on `FailedAttachVolume`. The
chart refuses to render `persistence.enabled` with `replicas > 1` rather than let you find
that out from a stuck rollout.

`values-ha.yaml` is that recipe as an overlay on top of the production profile, so HA is
four decisions rather than a second copy of the whole file:

```bash
helm upgrade --install perspectivegraph oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  -f values-production.yaml -f values-ha.yaml \
  --set postgres.externalHost=db.internal --set ingress.host=pg.example.com \
  --set nats.externalUrl=nats://nats.internal:4222
```

It sets the two settings above, raises the backend to three replicas and the dashboard to
two, spreads them one-per-node, and adds a **PodDisruptionBudget** - because `replicas: 3`
that a drain can evict all at once, or that the scheduler stacks on one node, is three
copies of a single failure domain rather than availability. `values-production.yaml` keeps
the single-replica shape on the file backend: fewer moving parts, and the audit chain in a
file you can archive.

Two single points of failure it does **not** remove, and neither is hidden:

- **The database.** Every replica shares one Postgres+AGE. Use a managed instance with a
  replica and automatic failover - §3 covers where AGE is actually available, which is
  narrower than it looks.
- **The event bus.** The bundled NATS is one replica whose JetStream store lives in the
  container's writable layer, so a restart drops in-flight events. The HA overlay therefore
  refuses to inherit it: it sets `nats.enabled: false` and the chart will not render until
  `nats.externalUrl` points at a NATS you run clustered. What that outage costs is the
  events in flight, not the graph - the graph is derived and the feeds re-ingest it - but
  the analyzer is blind for the duration.

### Retention and rotation

An append-only chain nobody may delete from grows forever, and "forever" is the absence of
a retention policy rather than one. Both backends can be bounded, differently:

**Postgres chain - `AUDIT_RETENTION`.** Set a window and the leader prunes records older
than it, oldest first, on a cadence derived from the window (a sixth of it, clamped to
between an hour and a day - so a 90-day window checks in daily):

```bash
AUDIT_RETENTION=2160h   # 90 days; unset (the default) keeps everything, as before
```

Pruning removes a **prefix** and records a checkpoint holding the sequence and hash of the
last record removed, so what survives still verifies link-by-link back to it - see the
[threat model](THREAT-MODEL.md#retention-and-one-honest-tension) for why that is the only
shape of deletion this log allows. `verify-audit` says what was pruned rather than quietly
reporting a shorter chain, the prune is itself an entry in the chain it shortened, and
`perspectivegraph_audit_pruned_records_total` counts what has gone.

**File chain - rotate it.** There is no automatic pruning, and the two obvious ways to
rotate are both wrong: `logrotate` with `copytruncate` leaves the process writing at its old
offset into a truncated file, and a live `mv` leaves it writing into the file you meant to
retire, because the open handle follows the inode. The procedure that works is **stop, move
the file aside, start** - the engine then begins a fresh chain, and each retired file stays
a complete chain that verifies on its own (a test pins this). Archive the retired files
somewhere append-only: once rotated, their integrity is your archive's problem, not the
engine's. Setting `AUDIT_RETENTION` on a file-backed deployment logs a warning and prunes
nothing, rather than pretending to.

Whichever you use, decide the window on purpose. It is the number a data-protection review
asks for, and the erasure/tamper-evidence tension in the threat model is the reason it
cannot simply be "delete that one record".

### Verifying the chain

Verify the chain wherever it lives - the subcommand follows it:

```bash
perspectivegraph verify-audit /var/log/perspectivegraph/audit.log   # file backend
perspectivegraph verify-audit -postgres                             # governance database
```

`-postgres` reads `POSTGRES_DSN` (or the discrete `POSTGRES_*` keys, `_FILE` variants
included) exactly as the server does, so a DSN with a password in it never has to be typed
into a command line where every process on the host can read it.

## 8. Pre-production checklist

- [ ] API auth enabled (`API_TOKENS`/OIDC) and verified from an unauthenticated client.
- [ ] Ingest HMAC (`INGEST_HMAC_SECRETS`) + `INGEST_RATE_RPS` set.
- [ ] TLS everywhere (`TLS_*`, `POSTGRES_SSLMODE=verify-full`, `NATS_TLS_*`).
- [ ] External Postgres+AGE chosen with §3 open (managed on Azure, self-managed on AWS/GCP),
      its role non-superuser, and the demo image out of the deployment.
- [ ] Secrets in a manager/mounted files, not inline in compose/Helm values.
- [ ] Connector role is read-only and reviewed; `GITHUB_TOKEN` scoped to one repo.
- [ ] Backup scheduled and a restore rehearsed (section 4).
- [ ] `/metrics` scraped; alerts on the SLOs above.
- [ ] Images verified (cosign signature + SBOM + provenance) before rollout.
- [ ] Engine behind a gateway/WAF; network policy between components.

See the [threat model operator assumptions](THREAT-MODEL.md#operator-assumptions-what-you-must-do-for-production)
for the rationale behind each item.
