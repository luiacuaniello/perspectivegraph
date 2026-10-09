# Production on one machine

*Part of the [PerspectiveGraph manual](../MANUAL.md).* A VM with Docker, a DNS name and one
command: TLS, generated credentials, an authenticated bus, daily backups and a tested restore.

This is the deployment for a team that wants the engine running for real without a Kubernetes
cluster. It is the compose stack from the [quick start](quick-start.md) - the same published,
signed images - with what production adds on top: a TLS front door that renews its own
certificate, every credential generated into files rather than typed into the environment,
`PG_ENV=production` so that the backend refuses to start open, nothing listening but that
front door, and a backup that is restored in CI on every change, so that the restore is known
to work rather than hoped to.

It is one machine, and that is its limit: no failover, and the database shares a disk with its
own backups until you copy them off. When that is not enough, the
[Helm chart with CloudNativePG](kubernetes.md#a-production-database-cloudnativepg) runs a
replicated database with continuous backups.

## What you need

- A Linux VM with Docker Engine and the Compose plugin, 2.24 or newer (`docker compose
  version`), and `git`, `make` and `curl`.
- A DNS name pointing at it (an `A` or `AAAA` record).
- Ports **80 and 443** open to it from the internet: 443 serves the dashboard, 80 answers
  the certificate authority's challenge and redirects to 443. Nothing else needs to be open.
- A user in the `docker` group to run it as. Not root: the backups are written as whoever runs
  the setup, so that they are yours to copy without `sudo`.

## Install

```bash
git clone --branch v1.36.0 https://github.com/luiacuaniello/perspectivegraph.git # x-release-please-version
cd perspectivegraph
make prod-init DOMAIN=perspectivegraph.example.com
```

`make prod-init` (it runs [`scripts/prod-init.sh`](../../scripts/prod-init.sh)):

1. **Generates every credential** into `./secrets`: the database password, the ingest HMAC
   secret, an admin API token, the at-rest encryption key, the export signing key and the
   NATS password. Each is 256 random bits, and none is ever replaced - a new database password
   would lock the backend out of the data the old one protects.
2. **Writes `.env`**, the instance: its name, the compose files the stack is made of
   (`docker-compose.yml`, the published images, the secrets overlay and
   [`docker-compose.vm.yml`](../../docker-compose.vm.yml)), and who owns the backups. From
   then on `docker compose` in this directory needs no `-f` flags.
3. **Starts it** and waits until the dashboard answers through Caddy. The first time, it
   also compiles Caddy - about a minute, with Go's toolchain image pulled once - and the
   first certificate takes a few seconds once the name resolves to the machine.

It prints where everything is. Run it again whenever you like: it keeps what exists.

> **Why the secrets are mode 644.** The directory is 700, which keeps every other user of the
> machine out. The files are readable because Compose mounts each one with the host's owner
> and mode, and the containers open them as their own users - the backend as uid 65532,
> Postgres as 999 - so a 600 file of yours is one neither can read, and the backend refuses
> to start, naming the file. Docker Desktop maps ownership and hides this; a server does not.

## What runs

| Container | Image | Listens |
|---|---|---|
| `caddy` | built here from [`deploy/caddy`](../../deploy/caddy/Dockerfile): Caddy's release compiled with this project's Go, on distroless, non-root | **80, 443** - the only published ports |
| `frontend` | the release's dashboard | inside the stack |
| `backend` | the release's engine, `PG_ENV=production` | inside: the API (8080) and the ingest endpoint (8081) |
| `postgres` | the release's PostgreSQL + AGE | inside |
| `nats` | NATS JetStream, its stream on a volume | inside, password required |
| `backup` | the release's PostgreSQL image, for `pg_dump` | - |

Caddy serves the dashboard and its API, and passes `POST /ingest/*` - the signed write path -
to the backend. The ingest server's other routes (its health and the connectors' status) are
not exposed. Every port `docker-compose.yml` binds to `127.0.0.1` is withdrawn, so on the
machine itself nothing else listens either; reach the inside with `docker compose exec`:

```bash
docker compose ps                                                  # health of everything
docker compose logs -f backend                                     # JSON logs
docker compose exec frontend wget -qO- http://backend:8081/connectors  # connector status
docker compose exec postgres psql -U perspective perspectivegraph   # the database
```

The production posture lives in `docker-compose.vm.yml`, where it can be reviewed and is
upgraded with the repository: the governance state (triage, tickets, verdicts, lockouts, the
audit chain) in Postgres, a 90-day audit retention, a brute-force lockout, JSON logs, CORS
and the dashboard URL set to `https://<DOMAIN>`, and `TRUSTED_PROXY_CIDRS` covering Docker's
networks so that rate limits and lockouts key on the real client behind Caddy. Each takes a
value from `.env` first; every other setting the backend reads goes in `.env` too
([configuration reference](configuration.md)), followed by `docker compose up -d`.

## Sign in and send the first report

The admin token is the part of `secrets/api_tokens` before the colon:

```bash
cut -d: -f1 secrets/api_tokens
```

Paste it into the dashboard's sign-in. For people rather than one shared token, configure SSO
([choosing between SSO and static tokens](security.md#choosing-between-sso-and-static-tokens))
in `.env`, and `docker compose up -d`.

Reports go to `https://<DOMAIN>/ingest/<source>`, signed with `secrets/ingest_hmac_secret`.
The release's CLI signs them; where the report is produced - a CI job, a cron job - give it
that secret and the address:

```bash
export INGEST_HMAC_SECRET_FILE=/path/to/ingest_hmac_secret
perspectivegraph ingest -url https://perspectivegraph.example.com trivy trivy.json
kubectl get ingress,service,pod,serviceaccount,role,clusterrole,rolebinding,clusterrolebinding -A -o json |
  perspectivegraph ingest -url https://perspectivegraph.example.com -cluster prod-eu k8s -
```

The CLI is a single binary on the [releases page](https://github.com/luiacuaniello/perspectivegraph/releases/latest),
and the same one is the engine's image: `docker run --rm -i
ghcr.io/luiacuaniello/perspectivegraph:<version> ingest ...` needs nothing installed. In
GitHub Actions the [merge gate](ci-gate.md) does the posting. Which sources to send, and in
what order, is the [onboarding runbook](onboarding.md).

**AWS, read live.** On EC2 the backend can read the account with the instance's own role. Add
to `.env`:

```bash
CONNECTORS_ENABLED=aws
AWS_CONNECTOR_MODE=sdk
AWS_REGION=eu-west-1
```

and give the instance's role the read-only policy from
[the read-only role](integrations.md#the-read-only-role) (or set `AWS_ROLE_ARN` to that role,
deployed with the instance's role as its trusted principal). The backend runs in a container,
one network hop further from the instance metadata service than the instance itself, and
IMDSv2's default hop limit of 1 drops its answers - so raise it to 2, keeping tokens required:

```bash
aws ec2 modify-instance-metadata-options --instance-id <id> \
  --http-tokens required --http-put-response-hop-limit 2
```

Off AWS, add [`docker-compose.aws.yml`](../../docker-compose.aws.yml) to `COMPOSE_FILE` in
`.env` to hand the backend a profile from the machine's `~/.aws`, read-only.

## Backups

The `backup` container dumps the database into `./backups` every day, as `pg_dump`'s custom
format, and keeps the newest 14 (`BACKUP_HOURS` and `BACKUP_KEEP` in `.env`). With the
governance state in Postgres, one dump is everything the engine holds. The dumps are written
mode 600, as you, and `docker compose ps` shows the container unhealthy when the newest dump
is more than a day and an hour old - a backup that silently stopped is visible.

Take one now, before an upgrade for instance:

```bash
docker compose run --rm backup once
```

**Copy them off the machine.** On its own disk a backup survives a mistake, not the loss of the
disk. Copy `./backups` elsewhere, encrypted: a dump is the whole attack map. A tool that
encrypts what it stores, such as restic, does both in one.

**Keep `./secrets` too, and apart from the dumps.** `STORE_ENCRYPTION_KEY` seals the audit
chain inside every dump: restored without it, the graph comes back and the audit trail does
not open. Stored together, the two are the attack map and the key to its history in one place.

## Restore

```bash
make prod-restore DUMP=backups/pg-graph-20261009T030000Z.dump
```

[`scripts/prod-restore.sh`](../../scripts/prod-restore.sh) asks before it changes anything,
then stops the backend and the backups, restores the dump into a new database, re-attaches
AGE's catalog to the restored graph, swaps the new database in for the old one and starts
everything again. A dump that turns out to be damaged stops it before the swap, with the old
database untouched.

The re-attaching is not optional, and it is why a plain `pg_restore` is not enough: AGE names
each graph in its own catalog by the OID of the graph's schema, `pg_dump` writes that as a
plain number, and the schema a restore creates gets a new one - so without it every query fails
with `graph with oid N does not exist`. [Backup & restore](../OPERATIONS.md#4-backup--restore-the-graph-is-sensitive-data)
has the same steps for a database you run yourself.

**On a new machine**: clone the same release, copy `./secrets` into the checkout, run
`make prod-init` with the same `DOMAIN` (it keeps the secrets it finds), then
`make prod-restore` with the dump.

## Upgrade

Read [UPGRADING](../UPGRADING.md) for the versions in between, take a backup, then:

```bash
docker compose run --rm backup once
git fetch --tags && git checkout vX.Y.Z       # the release you are moving to
make prod-init
```

`make prod-init` keeps the credentials and `.env`, pulls the release's images, rebuilds Caddy's
and restarts what changed. It never uses `docker compose up --build`: that would rebuild the
backend, the dashboard and the database from source on this machine and tag each build with
the release's own name, so an unsigned local image would run under the name of the signed one.

## How this is checked

[`scripts/prod-smoke.sh`](../../scripts/prod-smoke.sh) runs the whole recipe in a scratch
copy with `DOMAIN=localhost`, on Linux in CI on every change, and fails unless:

- only Caddy publishes a port;
- the dashboard answers over TLS that verifies against Caddy's certificate authority, with HSTS;
- the API refuses a request without the generated token, and accepts the token as admin;
- NATS refuses a client without the password;
- an unsigned report is refused at `/ingest/`, and a signed one is applied, through Caddy;
- the backup service writes a dump as the operator, mode 600;
- restoring that dump, after more was ingested, brings back the graph as it was when dumped;
- running `prod-init` again changes no credential.

Run it yourself with `make prod-smoke` (it needs ports 80 and 443 free, and Go).
