# Security, authentication and hardening

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Data hygiene, tenants and SSO, authentication and audit, and hardening the containers and the application.

## Data hygiene: a map of the attack surface, never a vault of secrets

PerspectiveGraph ingests raw scanner output, which can incidentally carry a **live
credential** - a hardcoded AWS key in a Semgrep snippet, a token on a Falco
command line. The graph is a map of *how to attack the org*, so the one thing it
must never become is a store of those secrets: a single read of the attack map
would otherwise hand an attacker working keys. At ingest, high-precision secret
patterns (AWS/GitHub/Slack/Google tokens, PEM private keys, JWTs, `secret=…`
assignments) are **redacted out of property values** before they reach the store -
you still learn *"an AWS key is hardcoded in `config.py:7`"*, you just never store
the key (`***redacted:aws-access-key***`, node stamped `secrets_scrubbed`).
Identifiers the graph joins on (ids, names, commit SHAs, image digests, refs) are
deliberately left untouched. On by default (`SCRUB_INGEST`); retention of the
scrubbed findings is governed by `GRAPH_TTL` - the graph is derived and
re-seedable, so nothing sensitive needs to live there long-term.

## Multi-tenant isolation & SSO login

This tool is, literally, a map of how to attack each customer - so the one thing
it must never do is leak across tenants. Every tenant gets its **own** AGE graph
and search index, and **every** API read funnels through `snapshot(tenantOf(ctx))`,
so a principal scoped to tenant A can never see tenant B's graph or attack paths.
That's the load-bearing security claim, so it's **proven by an end-to-end test**
(two tenants stay disjoint, the default tenant sees neither, id normalization
doesn't break the boundary), with per-tenant + per-app + role (viewer/operator/
admin) RBAC on top.

Login is **runtime, not baked in**. The dashboard reads a public `GET /auth/config`
(auth mode + the IdP's public coordinates - no secrets) and renders the right gate,
so a *single* build serves an open, token-secured, or SSO-secured backend with no
rebuild:

```bash
curl -s localhost:8080/auth/config
# open:  {"authRequired":false,"mode":"none"}
# secured: {"authRequired":true,"mode":"both","oidc":{"clientId":"…","authorizeUrl":"…"}}
# published read-only (API_ANONYMOUS_ROLE): {"authRequired":false,"mode":"token","anonymousRole":"viewer"}
```

A user pastes a token or clicks **Sign in with SSO**, which runs the full **OIDC
Authorization-Code + PKCE** flow (S256 challenge, `state` CSRF check, code→token
exchange at `OIDC_TOKEN_URL` - no client secret in the browser; the RFC 7636
derivation is unit-tested). The credential lives only in the tab's `sessionStorage`
and rides as a Bearer - never written to disk or the bundle. Token validation
stays on the JWKS / issuer / audience the backend already enforces (fail-closed:
it refuses to start with a JWKS URL but no `iss`/`aud`).

Once past the gate, the dashboard asks **`GET /auth/me`** what the credential resolved to,
so it offers only what the server will accept. A viewer or operator sees Suppress, Validate,
Create ticket and Open fix PR disabled with the reason, instead of pressing one and meeting
a 403; a mistyped, expired or revoked token sends the tab back to the sign-in screen instead
of opening a dashboard that fails every request. The endpoint sits behind the same
authentication as the data (401 without a valid credential) and describes only the caller:

```bash
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/auth/me
# {"subject":"token:1a2b3c4d","role":"viewer","tenant":"default","anonymous":false,"canWrite":false}
```

`subject` is the caller's name in the audit log - a fingerprint, never the token.
`canWrite` is the server's own write check answered in advance: suppressions, tickets,
verdicts and fix PRs need `admin`. `apps` appears when reads are scoped to applications, and
`anonymous` is true for a caller with no credential - on an open instance, or a visitor to
a published one.

### Trying SSO end-to-end on a laptop (the bundled Keycloak)

An opt-in compose profile stands up a demo IdP, so the login gate can be exercised
without a cloud tenant:

```bash
docker compose --profile app --profile sso up -d   # realm "demo", user demo/demo
```

Then point the backend at it and open <http://localhost:3000> → **Sign in with SSO**:

```bash
# Server-side validation - fetched by the BACKEND, over the compose network.
OIDC_JWKS_URL=http://keycloak:8080/realms/demo/protocol/openid-connect/certs
OIDC_ISSUER=http://localhost:8088/realms/demo
OIDC_AUDIENCE=perspectivegraph
# SPA-facing coordinates - used by the BROWSER, on the published port.
OIDC_CLIENT_ID=perspectivegraph
OIDC_AUTHORIZE_URL=http://localhost:8088/realms/demo/protocol/openid-connect/auth
OIDC_TOKEN_URL=http://localhost:8088/realms/demo/protocol/openid-connect/token
OIDC_LOGOUT_URL=http://localhost:8088/realms/demo/protocol/openid-connect/logout
```

**The two hosts differ on purpose**, and it is the step people get wrong. The JWKS is
fetched by the backend inside the compose network, so it uses the service name
(`keycloak:8080`). The issuer is a string *inside the token*, which Keycloak mints from
the address the browser used (`localhost:8088`) - so it has to match that one. They are
independent settings and they are meant to disagree. The Helm equivalent is
`values-sso-demo.yaml`, which splits them the same way.

**Where the role comes from.** RBAC is read off the token's `role` claim; a token without
one is `RoleNone` and sees nothing. The demo realm supplies it with a hardcoded claim
mapper (`role: admin`) - and that is the piece a real IdP has to provide too, mapping the
group or app role your directory already has onto a `role` claim of `viewer`, `operator`
or `admin`. There is no group-to-role mapping inside the engine, by design: the IdP is
where that decision belongs.

Demo only: Keycloak runs `start-dev` with an in-memory database and an imported realm.

## Auth, multi-tenancy & audit (optional, but do it before production)

Every door is open by default for zero-config local dev - and the backend
**logs a loud warning** when it is. The trust layer:

- **Ingest webhooks (write path)** - HMAC-SHA256 of the request body, keyed by a
  **per-tenant** secret that never travels on the wire (GitHub/Stripe model).
  Senders add `X-PerspectiveGraph-Signature-V2: v2=<hex>` with
  `X-PerspectiveGraph-Timestamp: <unix seconds>`, and `X-Tenant: <id>`. The v2 signature
  covers the time, the method, the path, the parameters and the body, and each one is
  accepted once within ±5 minutes - so a captured request cannot be replayed, or
  re-attributed to another commit by rewriting `?sha=`. The older
  `X-PerspectiveGraph-Signature: sha256=<hex>` covers the body alone; it stays accepted
  until `INGEST_HMAC_ACCEPT_V1=false`.
- **GraphQL API (read path)** - a bearer credential: a static token mapped to a
  role+tenant, or an **OIDC/JWT** (RS256/384/512 or ES256/384/512, verified against the
  JWKS - each algorithm only with a key of its own kind and curve; `role` and
  `tenant` claims). RBAC roles are `viewer` / `operator` / `admin`; GraphiQL is
  disabled when auth is on, and the dashboard is built with `VITE_API_TOKEN`.
- **Multi-tenancy** - each tenant's assets live in their **own isolated graph**
  (a separate Apache AGE graph + search index). Ingest routes by the
  authenticated tenant; queries are scoped to it. A tenant can never read or
  write another's data.
- **Immutable audit log - of *reads*, not just writes.** The tool is a map of how
  to breach the org, so *who looked at it* matters as much as who changed it. Every
  request and denial, **every view of the attack paths or the graph**
  (`view.attack_paths` / `view.graph` - with the path ids seen), and **every export**
  (`export.oscal` / `export.ndjson` - the moment the whole map leaves the tool) is
  appended to a **hash-chained** JSONL file (each record links to the previous via
  SHA-256, so tampering is detectable). It answers "who saw - or exfiltrated -
  which attack paths". Verify the chain any time:

  ```bash
  perspectivegraph verify-audit /var/log/perspectivegraph/audit.log
  # → audit chain OK: N records verified

  # Under GOVERNANCE_BACKEND=postgres the chain lives in the database instead (which is
  # what lets replicas exceed 1). Same check, addressed through POSTGRES_DSN / POSTGRES_*
  # rather than an argument, so the password stays out of the process list:
  perspectivegraph verify-audit -postgres
  ```

  **Retention.** Left alone the chain grows forever. `AUDIT_RETENTION=2160h` (90 days)
  prunes the database-backed chain, oldest records first, leaving a checkpoint so the
  survivors still verify against the hash of the last record removed - deleting from the
  middle stays impossible to do invisibly, which is the point of a chain. The file-backed
  chain is rotated instead. Both are in the
  [operations runbook](../OPERATIONS.md#retention-and-rotation).

```bash
# Single-tenant, signed + token-gated, with an audit trail:
INGEST_HMAC_SECRET=$(openssl rand -hex 32) \
API_TOKENS=$(openssl rand -hex 16):admin \
AUDIT_LOG_PATH=./audit.log \
  make run-backend
```

In production, set `PG_ENV=production`: the backend then **refuses to start** unless
both the API and ingest are authenticated, so the permissive default cannot be
reached by forgetting to configure it. Same idea as the OIDC check - a
misconfiguration should be a startup error someone reads, not a warning scrolling
past in a log.

### Choosing between SSO and static tokens

The two credential types are not interchangeable, and the difference that matters is
**how you take access away**.

**For people, use OIDC.** Revocation is your IdP's, which is where it belongs:
disable the account in Okta/Entra, their tokens expire on their own `exp` and no new
ones are issued. Nothing to redistribute, nothing to restart, and the audit trail
already records `jwt:<sub>` per request. This is the path to use for a team.

```bash
OIDC_JWKS_URL=https://your-idp/.well-known/jwks.json \
OIDC_ISSUER=https://your-idp/ \
OIDC_AUDIENCE=perspectivegraph \
  make run-backend
```

Issuer and audience are mandatory when JWKS is set - the backend refuses to start
without them, because a verifier that skips `iss`/`aud` accepts any token the
IdP ever minted, including ones meant for a different relying party.

**Then decide who gets which role, because signing in does not.** A token proves who
someone is; this tool's data is a map of how to attack the organisation, so an SSO
subject with no role gets **no access** until something grants it. Enterprise IdPs keep
that decision in group membership - neither Okta nor Entra mints a `role` claim unless
somebody builds a custom mapping inside the IdP first - so map the groups you already
have:

```bash
OIDC_GROUP_ROLES=pg-viewers=viewer,pg-secops=operator,pg-admins=admin
```

- A subject in **several** mapped groups gets the **highest** role among them, which is
  what adding someone to the admins group already means to whoever granted it.
- A `role` claim, if your IdP does mint one, still works and is taken together with the
  groups - the higher of the two wins. Both come from the same signed token, so
  preferring one would buy no security, only surprise.
- An entry that does not parse is **dropped and logged at error level**. Silently
  ignoring `pg-admins=administrator` would leave the group granting nothing, which reads
  as a working configuration to whoever wrote it and as a broken login to whoever is
  locked out.
- Claim names are configurable for directories that namespace them
  (`OIDC_GROUPS_CLAIM=https://acme.example/groups`, and the same for `OIDC_ROLE_CLAIM`,
  `OIDC_TENANT_CLAIM`, `OIDC_APPS_CLAIM`). The group claim is read whether it arrives as
  a JSON array or a delimited string.
- `OIDC_DEFAULT_ROLE=viewer` grants a role to **everyone the IdP authenticates**. That is
  a legitimate configuration when the IdP application is already restricted to the right
  people, and a serious widening otherwise - so it is off by default and startup warns
  when it is on.

**For machines, use static tokens** - CI jobs, an ingest sender, a scripted
integration. Give each one its own entry so it can be withdrawn alone, always set an
expiry, and store the hash rather than the value:

```bash
# token : role : tenant : expiry : apps      (sha256$… stores only the digest)
API_TOKENS='sha256$9f2b…:operator:acme:2026-12-31,sha256$41ac…:viewer:acme'
```

A token is any string that is hard to guess and contains no `:` or `,`; nothing is
registered anywhere. Generate one, keep only its digest in the configuration, and hand the
token itself to the client:

```bash
TOKEN=$(openssl rand -hex 32)                  # what the client sends: Authorization: Bearer $TOKEN
printf '%s' "$TOKEN" | sha256sum                # printf, not echo: a trailing newline changes the digest
                                                # (older macOS without sha256sum: shasum -a 256)
API_TOKENS='sha256$<that digest>:viewer:acme:2026-12-31'
```

**In a Compose `.env` file, keep the single quotes** (or write `sha256$$…`). Compose expands
`$` in `.env` values, so an unquoted `sha256$9f2b…` reaches the backend as `sha256:viewer`
with the digest gone - and all it says is a warning about an unset variable. Then check what
each token resolves to before handing it over:

```bash
curl -s -H "Authorization: Bearer $TOKEN" https://pg.example.com/auth/me
# 401                 → a wrong token, or its entry was dropped at startup (the log says why)
# "anonymous": true   → the API is not checking credentials at all
# anything else       → the role, tenant and apps this token grants
```

The honest limit: `API_TOKENS` is read **once at startup**. Withdrawing a static
token before its expiry means restarting the process (a rolling restart on
Kubernetes). That is acceptable for machine credentials on a scheduled rotation, and
it is the reason people should be on OIDC - where revocation is immediate and does
not involve this service at all.

## Container & compose hardening

The images and the compose stack are built to the bar you'd expect in a review:

- **Tiny, reproducible images.** The backend is a multi-stage build → a static
  (CGO-off, `-trimpath`, stripped) binary on `distroless/static:nonroot` - **~14 MB,
  no shell, no package manager, no root.** The dashboard is a Vite build served by
  nginx-alpine. Every base image (incl. Postgres/AGE, NATS, OpenSearch) is **pinned
  by SHA-256 digest**, not a floating tag - reproducible and tamper-evident.
- **Least privilege at runtime.** Every compose service sets
  `no-new-privileges:true`; the backend additionally runs `read_only: true`,
  `cap_drop: [ALL]`, non-root, with a `tmpfs` `/tmp` - it writes nothing to disk.
- **No accidental exposure.** All published ports bind to `127.0.0.1`, so a laptop
  demo never puts Postgres/NATS/OpenSearch/the API on the LAN. OpenSearch's demo
  security plugin is explicitly disabled only behind the opt-in `search` profile.
- **Real health gating.** The backend ships a `healthz` subcommand (the distroless
  image has no shell/curl) used as its Docker `HEALTHCHECK`; the dashboard waits on
  `condition: service_healthy`, which in turn waits on Postgres/NATS being healthy -
  so `make up-full` comes up in the right order, every time.
- **CI scans the supply chain** - `govulncheck`, `npm audit`, and a Trivy image scan
  gate the build, plus an **AGE store integration job** (Postgres+AGE service
  container) that exercises the real, hand-written Cypher path - including an
  injection round-trip - that unit tests with the in-memory store can't cover
  (see [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)).

### Application hardening

Beyond the container surface, the backend itself is built defensively:

- **Cypher injection defense (AGE store).** Values are wrapped in a *randomized*
  dollar-quote tag a value provably can't contain, single-quote-escaped, and
  labels/edge-types are validated against the ontology allowlist (graph names
  against a strict identifier pattern) - so attacker-influenceable scanner output
  (image tags, IAM role names, file paths) can never break out into SQL.
- **Per-IP rate limiting.** Token-bucket caps on the ingest webhook and the API
  (`INGEST_RATE_RPS` / `API_RATE_RPS`) blunt floods before any work is done.
- **Transport timeouts.** Both HTTP servers set explicit `ReadHeader`/`Read`/
  `Write`/`Idle` timeouts (Go's defaults are *none*), so slow-client / Slowloris
  connections can't pin resources; outbound clients (JWKS, forge APIs, webhooks)
  are timeout-bound with size-capped response reads.
- **CORS allowlist, not `*`.** `CORS_ALLOWED_ORIGINS` echoes only allow-listed
  browser origins (default: the dev/demo dashboards), so a page an analyst visits
  can't probe the API. **Fail-closed OIDC:** with `OIDC_JWKS_URL` set, the backend
  refuses to start without `OIDC_ISSUER` and `OIDC_AUDIENCE` (no unvalidated iss/aud).
- **Self-applied SAST.** CI runs `gosec` (static security analysis of the tool's
  own Go) and `gitleaks` (secret scan) alongside `govulncheck` + Trivy - a security
  tool held to the bar it sets.
- **At-rest encryption of its own sensitive-asset data.** `STORE_ENCRYPTION_KEY`
  encrypts the governance stores (suppressions/tickets/validations/history) **and
  the audit log** with AES-256-GCM, so a stolen volume or backup doesn't hand over
  the attack map plus who-viewed-it in plaintext. (Reads pre-encryption files
  transparently - a one-way migration.)
- **Signed exports.** With `EXPORT_SIGNING_KEY` (Ed25519) the OSCAL/SIEM exports
  carry a detached signature (`X-PerspectiveGraph-Signature`); a consumer fetches
  the public key at **`GET /export/pubkey`** and verifies integrity + origin.
- **Abuse detection on its own data.** Repeated failed auth from one IP triggers a
  temporary **lockout** (`AUTH_LOCKOUT_THRESHOLD`, HTTP 429); an unusual volume of
  attack-path reads/exports by one principal raises an **exfiltration alert**
  (`EXFIL_ALERT_THRESHOLD`) - both logged and written to the audit log.
- **Token lifecycle & object-level RBAC.** API tokens take an optional **expiry**
  (`token:role:tenant:YYYY-MM-DD`) and can be stored **hashed** (`sha256$<hex>`) so
  the live secret never sits at rest; a token (or OIDC `apps` claim) can be scoped
  to a set of **applications**, restricting *reads* (paths, graph, violations,
  exports, search) to those apps. It bounds **writes** too: the governance records -
  suppressions, tickets, validations - are keyed by attack-path id, and a scoped
  principal may only act on a path within its own applications. That half was missing
  and a self-assessment found it: the boards were scoped by tenant alone, so one team's
  admin could suppress another team's path - hiding a real finding from the people
  responsible for it. One residual is deliberate: the tenant-wide **calibration and
  precision/recall aggregates** are not scoped, because they measure the engine rather
  than any application and name nothing.
- **Fail-loud persistence.** `GRAPH_STRICT=true` refuses to start if Apache AGE is
  unreachable instead of silently falling back to the non-persistent in-memory
  store. Events that exhaust redelivery go to a **dead-letter stream**, not the void.
- **Large estates arrive whole.** An event over the bus's message limit (1 MiB on a
  default NATS) is split into chunks, nodes first; a large cluster or account used to be
  refused at ingest with a 502. The ingest response names the request's batch, and
  `ingestBatch(id)` says when all of it has reached the graph - the merge gate waits for
  that before it trusts a verdict.
- **Edges wait for their nodes.** An edge whose endpoint has not arrived - from another
  feed, or another chunk - is parked, and lands in the write that brings the endpoint.
  It used to be redelivered with its whole event for four minutes and then dropped.
  A parked edge waits up to 7 days; `perspectivegraph_graph_pending_edges` counts them.
- **A bounded bus.** A handled event leaves the stream as soon as it is acknowledged;
  `NATS_MAX_AGE` (default `168h`) caps how long an unhandled one waits, and how long a
  dead-lettered one is kept. A dropped connection is retried for as long as it takes,
  and a NATS that comes back empty gets its stream and consumer recreated.
- **No half-alive process.** A listener that cannot bind, or a bus connection or
  consumer that stops for good, ends the process with an error instead of a log line,
  so the orchestrator restarts it rather than routing to a replica that has lost part
  of itself.
- **Observability built in.** Prometheus metrics at **`GET /metrics`** (ingest /
  normalize / analyzer-pass timing / dead-letters / bus connection + Go runtime), so
  you don't operate it blind.
- **Throughput.** The AGE store uses a real connection pool (not a single pinned
  connection), writes each event in **one transaction**, and looks vertices up by id
  through a per-label index - so an event's cost grows linearly with its size (5,000
  nodes and edges each in under ten seconds on a laptop; see
  [SCALE.md](../SCALE.md#writing-an-event)).
- **Concurrent replicas converge.** Writes to one tenant's graph take a
  transaction-scoped advisory lock, so two replicas writing the same asset at once
  update one vertex instead of creating two.
- **Queryable graph, honest traversal.** Node and edge properties are stored as
  **native agtype** (the graph is queryable in Cypher, not a JSON blob). Path
  finding uses the **in-process Dijkstra by default** - polynomial and bounded. A
  DB-side Cypher finder is an **opt-in** (`ANALYZER_DB_PATHS`): since AGE has no
  weighted shortest-path it *enumerates* paths (unbounded worst-case), so it's
  safe-railed with a `statement_timeout` + `LIMIT` and falls back to Dijkstra on a
  runaway query. Legacy JSON-blob data is still read, so upgrades don't lose paths.
- **Replica-safe side-effects.** Run more than one backend replica and each still
  computes attack paths locally (warm API reads), but **at-most-once** external
  actions - drift webhooks and PR/MR comments - fire only from the **leader**,
  elected via a Postgres advisory lock with automatic failover. No duplicate
  notifications, no external coordinator.

> Hardening is layered, not absolute: the default Postgres password and open
> auth are deliberate **local-dev** defaults (the backend logs a loud warning).
> Set `POSTGRES_PASSWORD`, `INGEST_HMAC_SECRET` and `API_TOKENS`/OIDC before any
> shared or production deployment - see [`.env.example`](../../.env.example).
