# Configuration reference

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Every setting the backend reads: its default, the Helm value that sets it, and whether you need it.

**Nothing here is required to start.** Every setting has a default, and `make demo` runs
with none of them set. Without credentials, the API and the ingestion endpoint are open and
the log says so on every start. That is what a demo needs, and it is not a deployment: the
next section lists what changes when real findings go into the graph.

## Where to set them

| You run it with | Where the settings go |
|---|---|
| Docker Compose | A `.env` file next to `docker-compose.yml`. Copy [`.env.example`](../../.env.example) (every key, with the reasons behind it) or, for production, [`.env.production.example`](../../.env.production.example). `docker-compose.yml` passes every key on this page to the backend; a variable set in the shell wins over the file. |
| Helm | The chart's values - the **Helm** column below. [`values-production.yaml`](../../deploy/helm/perspectivegraph/values-production.yaml) is the production starting point, and [`values-ha.yaml`](../../deploy/helm/perspectivegraph/values-ha.yaml) adds replicas. |
| The binary | Environment variables. The backend also reads a `.env` in its working directory and in the parent. |

**Secrets.** A setting marked *secret* below also accepts `<KEY>_FILE`: the path of a file
holding the value, so it never enters the process environment, where `docker inspect`,
`/proc/<pid>/environ` and crash dumps can read it. Under Compose,
[`docker-compose.secrets.yml`](../../docker-compose.secrets.yml) mounts them; under Helm,
`secrets.existingSecret` names a Secret you manage. A `_FILE` that is set but unreadable stops
the backend at startup rather than leaving it without the credential.

## The minimum for production

`PG_ENV=production` turns the first three rows into conditions of starting: the backend
refuses to run without them, so an open deployment cannot be reached by forgetting a
setting. The rest are not enforced, and the
[pre-production checklist](../OPERATIONS.md#10-pre-production-checklist) explains each one.

| What | Settings | With `PG_ENV=production` |
|---|---|---|
| API authentication | `API_TOKENS`, or `OIDC_JWKS_URL` + `OIDC_ISSUER` + `OIDC_AUDIENCE` | required |
| Ingest authentication | `INGEST_HMAC_SECRET` or `INGEST_HMAC_SECRETS` | required |
| A database it can reach | `POSTGRES_*` or `POSTGRES_DSN`, with Apache AGE | required: no fallback to an in-memory graph |
| Encryption in transit | `TLS_CERT_FILE` + `TLS_KEY_FILE` (or TLS at the proxy), `POSTGRES_SSLMODE=verify-full`, `NATS_TLS_*` | recommended |
| NATS credentials | `NATS_USER` + `NATS_PASSWORD` for a NATS you run yourself (the chart's has them) | recommended |
| State that survives a restart | `GOVERNANCE_BACKEND=postgres`, or the `*_PATH` settings on a volume; `AUDIT_LOG_PATH`, `AUDIT_RETENTION` | recommended |
| Encryption at rest | `STORE_ENCRYPTION_KEY` | recommended |
| The edge | `CORS_ALLOWED_ORIGINS` (your dashboard's origin), `TRUSTED_PROXY_CIDRS` (behind a proxy), `METRICS_ADDR` (off the API port) | recommended |
| Logs a pipeline can read | `LOG_FORMAT=json` | recommended |

Below, **Default** is what the backend uses when the variable is unset or empty, and **Helm** is
the chart value that sets it.

## Deployment profile

| Setting | What it does |
|---|---|
| `PG_ENV`<br>Default: `demo`<br>Helm: `backend.env` | `production` makes startup refuse an open API, open ingestion and a missing database (see above). It only ever adds checks, so it is safe anywhere that is not a demo. |

## Database: PostgreSQL + Apache AGE

The graph lives in PostgreSQL with the Apache AGE extension. [Operations](../OPERATIONS.md#3-the-database-postgresql--apache-age) says where you can get one; most managed services do not offer AGE.

With `postgres.cloudnativepg.enabled`, the chart sets these itself: the host is the
operator's `-rw` Service, the password comes from the Secret the operator generates, the
mode is `verify-full`, and libpq's own `PGSSLROOTCERT` points the driver at the operator's CA
([Kubernetes](kubernetes.md#a-production-database-cloudnativepg)).

| Setting | What it does |
|---|---|
| `POSTGRES_HOST`<br>Default: `localhost`<br>Helm: `postgres.externalHost` | The database host. The chart uses its own Postgres unless `postgres.enabled=false`. |
| `POSTGRES_PORT`<br>Default: `5432`<br>Helm: `postgres.externalPort` | The database port. |
| `POSTGRES_USER`<br>Default: `perspective`<br>Helm: `postgres.auth.user` | The database user. Beyond a demo, a role that is not a superuser ([Operations](../OPERATIONS.md#3-the-database-postgresql--apache-age)). |
| `POSTGRES_PASSWORD`<br>Default: `perspective`<br>Helm: `postgres.auth.password` | *Secret.* Change it beyond a demo. The chart generates one for its own Postgres and keeps it across upgrades. |
| `POSTGRES_DB`<br>Default: `perspectivegraph`<br>Helm: `postgres.auth.database` | The database name. |
| `POSTGRES_SSLMODE`<br>Default: `disable`<br>Helm: `postgres.sslMode` | libpq `sslmode`. The bundled Postgres has no TLS; for an external one use `require`, or `verify-full` to check the server's certificate too. |
| `POSTGRES_DSN`<br>Default: built from the keys above<br>Helm: `postgres.dsn` | *Secret.* A full libpq connection string. When set, the six keys above are ignored; use it for what they cannot say, such as `sslrootcert`. |
| `AGE_GRAPH_NAME`<br>Default: `perspective`<br>Helm: `postgres.graph` | The AGE graph, created on startup. |
| `GRAPH_STRICT`<br>Default: `false`<br>Helm: `backend.graphStrict` | Refuse to start when AGE is unreachable, instead of falling back to an in-memory graph that a restart loses. `PG_ENV=production` does the same. |

## Event bus: NATS JetStream

| Setting | What it does |
|---|---|
| `NATS_URL`<br>Default: `nats://localhost:4222`<br>Helm: `nats.externalUrl` | The chart uses its own NATS unless `nats.enabled=false`. Use `tls://` for a NATS that speaks TLS. |
| `NATS_STREAM`<br>Default: `PERSPECTIVE`<br>Helm: `nats.stream` | The JetStream stream the events go through. |
| `NATS_SUBJECT`<br>Default: `perspective.events.*`<br>Helm: `nats.subject` | The subjects the stream carries. |
| `NATS_MAX_AGE`<br>Default: `168h`<br>Helm: `nats.maxAge` | How long an unprocessed or dead-lettered event is kept. A handled event leaves at once, so this bounds a backlog, not a history. |
| `NATS_USER`<br>Default: none<br>Helm: `nats.auth.user` | Credentials for a NATS that requires them. Without them, anything that reaches the bus can publish onto it, past ingest authentication. |
| `NATS_PASSWORD`<br>Default: none<br>Helm: `nats.auth.password` | *Secret.* The chart generates one for its own NATS and keeps it across upgrades. |
| `NATS_TLS_CA`<br>Default: none<br>Helm: `nats.tls.enabled`, `nats.tls.secretName` | A private CA to trust. Leave the three TLS keys empty inside a service mesh, which encrypts the hop already. |
| `NATS_TLS_CERT`<br>Default: none<br>Helm: `nats.tls.secretName` | A client certificate, for mutual TLS. |
| `NATS_TLS_KEY`<br>Default: none<br>Helm: `nats.tls.secretName` | Its key. |

## Servers, TLS and logs

| Setting | What it does |
|---|---|
| `API_ADDR`<br>Default: `:8080`<br>Helm: `service.apiPort` | The GraphQL API and the dashboard's backend. |
| `INGEST_ADDR`<br>Default: `:8081`<br>Helm: `service.ingestPort` | The ingestion endpoint: the write side of the graph. Never publish it beyond the scanners that post to it. |
| `TLS_CERT_FILE`<br>Default: none<br>Helm: `backend.tls.enabled`, `backend.tls.secretName` | With `TLS_KEY_FILE`, both servers speak HTTPS (TLS 1.2 or later) themselves. Empty: plain HTTP, for TLS that ends at a proxy or ingress. |
| `TLS_KEY_FILE`<br>Default: none<br>Helm: `backend.tls.secretName` | The key for `TLS_CERT_FILE`. |
| `METRICS_ADDR`<br>Default: none<br>Helm: `backend.metricsAddr` | Moves Prometheus `/metrics` off the API port. Recommended in production: some series carry a `tenant` label, so on a reachable API port anyone can list the tenants. |
| `CORS_ALLOWED_ORIGINS`<br>Default: `http://localhost:5173,http://localhost:3000`<br>Helm: `backend.corsAllowedOrigins` | Browser origins allowed to call the API. Set your dashboard's origin in production; an empty value allows none, `*` allows any. |
| `TRUSTED_PROXY_CIDRS`<br>Default: none<br>Helm: `backend.trustedProxyCidrs` | The proxies in front of the backend, whose `X-Forwarded-For` is believed. Set it behind a proxy, or every request looks like the proxy's and one attacker's failed logins lock everyone out. Leave it empty without one. |
| `GRAPHQL_INTROSPECTION`<br>Default: follows authentication<br>Helm: `backend.graphqlIntrospection` | Whether the schema can be queried: on while the API is open, off once it needs a credential. `on` or `off` overrides it. |
| `LOG_LEVEL`<br>Default: `info`<br>Helm: `backend.logLevel` | `debug`, `info`, `warn` or `error`. |
| `LOG_FORMAT`<br>Default: `text`<br>Helm: `backend.logFormat` | `json` for a log pipeline. |

## Authentication and access

| Setting | What it does |
|---|---|
| `API_TOKENS`<br>Default: none<br>Helm: `auth.apiTokens` | *Secret.* Bearer tokens, comma-separated, each `token:role[:tenant[:expiry[:apps]]]`; the role is `viewer`, `operator` or `admin`. A token can be stored as `sha256$<hex>` so only its hash sits at rest. [Security](security.md) has the details. |
| `API_ANONYMOUS_ROLE`<br>Default: none<br>Helm: `auth.anonymousRole` | `viewer` publishes the instance read-only: a request with no credential gets that role instead of a 401. Writes stay admin-only. Only for data meant to be public. |
| `API_RATE_RPS`<br>Default: `60`<br>Helm: `auth.apiRateRps` | Requests per second per client IP on the API. `0` disables the limit. |
| `AUTH_LOCKOUT_THRESHOLD`<br>Default: `50`<br>Helm: `backend.authLockoutThreshold` | Failed logins from one IP within 5 minutes before it is locked out for 15. `0` disables it. |
| `OIDC_JWKS_URL`<br>Default: none<br>Helm: `auth.oidc.jwksUrl` | Turns on SSO: RS256 tokens are verified against these keys. Then `OIDC_ISSUER` and `OIDC_AUDIENCE` are required, and the backend refuses to start without them. |
| `OIDC_ISSUER`<br>Default: none<br>Helm: `auth.oidc.issuer` | The issuer the tokens must name. Required with `OIDC_JWKS_URL`. |
| `OIDC_AUDIENCE`<br>Default: none<br>Helm: `auth.oidc.audience` | The audience the tokens must carry. Required with `OIDC_JWKS_URL`. |
| `OIDC_CLIENT_ID`<br>Default: none<br>Helm: `auth.oidc.clientId` | With `OIDC_AUTHORIZE_URL`, shows "Sign in with SSO" on the dashboard. Not a secret. |
| `OIDC_AUTHORIZE_URL`<br>Default: none<br>Helm: `auth.oidc.authorizeUrl` | The IdP's authorization endpoint, where "Sign in with SSO" sends the browser. |
| `OIDC_TOKEN_URL`<br>Default: none<br>Helm: `auth.oidc.tokenUrl` | The IdP's token endpoint. When set, the dashboard uses Authorization Code with PKCE; the IdP must allow CORS from the dashboard's origin. |
| `OIDC_SCOPES`<br>Default: `openid profile email`<br>Helm: `auth.oidc.scopes` | The scopes the dashboard asks for at sign-in. |
| `OIDC_LOGOUT_URL`<br>Default: none<br>Helm: `auth.oidc.logoutUrl` | The IdP's end-session endpoint, so "Sign out" ends the IdP session too. |
| `OIDC_GROUP_ROLES`<br>Default: none<br>Helm: `auth.oidc.groupRoles` | Maps directory groups to roles, e.g. `pg-viewers=viewer,pg-admins=admin`. Without it or a role claim, a signed-in user gets no access. |
| `OIDC_DEFAULT_ROLE`<br>Default: none<br>Helm: `auth.oidc.defaultRole` | A role for every user the IdP signs in, mapped group or not. A deliberate widening, logged at startup. |
| `OIDC_ROLE_CLAIM`<br>Default: `role`<br>Helm: `auth.oidc.roleClaim` | Claim names, for directories that namespace them (Auth0 and Entra often do). |
| `OIDC_GROUPS_CLAIM`<br>Default: `groups`<br>Helm: `auth.oidc.groupsClaim` | The claim that lists a user's groups, read by `OIDC_GROUP_ROLES`. |
| `OIDC_TENANT_CLAIM`<br>Default: `tenant`<br>Helm: `auth.oidc.tenantClaim` | The claim naming the user's tenant. |
| `OIDC_APPS_CLAIM`<br>Default: `apps`<br>Helm: `auth.oidc.appsClaim` | The claim listing the applications a user may read, for access scoped to them. |

## Ingestion

| Setting | What it does |
|---|---|
| `INGEST_HMAC_SECRET`<br>Default: none<br>Helm: `ingest.hmacSecret` | *Secret.* Every ingest request must be signed with it ([how to sign](onboarding.md#authentication)). Required with `PG_ENV=production`. |
| `INGEST_HMAC_SECRETS`<br>Default: none<br>Helm: `ingest.hmacSecrets` | *Secret.* One secret per tenant, `tenant-a:secretA,tenant-b:secretB`; the `X-Tenant` header picks it. |
| `INGEST_HMAC_ACCEPT_V1`<br>Default: `true`<br>Helm: `ingest.hmacAcceptV1` | Whether the older signature over the body alone is still accepted. It can be replayed: set `false` once `perspectivegraph_ingest_signatures_total{version="v1"}` stays at zero. |
| `INGEST_RATE_RPS`<br>Default: `30`<br>Helm: `auth.ingestRateRps` | Requests per second per client IP on ingestion. `0` disables the limit. |
| `SCRUB_INGEST`<br>Default: `true`<br>Helm: `scrubIngest` | Redacts credentials that scanner output carries by accident (cloud keys, tokens, private keys) before they reach the graph. |

## Data protection and audit

| Setting | What it does |
|---|---|
| `STORE_ENCRYPTION_KEY`<br>Default: none<br>Helm: `crypto.storeEncryptionKey` | *Secret.* Encrypts the file-backed stores and the audit log at rest (AES-256-GCM). 64 hex characters are the key itself; anything else is a passphrase. Generate one with `openssl rand -hex 32`. |
| `EXPORT_SIGNING_KEY`<br>Default: none<br>Helm: `crypto.exportSigningKey` | *Secret.* Signs the OSCAL and SIEM exports (Ed25519); the public key is at `GET /export/pubkey`. |
| `AUDIT_LOG_PATH`<br>Default: none<br>Helm: `persistence.enabled` | The tamper-evident audit log: who changed, viewed or exported which attack paths. Empty: kept in memory only. |
| `AUDIT_RETENTION`<br>Default: kept forever<br>Helm: `auditRetention` | How long audit records are kept, e.g. `2160h` (90 days). Applies with `GOVERNANCE_BACKEND=postgres`; a file-backed log is rotated instead. |
| `EXFIL_ALERT_THRESHOLD`<br>Default: `0` (off)<br>Helm: `backend.exfilAlertThreshold` | Attack-path views or exports by one user within 5 minutes before an exfiltration alert. |

## Governance state

Suppressions, tickets, red-team verdicts and posture history. Each lives in memory unless one of these keeps it.

| Setting | What it does |
|---|---|
| `GOVERNANCE_BACKEND`<br>Default: `file`<br>Helm: `governanceBackend` | `postgres` keeps all of them in the database, shared by every replica, and ignores the paths below. `file` keeps each in its path: one writer, one replica. |
| `SUPPRESSIONS_PATH`<br>Default: none<br>Helm: `persistence.enabled` | Paths taken off the board, with owner and expiry. |
| `TICKETS_PATH`<br>Default: none<br>Helm: `persistence.enabled` | Remediation tickets, one open per path. |
| `VALIDATIONS_PATH`<br>Default: none<br>Helm: `persistence.enabled` | Red-team and BAS verdicts, the evidence behind the precision and recall the dashboard reports. |
| `HISTORY_PATH`<br>Default: none<br>Helm: `persistence.enabled` | Per-path first and last seen, MTTR and the posture trend. Without it, path ages start over on every restart. |
| `TICKET_WEBHOOK_URL`<br>Default: none<br>Helm: `ticket.webhookUrl` | *Secret.* Also posts each new ticket to a tracker (Jira, GitHub, a SOAR). |

## The graph and the analyzer

| Setting | What it does |
|---|---|
| `ANALYZER_INTERVAL`<br>Default: `30s`<br>Helm: `backend.analyzerInterval` | How often the attack paths are recomputed. |
| `ANALYZER_MAX_HOPS`<br>Default: `12`<br>Helm: `backend.analyzerMaxHops` | The longest path searched for. |
| `ANALYZER_WORKERS`<br>Default: `0` (one per CPU)<br>Helm: `backend.analyzerWorkers` | Parallel searches per pass. The result is the same either way; only the time changes. |
| `ANALYZER_INCREMENTAL`<br>Default: `false`<br>Helm: `backend.analyzerIncremental` | Keeps the graph in memory and reads only what changed each pass: less database load on a large graph, more memory. |
| `ANALYZER_DB_PATHS`<br>Default: `false`<br>Helm: `backend.analyzerDbPaths` | Computes paths in the database with Cypher instead of in process. Only for graphs known to be small: it enumerates paths. |
| `GRAPH_SWEEP`<br>Default: `true`<br>Helm: `graph.sweep` | A source that describes a scope in full retracts what it no longer lists: a fixed CVE or a terminated instance leaves the graph at the next scan. |
| `GRAPH_TTL`<br>Default: `0` (off)<br>Helm: `graph.ttl` | Removes what no source has reported within this window, e.g. `168h`. Set it to a few scan cycles. |
| `COVERAGE_STALE_AFTER`<br>Default: `24h`<br>Helm: `backend.coverageStaleAfter` | How long a source may stay silent before the dashboard reports it as stale, so an empty board is not mistaken for a safe one. |
| `SEED_IAM_USERS`<br>Default: `false`<br>Helm: `backend.seedIamUsers` | Also starts paths from IAM users, as if their keys had leaked, beside the paths from the internet. |
| `ATTACKER_PROFILE_PRIORS`<br>Default: `0.5` / `0.35` / `0.15`<br>Helm: `backend.attackerProfilePriors` | The weights of the commodity, criminal and APT attacker profiles that each path's score is averaged over ([scoring](scoring.md)). |
| `EPSS_TRAVERSAL_GAMMA`<br>Default: `1.0`<br>Helm: `backend.epssTraversalGamma` | Maps EPSS to the probability of crossing a hop as EPSS to this power; below 1 raises it. |

## Connectors: reading your cloud accounts

[Sources and integrations](integrations.md#agentless-connectors-pull-dont-wait-for-an-upload) has the permissions the AWS role needs.

| Setting | What it does |
|---|---|
| `CONNECTORS_ENABLED`<br>Default: none<br>Helm: `connectors.enabled` | `aws`, `azure`, `kubernetes`, comma-separated. Empty: data arrives only by ingestion. |
| `CONNECTOR_INTERVAL`<br>Default: `15m`<br>Helm: `connectors.interval` | How often each connector reads. |
| `CONNECTOR_TIMEOUT`<br>Default: `2m`<br>Helm: `connectors.timeout` | The longest one read may take. |
| `CONNECTOR_TENANT`<br>Default: the default tenant<br>Helm: `connectors.tenant` | The tenant whose graph the connectors feed. |
| `AWS_CONNECTOR_MODE`<br>Default: `fixtures`<br>Helm: `connectors.aws.mode` | `sdk` reads the live account; `fixtures` reads sample files, with no credentials. |
| `AWS_REGION`<br>Default: none<br>Helm: `connectors.aws.region` | The region the connector reads. |
| `AWS_ROLE_ARN`<br>Default: none<br>Helm: `connectors.aws.roleArn` | A read-only role to assume, or several, comma-separated, one per account. Without it, the connector uses the standard AWS credential chain directly. |
| `AWS_FIXTURES_DIR`<br>Default: none<br>Helm: `connectors.aws.fixturesDir` | Where `fixtures` mode reads from. |
| `AZURE_CONNECTOR_MODE`<br>Default: `fixtures`<br>Helm: `connectors.azure.mode` | Only `fixtures` is built so far. |
| `AZURE_FIXTURES_DIR`<br>Default: none<br>Helm: `connectors.azure.fixturesDir` | Where `fixtures` mode reads from. |
| `K8S_CONNECTOR_MODE`<br>Default: `incluster`<br>Helm: `connectors.kubernetes.mode` | `incluster` reads the cluster the backend runs in, with its service account (the chart grants it read access); `fixtures` reads a kubectl dump from disk. |
| `K8S_CLUSTER_NAME`<br>Default: none<br>Helm: `connectors.kubernetes.clusterName` | **Required for the Kubernetes connector.** Names repeat across clusters; on EKS it must be the EKS cluster's name, so its objects meet the AWS connector's. |
| `K8S_AWS_ACCOUNT`<br>Default: none<br>Helm: `connectors.kubernetes.awsAccount` | On EKS, the account the nodes run in, so a pod's escape to its node meets the instance the AWS connector reads. |
| `K8S_FIXTURES_DIR`<br>Default: none<br>Helm: `connectors.kubernetes.fixturesDir` | Where `fixtures` mode reads `k8s-sample.json` from. |

## Threat intelligence

| Setting | What it does |
|---|---|
| `THREATINTEL`<br>Default: off<br>Helm: `threatIntel.enabled` | Adds CISA KEV (exploited in the wild) and FIRST EPSS (likely to be) to every CVE, and weighs the paths through them accordingly. |
| `KEV_FEED_URL`<br>Default: the CISA feed<br>Helm: `threatIntel.kevFeedUrl` | A mirror, for an installation without internet access. |
| `EPSS_API_URL`<br>Default: the FIRST API<br>Helm: `threatIntel.epssApiUrl` | Likewise. |
| `KEV_HOLDOUT`<br>Default: off<br>Helm: `kevHoldout.enabled` | Needs `THREATINTEL`. Records a forecast for each CVE not yet exploited and grades it a window later against KEV: a calibration measure the engine cannot mark itself on. |
| `KEV_HOLDOUT_PATH`<br>Default: none<br>Helm: `kevHoldout.path` | Where forecasts wait to be graded. Without it they live in memory, and a restart before the window ends loses them. |
| `KEV_HOLDOUT_WINDOW`<br>Default: `720h`<br>Helm: `kevHoldout.window` | How long after a forecast it is graded: 30 days by default, the horizon EPSS itself forecasts over. |

## GitHub and GitLab

| Setting | What it does |
|---|---|
| `GITHUB_TOKEN`<br>Default: none<br>Helm: `github.token` | *Secret.* Pull request comments, the merge-gate commit status and fix pull requests. Empty: logged, not posted. |
| `GITHUB_API_URL`<br>Default: `https://api.github.com`<br>Helm: `github.apiUrl` | For GitHub Enterprise Server. |
| `GITHUB_DRY_RUN`<br>Default: `false`<br>Helm: `github.dryRun` | Logs instead of posting, even with a token. |
| `DASHBOARD_URL`<br>Default: none<br>Helm: `github.dashboardUrl` | Links the commit status back to the dashboard. |
| `GITLAB_TOKEN`<br>Default: none<br>Helm: `gitlab.token` | *Secret.* Merge request comments. Empty: logged, not posted. |
| `GITLAB_API_URL`<br>Default: `https://gitlab.com/api/v4`<br>Helm: `gitlab.apiUrl` | For a self-managed GitLab. |
| `GITLAB_DRY_RUN`<br>Default: `false`<br>Helm: `gitlab.dryRun` | Logs instead of posting, even with a token. |
| `REPO_ALLOWLIST`<br>Default: - (no writes)<br>Helm: `repoAllowlist` | The repositories the engine may write to, `owner/repo` or `owner/*`. **Required for any write**: the destination otherwise comes from ingested data, which anyone holding the ingest secret can plant. |
| `PR_ATTRIBUTION`<br>Default: `diff`<br>Helm: `prAttribution` | `diff` counts only the routes a change opened or made likelier; `commit` every route through what the commit touched. |

## Alerts and search

| Setting | What it does |
|---|---|
| `ALERT_WEBHOOK_URL`<br>Default: none<br>Helm: `alert.webhookUrl` | *Secret.* Posts an alert when a new attack path appears. |
| `ALERT_WEBHOOK_FORMAT`<br>Default: `slack`<br>Helm: `alert.webhookFormat` | `slack` (Slack, Mattermost) or `generic` (the raw JSON). |
| `OPENSEARCH_URL`<br>Default: none<br>Helm: `opensearch.url` | Full-text search over the graph. |

## AI assistant

Off unless a key is set. Each call sends a compacted view of the graph to the provider and is
recorded in the audit log ([AI assistant and MCP](ai-and-mcp.md)).

| Setting | What it does |
|---|---|
| `ANTHROPIC_API_KEY`<br>Default: none<br>Helm: `ai.apiKey` | *Secret.* Turns the assistant on with Claude. |
| `ANTHROPIC_MODEL`<br>Default: `claude-opus-5`<br>Helm: `ai.model` | The Claude model. |
| `ANTHROPIC_BASE_URL`<br>Default: `https://api.anthropic.com`<br>Helm: `ai.baseUrl` | For a proxy. |
| `AI_MAX_TOKENS`<br>Default: `4096`<br>Helm: `ai.maxTokens` | The longest answer, in tokens. |
| `AI_RATE_PER_MIN`<br>Default: `10`<br>Helm: `ai.ratePerMin` | Calls per minute per client, on top of `API_RATE_RPS`: each one is paid for. |
| `HF_TOKEN`<br>Default: none<br>Helm: `ai.hf.token` | *Secret.* Any OpenAI-compatible provider instead, used only without `ANTHROPIC_API_KEY`. `HUGGINGFACE_API_KEY` is accepted as an alias. |
| `HF_MODEL`<br>Default: `meta-llama/Llama-3.1-8B-Instruct`<br>Helm: `ai.hf.model` | A chat model the token can reach. |
| `HF_BASE_URL`<br>Default: `https://router.huggingface.co/v1`<br>Helm: `ai.hf.baseUrl` | Any OpenAI-compatible API: Together, Groq, a local Ollama. |
