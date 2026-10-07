# Deploy to Kubernetes

*Part of the [PerspectiveGraph manual](../MANUAL.md).* The Helm chart, a local cluster with the SSO demo, and hardening a real deployment.

A Helm chart bundles the backend, dashboard, Postgres+AGE, and NATS. It is published as
an OCI artifact, so installing it needs no clone of this repository - and gives you a
version you can pin, verify and name in a change record:

```bash
# Install a pinned release straight from the registry
helm install perspective oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  --set github.token=$GITHUB_TOKEN \
  --set opensearch.url="" \
  --version 1.33.0 # x-release-please-version
```

The chart is cosign-signed like the images. Verify it before it templates anything into
your cluster - a chart is a description of what will run with cluster credentials, so an
unverified one is a larger hole than an unverified image:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/luiacuaniello/perspectivegraph/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/luiacuaniello/charts/perspectivegraph:1.33.0 # x-release-please-version
```

The chart declares `kubeVersion: >= 1.21.0-0` (the floor is `policy/v1`
PodDisruptionBudget), so an older cluster is refused at install time rather than halfway
through. Working from a git checkout instead is still supported everywhere below - swap
the `oci://…` reference for `deploy/helm/perspectivegraph`:

```bash
helm install perspective deploy/helm/perspectivegraph \
  --set github.token=$GITHUB_TOKEN
```

Bring your own Postgres/NATS by disabling the bundled ones and pointing the chart at
the external endpoints. Read
[the database matrix](../OPERATIONS.md#3-the-database-postgresql--apache-age) before you
pick one: Apache AGE is a managed offering on Azure only, so on AWS and GCP "external"
means an instance you run.

```bash
helm install perspective deploy/helm/perspectivegraph \
  --set postgres.enabled=false \
  --set postgres.externalHost=my-postgres.example.internal \
  --set postgres.auth.user=perspective --set postgres.auth.password=… \
  --set nats.enabled=false \
  --set nats.externalUrl=nats://my-nats.example.internal:4222
```

The external Postgres must have the [Apache AGE](https://age.apache.org/)
extension installed and the graph created (see
[`deploy/postgres/init-age.sql`](../../deploy/postgres/init-age.sql)). All knobs:
[`deploy/helm/perspectivegraph/values.yaml`](../../deploy/helm/perspectivegraph/values.yaml).

## Local cluster (Docker Desktop / kind / minikube) + SSO demo

On a local cluster the images aren't on a registry, so build them and **load them
into the cluster** (its container runtime doesn't share the host Docker daemon):

```bash
make up-full && make down   # quickest way to build perspectivegraph-{backend,dashboard}:local

# Load into the cluster's containerd:
#   Docker Desktop:  docker save <img> | docker exec -i desktop-control-plane ctr -n k8s.io images import -
#   kind:            kind load docker-image <img>
#   minikube:        minikube image load <img>
```

Then install pointing at the local images (and, to try the **SSO login** end-to-end
against a bundled demo Keycloak, with the SSO overlay):

```bash
kubectl create namespace perspectivegraph
kubectl -n perspectivegraph create configmap keycloak-realm \
  --from-file=realm-demo.json=deploy/keycloak/realm-demo.json
kubectl -n perspectivegraph apply -f deploy/keycloak/k8s-keycloak-demo.yaml

helm install perspectivegraph deploy/helm/perspectivegraph \
  -n perspectivegraph -f deploy/helm/perspectivegraph/values-sso-demo.yaml

# Reach it (each in its own terminal): Keycloak for the browser, the dashboard,
# and the ingest port so `make seed` (which posts to localhost:8081) works.
kubectl -n perspectivegraph port-forward svc/keycloak 8088:8080
kubectl -n perspectivegraph port-forward svc/perspectivegraph-perspectivegraph-frontend 3000:80
kubectl -n perspectivegraph port-forward svc/perspectivegraph-perspectivegraph-backend 8081:8081
# open http://localhost:3000 → "Sign in with SSO" → demo / demo
make seed   # and make seed-discovery - they post to localhost:8081 (the ingest port)
```

Full walk-through (incl. why the OIDC URLs differ) in
[Trying SSO end-to-end on a laptop](security.md#trying-sso-end-to-end-on-a-laptop-the-bundled-keycloak).
Demo only: locally-built images + Keycloak in `start-dev`.

## Hardening a real deployment (beyond a trusted cluster)

The default chart runs **unauthenticated with in-memory governance** - fine for a
demo inside a trusted cluster, but this tool is a *map of how to attack the org*,
so anything reachable beyond that boundary must turn the controls on. The chart
surfaces them as first-class values:

```bash
helm install perspective deploy/helm/perspectivegraph \
  --set auth.apiTokens="$(openssl rand -hex 16):admin" \   # bearer auth on the API (token:role[:tenant])
  --set ingest.hmacSecret="$(openssl rand -hex 16)" \      # scanners must sign ingest bodies
  --set persistence.enabled=true \                         # PVC for the governance stores + audit log
  --set graph.ttl=168h \                                   # prune stale assets (phantom paths)
  --set networkPolicy.enabled=true                         # only the backend reaches NATS and Postgres
```

- **`auth.apiTokens` / `auth.oidc.*`** - without a token the API is open; set
  static tokens and/or OIDC (`issuer`/`audience`/`jwksUrl`). `auth.apiRateRps` /
  `auth.ingestRateRps` cap per-IP request rates (0 disables).
- **`ingest.hmacSecret` / `ingest.hmacSecrets`** - HMAC-sign ingestion so nobody
  can forge scanner data on the open ingest port.
- **`persistence.enabled`** - mounts a ReadWriteOnce PVC so suppressions, tickets,
  red-team validations, MTTR/posture history and the **tamper-evident audit log**
  survive restarts (in-memory and lost otherwise). `GOVERNANCE_BACKEND=postgres` moves
  **suppressions, tickets, history, validations and the KEV holdout** into the database,
  where every replica reads the same rows. The audit log stays a single-writer hash
  chain, so the chart **refuses to render with `backend.replicas > 1`** while persistence
  is on - scale-out would split-brain it.
- **The bus and the database authenticate on their own.** The bundled NATS requires a
  user and a password the chart generates into a Secret and hands the backend, so a pod
  that can reach port 4222 cannot publish events past the ingest signature check. The
  bundled Postgres gets a random password on install (an existing install keeps its
  own). Both are kept across `helm upgrade`; a `helm template` render (Argo CD, Flux)
  cannot read the cluster, so there set `postgres.auth.password` and
  `nats.auth.password` - or bring `secrets.existingSecret` and `nats.auth.existingSecret`.
- **`networkPolicy.enabled`** - only the backend may open a connection to the bundled
  NATS and Postgres; `networkPolicy.backendFrom` (the ingress controller's namespace,
  say) also closes the backend to the rest of the cluster. It needs a CNI that enforces
  NetworkPolicy - which is why NATS authenticates too.
- **`nats.persistence.enabled`** (default on) keeps the event stream on a volume, so a
  NATS restart does not lose queued events, dead letters, or the record a merge gate
  waits on.
- The release prints a ⚠ in `NOTES` whenever auth or persistence is left off, so
  an insecure exposure is never silent.
- **Startup ordering** - the backend has `initContainers` that block on the bundled
  Postgres:5432 and NATS:4222 before it boots, so a fresh install connects to
  Apache AGE on the first try instead of crash-looping on NATS or *silently* falling
  back to the in-memory graph when Postgres is slow. (External Postgres/NATS are
  assumed reachable and aren't gated.)

### Transport security (TLS) & data-in-transit

The app speaks plain HTTP by default and expects TLS to terminate **at the edge** -
turn it on, it isn't hardcoded off:

- **HTTPS at the ingress (recommended):** `--set ingress.tls.enabled=true
  --set ingress.tls.secretName=perspectivegraph-tls`, and let cert-manager issue
  the cert (`--set ingress.annotations."cert-manager\.io/cluster-issuer"=…`).
- **HTTPS in the pod (no proxy):** `--set backend.tls.enabled=true
  --set backend.tls.secretName=<kubernetes.io/tls secret>` - the API + ingest
  servers then serve TLS ≥ 1.2 directly (env `TLS_CERT_FILE`/`TLS_KEY_FILE` for the
  non-Helm/compose case).
- **Database in transit:** the connection carries the attack map, so for a
  managed/external Postgres set `--set postgres.sslMode=verify-full` (the chart
  already defaults an external DB to `require`); the bundled in-cluster DB stays
  `disable` since it has no TLS. Full control (CA path) via `POSTGRES_DSN` +
  `sslrootcert`.
- **NATS in transit:** point `NATS_URL` at a `tls://` endpoint; `NATS_TLS_CA`
  trusts a private CA and `NATS_TLS_CERT`/`NATS_TLS_KEY` add a client cert for
  **mutual TLS** (Helm: `--set nats.tls.enabled=true --set nats.tls.secretName=…`).
- **mTLS for all in-cluster traffic (the easy way):** run a **service mesh**
  (Linkerd / Istio) - it transparently mTLS-wraps every pod-to-pod hop (backend ↔
  Postgres ↔ NATS ↔ dashboard) with automatic cert rotation and **no app changes**;
  the per-component TLS knobs above are for when you *don't* run a mesh.
- **Secrets at rest:** the chart writes credentials to a Kubernetes `Secret`
  (base64, not encrypted in etcd by default). Either enable etcd encryption, or
  manage the Secret externally - `--set secrets.existingSecret=<name>` makes the
  chart **stop creating its own** and read a Secret you supply (External Secrets /
  Sealed Secrets / Vault). App-managed secrets are already encrypted at rest on
  disk via `STORE_ENCRYPTION_KEY`.

Every optional capability is wired through both `docker-compose.yml` (as
`${VAR:-}` passthroughs, off by default) and the chart, so a feature you enable in
code is actually reachable in the running stack:

- **Agentless connectors** - `--set connectors.enabled='{aws,azure}'` pulls cloud
  posture on a schedule (`connectors.interval`); the AWS connector runs from bundled
  fixtures unless `connectors.aws.mode=sdk` (then `connectors.aws.region` + an
  assumable read-only `connectors.aws.roleArn`); the Azure connector runs from
  fixtures (`connectors.azure.mode`), mapping normalized `az` state onto the
  `cloudnet` shape.
- **SSO login** - `auth.oidc.clientId` / `authorizeUrl` / `tokenUrl` / `scopes` are
  the SPA-facing coordinates the dashboard login gate reads from `GET /auth/config`
  to run the Authorization-Code + PKCE flow (the `issuer`/`audience`/`jwksUrl` trio
  above does the server-side token verification).
- **Dev workflow** - `github.token` turns the PR comment / merge-gate status and
  remediation-as-PR from dry-run into live; `github.dashboardUrl` is the link those
  comments point back to.
- **AI-native layer (Claude or HuggingFace)** - `ai.apiKey` (Anthropic) enables
  `/ai/*` (NL query, exec summary, path explain); empty keeps it self-gated off.
  `ai.hf.token` is the free OpenAI-compatible alternative, used when `ai.apiKey` is
  empty (`ai.hf.model`/`ai.hf.baseUrl` tune it). Both keys land in the Secret;
  `ai.model`/`baseUrl`/`maxTokens` are optional overrides.
- **Hardening** - `scrubIngest` (on by default) redacts secret-looking values out
  of scanner output before the store; `crypto.storeEncryptionKey` encrypts the
  file-backed governance stores at rest and `crypto.exportSigningKey` signs graph
  exports (both land in the Secret).
