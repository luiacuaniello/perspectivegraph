# Quick start

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Running the stack, feeding it sample data, and seeing the first attack path.

**See the wedge in ~90 seconds** - bring up the stack, seed it, and watch the
findings correlate into the top ranked attack path with its fix:

```bash
make demo           # needs Docker, curl and jq; then open http://localhost:3000
```

Nothing is compiled: it runs the **published, signed release images**
([`docker-compose.demo.yml`](../../docker-compose.demo.yml) overrides the two services that
would otherwise be built), so there is no Go or Node toolchain to install and no wait -
measured at 23 seconds from an empty image cache. `make demo-build` is the same demo from
your working tree, for when you are changing the code.

**Or step by step (everything in containers):**

```bash
make up-demo        # published images, no build
# or: make up-full  # builds infra + backend + dashboard from this tree
make seed           # feed the sample sources; they correlate into attack paths
open http://localhost:3000
```

`make up-full` brings up the whole stack - Postgres+AGE, NATS, the Go backend, and
the nginx-served dashboard on **:3000** (which proxies `/graphql` to the backend).
Tear it all down with `make down`. All ports bind to `127.0.0.1`; the backend runs
non-root on a read-only rootfs with every Linux capability dropped (see
[Container & compose hardening](security.md#container--compose-hardening)). The dashboard ships
**light & dark themes** - a header toggle (☀️/🌙) that remembers your choice and
follows the OS preference on first load.

**Or run the backend/frontend on the host (dev loop):**

```bash
# 1. Boot just the infrastructure (Postgres+AGE, NATS)
make up          # or: make up-search to also start the optional OpenSearch index

# 2. Run the backend (Go)
make run-backend

# 3. Run the frontend (React + Vite)
make run-frontend

# 4. Feed the sample scanner output; it correlates into attack paths
make seed
```

`make seed` posts eight sources - an infra/identity context, a Trivy report
(dependency CVEs), CI build provenance (image ↔ repository), supply-chain
provenance (cosign, SLSA, SBOM), a Semgrep report (SAST weaknesses), a Cloud
Custodian export (cloud infra/identity), a Falco runtime alert, and
data-classification findings (which assets hold sensitive data). They **correlate** into
multiple ranked attack paths to sensitive assets, for example:

- **Trivy** → `internet LB → container → image → log4j → Log4Shell → admin IAM role`
- **Semgrep** → `internet LB → container → image → repo → command-injection → customers PII DB`
- **Custodian** → `public ALB → EC2 → assumes admin role → S3 PII bucket`

The **Falco** alert on the payments container flips the paths through it to
⚡ *runtime-confirmed* (actively exploited, ranked first). The **policy engine**
flags forbidden shapes (e.g. *internet → sensitive asset*), and each path carries
generated **remediation** (a K8s NetworkPolicy or Terraform that cuts one edge).
