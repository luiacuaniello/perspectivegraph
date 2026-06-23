# Demo: an attack path caught in the pull request - in 90 seconds

The wedge in one run: feed the security scanners you already use, watch them
correlate into a *real, reachable* internet → crown-jewel path, and turn the fix
into a pull request. This page is the script for trying it (and for recording a
short GIF).

## Prerequisites

- Docker (the stack runs in containers; ~4 GB free is comfortable).
- `jq` and `curl` (the demo prints the top path as JSON). `brew install jq`.
- ~2-3 minutes for the first run (it builds the images).

## One command

```bash
make demo
```

That target:

1. `up-full` - builds and starts the whole stack (Postgres+AGE, NATS, backend,
   dashboard on **:3000**).
2. Seeds the sample sources - Trivy CVEs, Semgrep SAST, Cloud Custodian, Falco
   runtime alerts, a Kubernetes dump, IAM authorization details, SSO federation,
   supply-chain provenance, data classification.
3. Waits for the analyzer to correlate them, then prints the **top attack path**:
   the kill chain (internet → … → crown jewel), its priority (P1/P2/P3), score,
   whether it's runtime-confirmed, and the **generated fix** (NetworkPolicy /
   Terraform / IAM policy).

You'll see something like:

```
════════ TOP ATTACK PATH  (internet → crown jewel, ranked) ════════
{
  "priorityLabel": "P1",
  "priority": 92.4,
  "score": 0.61,
  "runtimeConfirmed": true,
  "nodes": [ { "name": "payments-api ingress", "label": "Service" }, … ,
             { "name": "customer-exports", "label": "S3Bucket" } ],
  "remediations": [ { "title": "Deny lateral path", "kind": "NetworkPolicy", … } ]
}
```

Then open **http://localhost:3000** for the visual: the ranked paths, the kill
chain on the path detail, and the **Open fix PR** button.

## The 90-second story (for a recording)

1. **The noise** (5s): "Scanners give you 10,000 findings. Which one can actually
   reach something valuable?"
2. **`make demo`** (40s): the stack comes up, findings stream in, "correlating…",
   then the **one** ranked P1 path prints - internet → … → a crown jewel - with
   the fix attached.
3. **The dashboard** (30s): open `:3000`, click the top path, show the kill chain
   (each hop, runtime-confirmed in red), then click **Open fix PR**.
4. **The point** (15s): "It caught the reachable path and opened the fix as a PR -
   in the developer's workflow, not a runtime console months later."

Recording tips: a terminal + a browser side by side; tools like
[asciinema](https://asciinema.org) (terminal) or Kap/LICEcap (screen GIF). Keep
it under ~90s; the printed JSON + the kill-chain view are the money shots.

## Make "Open fix PR" a real pull request

By default the action layer runs **dry-run** (it logs what it would post). To open
an actual PR on a sandbox repo:

```bash
GITHUB_TOKEN=<token with pull_requests: write on a sandbox repo> \
DASHBOARD_URL=http://localhost:3000 \
  docker compose --profile app up -d backend
```

Then click **Open fix PR** on a path (or `POST /remediation/pr {"pathId":"…"}`).
It branches off the default branch, commits the generated fix, and opens the PR.
The same path context the analyzer carries (`repo_slug` / `pr_number` /
`commit_sha`, set when a scan is fed with PR context - e.g. the Trivy seed uses
`?slug=acme/payments-api&pr=42`) is what routes the comment + the **merge-gate
status** (`perspectivegraph/attack-paths`, red on an internet→crown-jewel path) to
the right PR. Make that status a *required* check in branch protection and the red
**blocks the merge**.

## Prove it on your own data

The sample seed is synthetic but realistic. To run it against a real environment,
point an agentless connector at a read-only cloud account
(`CONNECTORS_ENABLED=aws`, `AWS_CONNECTOR_MODE=live`, an assumable read-only role -
see the README) or POST your own scanner output to the ingest webhooks. The PR
gate and the ranked paths work the same way.

## Teardown

```bash
make down
```
