# Connect your own infrastructure

*Part of the [PerspectiveGraph manual](../MANUAL.md).* Where to run the engine for the AWS accounts and Kubernetes clusters you have, and how each of them reaches it.

The engine learns an estate in two ways. It **reads** some of it itself, read-only and on a
schedule: the AWS connector reads accounts, and the Kubernetes connector reads the cluster the
engine is installed in. Everything else is **sent** to it: other clusters, scanner reports and
the merge gate's pull requests, posted by `perspectivegraph ingest` or the GitHub Action. Where
the engine runs decides which of the two each source takes, so this page goes by place:

| | [On a laptop](#on-a-laptop) | [On one machine](#on-one-machine) | [On Kubernetes](#on-kubernetes) |
|---|---|---|---|
| **For** | a look at your own account, this afternoon | a team's instance, without a cluster | production beside your workloads |
| **Install** | `make up-aws` | `make prod-init DOMAIN=<name>` | the Helm chart |
| **AWS accounts** | read with your profile | read with the instance's role, or a profile | read with the pod's role (EKS Pod Identity or IRSA) |
| **The cluster it runs in** | - | - | read by the Kubernetes connector |
| **Other clusters** | a dump sent from the laptop | a dump sent by cron or CI | a dump sent by cron or CI |
| **Database** | bundled, throwaway | bundled, dumped daily, restore tested | CloudNativePG: replicas, failover, point-in-time recovery |

Whatever the place, the account is read through **one role**: [`deploy/aws`](../../deploy/aws/readonly-role.cfn.yaml)
has it as CloudFormation and as Terraform - the AWS-managed `SecurityAudit` policy, two EKS
Pod Identity reads, nothing that writes - and [the read-only role](integrations.md#the-read-only-role)
says who may assume it in each case. Deploy it in every account you want read.

The engine does not scan anything. Image and code findings come from the scanners you already
run (Trivy, Semgrep, Falco, Cloud Custodian), sent as they are: the
[onboarding runbook](onboarding.md) has a recipe for each, and the order that builds a correct
graph.

## On a laptop

For your own account, today, with nothing deployed: Docker, a clone of the repository at the
release, and an AWS profile.

```bash
git clone --branch v1.37.0 https://github.com/luiacuaniello/perspectivegraph.git # x-release-please-version
cd perspectivegraph
AWS_PROFILE=<profile> AWS_REGION=eu-west-1 make up-aws
```

`make up-aws` runs the published images with your `~/.aws` mounted read-only, checks first
that the backend can read it, and waits for the first pull of the account. Better still, read
as the role rather than as yourself: deploy it with `TrustedPrincipalArn` set to your user or
role, and add `AWS_ROLE_ARN=<the role's ARN>` to the command. The details, SSO profiles and
Linux included, are in [From your own machine](integrations.md#from-your-own-machine-make-up-aws).
The dashboard is on http://localhost:3000.

**A cluster**, from the same laptop: dump it with `kubectl` and send the dump. The CLI is a
single binary from the [releases page](https://github.com/luiacuaniello/perspectivegraph/releases/latest),
and it posts to the local stack by default:

```bash
kubectl get ingress,service,pod,serviceaccount,role,clusterrole,rolebinding,clusterrolebinding,node -A -o json |
  perspectivegraph ingest -cluster prod-eu -snapshot cluster:prod-eu k8s -
```

On EKS, name the cluster by its EKS name: that is how its pods meet the Pod Identity
associations and access entries the AWS connector reads, so a route can run from a pod into
the account. `-snapshot` says the dump is the whole cluster, so what it no longer holds next
time leaves the graph.

This stack is the demo profile: no credentials, and nothing published beyond `127.0.0.1`. It
holds your account's attack paths, so keep it there, and erase it when you are done:
`docker compose -f docker-compose.yml -f docker-compose.demo.yml --profile app down -v`.

## On one machine

`make prod-init DOMAIN=<name>` on a VM with Docker sets up the rest: TLS that renews itself,
every credential generated into files, the backend refusing to start without them, NATS with
a password, a daily backup and a restore tested in CI on every change. [Production on one
machine](single-vm.md) is the whole procedure. Then connect the estate:

**AWS, from an EC2 instance.** The backend reads the account with the instance's own role: add
the read-only policy to that role, or deploy the read-only role trusting it and set
`AWS_ROLE_ARN`. Add to `.env`, then `docker compose up -d`:

```bash
CONNECTORS_ENABLED=aws
AWS_CONNECTOR_MODE=sdk
AWS_REGION=eu-west-1
# AWS_ROLE_ARN=arn:aws:iam::111111111111:role/PerspectiveGraphReadOnly
```

The backend is a container, one network hop further from the instance metadata service than
the instance itself, and IMDSv2's default hop limit of 1 drops its answers. Raise it to 2,
keeping tokens required:

```bash
aws ec2 modify-instance-metadata-options --instance-id <id> \
  --http-tokens required --http-put-response-hop-limit 2
```

**AWS, from a machine elsewhere** - another cloud, a server of your own. Append
`:docker-compose.aws.yml` to `COMPOSE_FILE` in `.env`, and the backend reads with a profile from
the `~/.aws` of the user who runs `docker compose`, mounted read-only.

**Clusters** are sent, from wherever `kubectl` reaches them - a CI job, or cron on a bastion.
The address is the machine's, `/ingest` behind Caddy, and the secret is the one `prod-init`
generated (`secrets/ingest_hmac_secret`):

```bash
# crontab: every 30 minutes
*/30 * * * * kubectl get ingress,service,pod,serviceaccount,role,clusterrole,rolebinding,clusterrolebinding,node -A -o json | INGEST_HMAC_SECRET_FILE=/etc/perspectivegraph/ingest_hmac_secret perspectivegraph ingest -url https://perspectivegraph.example.com -cluster prod-eu -snapshot cluster:prod-eu k8s -
```

**Pull requests** get their verdict from the [merge gate](ci-gate.md), pointed at the same
address.

## On Kubernetes

### On EKS, with its AWS account

The engine runs beside the workloads it reads: the Kubernetes connector reads the cluster, the
AWS connector reads the account with a role bound to the backend alone, and the database is
run by CloudNativePG with replicas and continuous backups. Four steps, the first two once per
cluster.

**1. The CloudNativePG operator** - and, for backups, its Barman Cloud plugin and a bucket:
[A production database](kubernetes.md#a-production-database-cloudnativepg) has both.

```bash
kubectl apply --server-side -f \
  https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v1.30.1/cnpg-1.30.1.yaml
```

**2. The read-only role, for the backend's service account.** EKS Pod Identity needs its
agent on the cluster. The association names the service account the chart creates,
`<release>-perspectivegraph-backend`, and can be made before the install:

```bash
aws eks create-addon --cluster-name prod-eu --addon-name eks-pod-identity-agent
aws cloudformation deploy --stack-name perspectivegraph-readonly \
  --template-file deploy/aws/readonly-role.cfn.yaml --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustEksPodIdentity=true
aws eks create-pod-identity-association --cluster-name prod-eu \
  --namespace perspectivegraph --service-account perspective-perspectivegraph-backend \
  --role-arn <the stack's RoleArn output>
```

IRSA works too: let the role trust the cluster's OIDC provider instead, and put its ARN in
`serviceAccount.annotations`.

**3. The chart**, from the production profile it ships with:

```bash
helm pull oci://ghcr.io/luiacuaniello/charts/perspectivegraph --untar \
  --version 1.37.0 # x-release-please-version
helm install perspective oci://ghcr.io/luiacuaniello/charts/perspectivegraph \
  --namespace perspectivegraph --create-namespace \
  -f perspectivegraph/values-production.yaml \
  --set secrets.existingSecret= --set secrets.generate=true \
  --set postgres.cloudnativepg.enabled=true \
  --set governanceBackend=postgres \
  --set 'connectors.enabled={aws,kubernetes}' \
  --set connectors.aws.mode=sdk --set connectors.aws.region=eu-west-1 \
  --set connectors.kubernetes.clusterName=prod-eu \
  --set-string connectors.kubernetes.awsAccount=111111111111 \
  --set ingress.enabled=true --set ingress.host=perspectivegraph.example.com \
  --set ingress.tls.enabled=true \
  --set-string 'ingress.annotations.cert-manager\.io/cluster-issuer=letsencrypt-prod' \
  --set backend.trustedProxyCidrs=10.0.0.0/16 \
  --version 1.37.0 # x-release-please-version
```

What each line does:

- `values-production.yaml` is the hardened profile: `PG_ENV=production`, network policies, a
  verified TLS connection to the database. `secrets.generate` fills every credential it needs -
  an admin token, the ingest secret, the at-rest encryption key - and keeps them across
  upgrades; the release notes print how to read the token and the ingest secret back. Back the
  Secret up: its encryption key is the only key to the encrypted stores. Under Argo CD or Flux,
  which render without the cluster, bring the Secret yourself instead
  ([why](kubernetes.md#hardening-a-real-deployment-beyond-a-trusted-cluster)).
- `postgres.cloudnativepg.enabled` hands the database to the operator, and
  `governanceBackend=postgres` puts triage, tickets, verdicts and the audit chain in it, so
  they have its replicas and backups too. Add `postgres.cloudnativepg.backup.objectStore` once
  the bucket exists - without it there are no backups, and the release notes say so.
- `connectors.kubernetes.clusterName` is the EKS cluster's name, and `awsAccount` the
  account its nodes run in. It is a string: `--set` would read the account id as a number,
  which the chart's schema refuses.
- `connectors.aws` reads the account with the role from step 2, with no keys anywhere.
- The ingress publishes the dashboard, the API and `/ingest` - the chart refuses to publish
  them without credentials. `backend.trustedProxyCidrs` is where the ingress controller
  connects from (on EKS, pod addresses come from the VPC), so rate limits and lockouts count
  each client rather than the controller.

**4. Check it reads**:

```bash
kubectl -n perspectivegraph port-forward svc/perspective-perspectivegraph-backend 8081:8081 &
curl -s localhost:8081/connectors
```

Each connector reports its last run, whether it succeeded, the error if not, and how many
events it produced. A Pod Identity that is not working shows here as a credentials error from
the AWS connector, not as an empty board.

### Any other Kubernetes

GKE, AKS, a cluster of your own: the same chart. The Kubernetes connector reads any cluster,
and CloudNativePG runs on any of them - leave out the AWS lines, and keep the operator for the
database: Apache AGE is a managed offering on Azure alone
([the database matrix](../OPERATIONS.md#3-the-database-postgresql--apache-age)). Of the clouds
themselves, only AWS is read live today: the Azure connector reads exported files, and there is
no GCP connector.

### More clusters and more accounts

**Clusters.** The connector reads the cluster the engine runs in. Every other cluster sends
its dump, from a job that can read it - the same `kubectl get … | perspectivegraph ingest`
as above, with `-url https://perspectivegraph.example.com`, its own `-cluster` name and the
ingest secret from the chart's Secret.

**Accounts.** One role in each account, all trusting the backend's own role; on that role,
`AssumableRoleArns` lists them ([the role's table](integrations.md#the-read-only-role)). Then
name them all, comma-separated - escaped, because `--set` splits on commas:

```bash
--set 'connectors.aws.roleArn=arn:aws:iam::111111111111:role/PerspectiveGraphReadOnly\,arn:aws:iam::222222222222:role/PerspectiveGraphReadOnly'
```

Each account's assets are qualified with its id, so two accounts that reuse an identifier stay
two, and one account whose role fails costs that account alone.

## Is it connected?

Two questions, and an empty board answers neither.

**Did each connector read?** `GET /connectors` on the ingest port, as above - on one machine,
`docker compose exec frontend wget -qO- http://backend:8081/connectors`.

**What has been fed, and how recently?** `ingestCoverage`, with any API token:

```bash
curl -s https://perspectivegraph.example.com/graphql -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"query":"{ ingestCoverage { source events nodes lastSeen stale } }"}'
```

A source that is missing, or `stale`, is a feed to fix, not a finding. The first attack paths
appear after the next analyzer pass once a scanner report and the topology it sits in have both
arrived - [the order that builds a correct graph](onboarding.md#1-the-order-that-builds-a-correct-graph)
says which is which.
