.DEFAULT_GOAL := help
.PHONY: help up up-full demo up-search down logs run-backend build-backend test bench bench-cloudgoat mcp tidy run-frontend install-frontend seed seed-discovery seed-load clean

# CGO is disabled so the Go binaries link statically (Go's pure-Go DNS resolver
# instead of the system one). This also sidesteps a macOS system-linker bug on
# recent Darwin releases. All dependencies are pure Go, so nothing is lost.
GO := CGO_ENABLED=0 go

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F': ' '{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## up: start infra (Postgres+AGE, NATS) via docker compose
up:
	docker compose up -d postgres nats

## up-full: build + run the WHOLE stack in containers (infra + backend + dashboard on :3000)
up-full:
	docker compose --profile app up -d --build

## demo: the wedge in ~90s - bring up the stack, seed it, and surface the top attack path + its generated fix (needs jq)
demo: up-full
	@echo ""
	@echo "→ feeding sample scanner output (Trivy, Semgrep, Custodian, Falco, K8s, IAM, SSO, supply-chain, data-class)…"
	@$(MAKE) --no-print-directory seed          >/dev/null 2>&1 || true
	@$(MAKE) --no-print-directory seed-discovery >/dev/null 2>&1 || true
	@printf "→ correlating findings into reachable attack paths"
	@for i in $$(seq 1 30); do \
	  n=$$(curl -s -X POST http://localhost:8080/graphql -H 'Content-Type: application/json' \
	    -d '{"query":"{ attackPaths(limit:1){ id } }"}' 2>/dev/null | jq -r '.data.attackPaths | length' 2>/dev/null); \
	  if [ "$$n" = "1" ]; then break; fi; printf "."; sleep 3; \
	done; echo ""
	@echo ""
	@echo "════════ TOP ATTACK PATH  (internet → crown jewel, ranked) ════════"
	@curl -s -X POST http://localhost:8080/graphql -H 'Content-Type: application/json' \
	  -d '{"query":"{ attackPaths(limit:1){ priorityLabel priority score runtimeConfirmed nodes{ name label } remediations{ title kind filename } } }"}' \
	  | jq '.data.attackPaths[0]'
	@echo ""
	@echo "→ Open the dashboard: http://localhost:3000  (see the kill chain, then click 'Open fix PR')"
	@echo "  Make the fix a REAL pull request: set GITHUB_TOKEN on a sandbox repo - see DEMO.md."
	@echo "  Tear down when done: make down"

## up-search: start infra plus the optional OpenSearch full-text index
up-search:
	docker compose --profile search up -d

## down: stop and remove the WHOLE stack (infra + app + optional search/sso profiles)
down:
	docker compose --profile app --profile search --profile sso down

## logs: tail infra logs
logs:
	docker compose logs -f

## tidy: resolve Go module dependencies
tidy:
	cd backend && go mod tidy

## build-backend: compile the perspectivegraph binary
build-backend:
	cd backend && $(GO) build -o bin/perspectivegraph ./cmd/perspectivegraph

## run-backend: run the backend (all layers) locally
run-backend:
	cd backend && $(GO) run ./cmd/perspectivegraph

## test: run Go tests
test:
	cd backend && $(GO) test ./...

## bench: run the analyzer scaling benchmarks (pathfinding cost + parallel speedup)
bench:
	cd backend && $(GO) test ./internal/analyzer -run '^$$' -bench 'BenchmarkFindCriticalPaths|BenchmarkPathfindWorkers' -benchmem

## mcp: serve the engine as MCP tools on stdio, so an AI agent can query it (point an MCP client at this command). Needs the stack up.
mcp:
	cd backend && $(GO) run ./cmd/perspectivegraph mcp --api $(or $(API),http://localhost:8080)

## bench-cloudgoat: grade the attack-path engine against CloudGoat-shaped ground-truth scenarios (precision/recall). Runs in CI under `make test`; this target prints the per-scenario table. Add scenarios under backend/testdata/cloudgoat (see its README).
bench-cloudgoat:
	cd backend && $(GO) test ./internal/benchmark -run TestCloudGoatBenchmark -v

## fuzz: fuzz the collector parse boundary (attacker-influenceable input) for panics/OOM. Runs every FuzzXxx briefly (FUZZTIME per target, default 20s). Deep run: cd backend && go test ./internal/ingestion/fuzz -run x -fuzz FuzzCloudnet -fuzztime 5m
fuzz:
	@cd backend && for t in FuzzCloudnet FuzzIAM FuzzK8s FuzzTrivy FuzzSemgrep FuzzFalco FuzzCustodian FuzzSupplychain FuzzSSO FuzzDataclass FuzzBuild; do \
	  echo "== $$t =="; $(GO) test ./internal/ingestion/fuzz -run x -fuzz $$t -fuzztime $(or $(FUZZTIME),20s) || exit 1; \
	done

## install-frontend: install dashboard dependencies
install-frontend:
	cd frontend && npm install

## run-frontend: start the Vite dev server
run-frontend:
	cd frontend && npm run dev

## seed: feed six sample sources (context, Trivy, build provenance, Semgrep, Custodian, Falco) that correlate into ranked attack paths
seed:
	@echo "→ posting infra/identity context (cloud + runtime stand-in)"
	curl -sS -X POST http://localhost:8081/ingest/events \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/context.json | jq .
	@echo "→ posting Trivy report (dependency CVEs)"
	curl -sS -X POST 'http://localhost:8081/ingest/trivy?slug=acme/payments-api&pr=42&sha=deadbeef' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/trivy-sample.json | jq .
	@echo "→ posting CI build provenance (image ↔ repository)"
	curl -sS -X POST 'http://localhost:8081/ingest/build' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/build-sample.json | jq .
	@echo "→ posting supply-chain provenance (cosign/SLSA/SBOM; image is unsigned → policy violation)"
	curl -sS -X POST 'http://localhost:8081/ingest/supplychain' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/supplychain-sample.json | jq .
	@echo "→ posting Semgrep report (SAST code weaknesses)"
	curl -sS -X POST 'http://localhost:8081/ingest/semgrep?repo=payments-api&slug=acme/payments-api&pr=42&sha=deadbeef' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/semgrep-sample.json | jq .
	@echo "→ posting Cloud Custodian export (cloud infra/identity)"
	curl -sS -X POST 'http://localhost:8081/ingest/custodian' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/custodian-sample.json | jq .
	@echo "→ posting Falco alerts (runtime, marks the path actively exploited)"
	curl -sS -X POST 'http://localhost:8081/ingest/falco' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/falco-sample.json | jq .
	@echo "→ posting data-classification (Macie/DLP; upgrades customer-exports to an authoritative crown jewel)"
	curl -sS -X POST 'http://localhost:8081/ingest/dataclass' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/dataclass-sample.json | jq .
	@echo "→ open the dashboard or query: { attackPaths { id score runtimeConfirmed nodes { name label } } }"

## seed-discovery: feed a K8s dump + cloud-network export + IAM authorization details; topology & privesc auto-discovered (no hand-stitched ids)
seed-discovery:
	@echo "→ posting Kubernetes dump (Ingress/Service/Pod/SA/RBAC → exposure topology)"
	curl -sS -X POST 'http://localhost:8081/ingest/k8s' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/k8s-sample.json | jq .
	@echo "→ posting cloud-network export (security groups / VPC peering → reachability)"
	curl -sS -X POST 'http://localhost:8081/ingest/cloudnet' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/cloudnet-sample.json | jq .
	@echo "→ posting IAM authorization details (get-account-authorization-details → privilege-escalation graph)"
	curl -sS -X POST 'http://localhost:8081/ingest/iam' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/iam-sample.json | jq .
	@echo "→ posting SSO/IdP federation (Okta → cloud roles; no-MFA user → admin role)"
	curl -sS -X POST 'http://localhost:8081/ingest/sso' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/sso-sample.json | jq .
	@echo "→ discovered paths: internet → Ingress → Pod → ServiceAccount → cluster-admin (deep RBAC: create-pods/secrets/bind too),"
	@echo "  internet → web → PII db, internet → public-deployer → CAN_ESCALATE_TO → account-admin (IAM privesc),"
	@echo "  and internet → Okta → no-MFA user → federated admin-role → account-admin (SSO federation)"

## seed-validation: record sample red-team/BAS verdicts on every current path (outcome correlated with the predicted score, plus a detection report on confirmed ones) so precision/recall AND the calibration panel + diagnostics (Brier/ECE, segments, detection, diagnosis) light up
seed-validation:
	@echo "→ recording scored red-team/BAS verdicts on every path → precision/recall + calibration diagnostics"
	@for i in $$(seq 1 20); do \
	  pairs=$$(curl -sS -X POST http://localhost:8080/graphql -H 'Content-Type: application/json' \
	    -d '{"query":"{ attackPaths{ id score } }"}' | jq -r '.data.attackPaths[] | "\(.id)\t\(.score)"'); \
	  if [ -n "$$pairs" ]; then break; fi; \
	  echo "  waiting for the analyzer to surface attack paths…"; sleep 3; \
	done; \
	if [ -z "$$pairs" ]; then echo "  ✗ no attack paths yet - run 'make seed' (and give the analyzer a cycle) first"; exit 1; fi; \
	printf '%s\n' "$$pairs" | while IFS="$$(printf '\t')" read -r id score; do \
	  [ -z "$$id" ] && continue; \
	  outcome=$$(awk -v s="$$score" 'BEGIN{print (s>=0.5)?"confirmed":"refuted"}'); \
	  body="{\"pathId\":\"$$id\",\"outcome\":\"$$outcome\",\"source\":\"caldera-bas\",\"evidence\":\"atomic test run\""; \
	  if [ "$$outcome" = "confirmed" ]; then \
	    det=$$(awk -v s="$$score" 'BEGIN{print (s>=0.88)?"true":"false"}'); \
	    body="$$body,\"detected\":$$det"; \
	  fi; \
	  curl -sS -X POST http://localhost:8080/validations -H 'Content-Type: application/json' -d "$$body}" >/dev/null; \
	done; \
	curl -sS -X POST http://localhost:8080/validations -H 'Content-Type: application/json' \
	  -d '{"outcome":"missed","source":"red-team","route":"Okta → SaaS → data export (engine missed it)"}' >/dev/null; \
	echo "  done - Overview ‘Calibration’ panel now shows segments, detection and a diagnosis:"; \
	curl -sS http://localhost:8080/validations | jq -c '.calibration | {samples,brier,brier_recalibrated,verdict,diagnosis}'

## seed-load: generate a large synthetic graph and POST it to ingest (scale demo)
seed-load:
	cd backend && $(GO) run ./cmd/perspectivegraph genload --seeds 32 --jewels 16 --layers 8 --width 500 --fanout 4

## scale-test: characterize the analyzer at a target graph size - generate a large synthetic graph, wait for a full analyzer pass, and report graph size + per-pass timing from /metrics. Tune with SEEDS/JEWELS/LAYERS/WIDTH/FANOUT; set ANALYZER_WORKERS on the backend for parallel pathfinding. Needs the stack up. See docs/SCALE.md.
scale-test:
	@bash scripts/scale-test.sh

## calibration-selftest: exercise + TEST the calibration diagnostics WITHOUT real infra. Draws verdicts from a known reality (SCENARIO=calibrated|overconfident|underconfident|correlated|low-resolution|detection) and prints the diagnosis it should produce. e.g. make calibration-selftest SCENARIO=correlated
calibration-selftest:
	cd backend && $(GO) run ./cmd/perspectivegraph genverdicts --scenario $(or $(SCENARIO),calibrated) --count $(or $(COUNT),500) --reset
	@echo "→ diagnosis for scenario '$(or $(SCENARIO),calibrated)':"
	@curl -sS http://localhost:8080/validations | jq -c '.calibration | {samples,verdict,brier,brier_recalibrated,diagnosis}'

## import-verdicts: bridge a REAL red-team/BAS run into the calibration loop - map a tool-agnostic attack report (FILE=<report.json>, default the sample) onto the engine's live paths and record the verdicts. This is the on-ramp from a vulnerable target (CloudGoat via the AWS connector, a local Juice Shop, a manual pentest) to real calibration.
import-verdicts:
	cd backend && $(GO) run ./cmd/perspectivegraph importverdicts --file $(or $(FILE),testdata/bas-report-sample.json)
	@echo "→ precision/recall + calibration after import:"
	@curl -sS http://localhost:8080/validations | jq -c '{metrics: .metrics, calibration: (.calibration | {samples,verdict,diagnosis,detection})}'

## validate-harness: repeatable REAL-verdict loop with no circularity - bring up a genuinely-exploitable log4shell app, let the engine surface the path, EXPLOIT the live app, and take the verdict from an independent oracle (did the app make the JNDI callback?). Records confirmed/refuted with the path's server-captured predicted score -> calibration. Override TARGET_IMAGE=... to point at a patched image (harvests honest 'refuted') or another target. Needs docker + the stack up.
validate-harness:
	@bash scripts/validate-harness.sh

## validate-harness-k8s: REAL-topology verdict loop - stand up a kind cluster with two misconfigured RBAC scenarios, let the k8s collector DISCOVER the paths (real scores, not modelled), then exploit each and take the verdict from the Kubernetes API server's own RBAC decision (reader=confirmed, webapp=refuted false-positive). SUFFIX=<x> makes distinct samples to accumulate; DELETE_CLUSTER=1 tears the cluster down. Needs kind + the stack up.
validate-harness-k8s:
	@bash scripts/validate-harness-k8s.sh

## validate-harness-aws: real-topology calibration on a LIVE AWS account using a CloudGoat scenario as independent ground truth. Briefly opens the scenario instance's SG to 0.0.0.0/0 so the engine sees a seed, snapshots the topology read-only, closes the window (an EXIT trap re-closes it even on failure), scores the path, and records your exploit's outcome (OUTCOME=confirmed|refuted). YOU deploy/destroy the scenario. Needs: CONFIRM=i-understand-internet-exposure, REGION, ROLE_ARN, an admin AWS_PROFILE, the stack up. See scripts/validate-harness-aws.sh.
validate-harness-aws:
	@bash scripts/validate-harness-aws.sh

## validate-aws: run the LIVE AWS connector against a REAL read-only account (describe-* only, no writes) and print what it discovered - the internet-exposed seeds vs the SG-open instances the route/NACL layer SUPPRESSED (naming why). The first-contact check for reachability precision on real data. AWS_REGION=<region> required; ROLE_ARN=<arn> assumes a cross-account read-only role; INGEST_URL=<url> also pushes into a running stack for full path scoring. Read-only grant: SecurityAudit or ViewOnlyAccess. Needs AWS creds in the environment.
validate-aws:
	@bash scripts/validate-aws-readonly.sh

## ingest-real: zero-cost REAL ingest - Trivy-scan a genuinely vulnerable image (IMAGE=<image>, e.g. the running vulhub log4shell image) and wire the minimal topology so the real CVE sits on an internet->sensitive-asset path (real CVSS; real KEV/EPSS with THREATINTEL=on). REPORT=<trivy.json> uses a saved report instead of running trivy. Then exploit for real and `make import-verdicts`.
ingest-real:
	cd backend && $(GO) run ./cmd/perspectivegraph ingestreal $(if $(REPORT),--report $(REPORT),--image "$(IMAGE)")
	@echo "→ give the analyzer a pass, then the real path appears under attackPaths (target the sensitive asset)."

## ingest-k8s: ingest REAL cluster topology from your current kubectl context (Ingress/Service/Pod/SA/RBAC -> exposure + privesc + escape edges). Point kubectl at a local cluster first (e.g. kind + kubernetes-goat for a vulnerable one). Then `make and-probe` to see real AND-semantics.
ingest-k8s:
	@command -v kubectl >/dev/null 2>&1 || { echo "  ✗ kubectl not found - install it and point it at a local cluster"; exit 1; }
	kubectl get ingress,service,pod,serviceaccount,role,clusterrole,rolebinding,clusterrolebinding -A -o json \
	  | curl -sS -X POST http://localhost:8081/ingest/k8s -H 'Content-Type: application/json' --data-binary @- | jq .
	@echo "→ give the analyzer a pass, then: make and-probe   (real topology -> real AND-semantics signal)"

## and-probe: #6 (Bayesian Attack Graph) DECISION tool - scans the live graph and counts how many critical-path nodes plausibly have AND semantics (a compromise needing >=2 distinct prerequisite categories) vs pure OR-reachability. Near-zero => #6 is a no-op, invest in better p(e). --all-nodes inspects the whole topology. Upper-bound heuristic; confirm with real refuted verdicts.
and-probe:
	cd backend && $(GO) run ./cmd/perspectivegraph andprobe

## clean: remove build artifacts
clean:
	rm -rf backend/bin frontend/dist frontend/node_modules
