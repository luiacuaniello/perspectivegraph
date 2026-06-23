.DEFAULT_GOAL := help
.PHONY: help up up-full up-search down logs run-backend build-backend test bench tidy run-frontend install-frontend seed seed-discovery seed-load clean

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

## up-search: start infra plus the optional OpenSearch full-text index
up-search:
	docker compose --profile search up -d

## down: stop and remove infra containers
down:
	docker compose down

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

## seed-validation: record sample red-team/BAS verdicts on the current top paths so the Validation card (precision/recall) and per-path verdict badges light up
seed-validation:
	@echo "→ recording red-team/BAS verdicts (confirmed / refuted / missed) → precision & recall"
	@for i in $$(seq 1 20); do \
	  ids=$$(curl -sS -X POST http://localhost:8080/graphql -H 'Content-Type: application/json' \
	    -d '{"query":"{ attackPaths(limit:2){ id } }"}' | jq -r '.data.attackPaths[].id'); \
	  set -- $$ids; \
	  if [ -n "$$2" ]; then break; fi; \
	  echo "  waiting for the analyzer to surface attack paths…"; sleep 3; \
	done; \
	if [ -z "$$2" ]; then echo "  ✗ no attack paths yet - run 'make seed' (and give the analyzer a cycle) first"; exit 1; fi; \
	curl -sS -X POST http://localhost:8080/validations -H 'Content-Type: application/json' \
	  -d "{\"pathId\":\"$$1\",\"outcome\":\"confirmed\",\"source\":\"caldera\",\"evidence\":\"atomic test T1190 reached the jewel\"}" | jq -c '{outcome,source}'; \
	curl -sS -X POST http://localhost:8080/validations -H 'Content-Type: application/json' \
	  -d "{\"pathId\":\"$$2\",\"outcome\":\"refuted\",\"source\":\"red-team\",\"evidence\":\"WAF blocks the entry endpoint\"}" | jq -c '{outcome,source}'; \
	curl -sS -X POST http://localhost:8080/validations -H 'Content-Type: application/json' \
	  -d '{"outcome":"missed","source":"red-team","route":"Okta → SaaS → data export (engine missed it)"}' | jq -c '{outcome,source}'; \
	echo "  done - Overview ‘Validation’ card shows precision; open the top paths to see the verdict badges"

## seed-load: generate a large synthetic graph and POST it to ingest (scale demo)
seed-load:
	cd backend && $(GO) run ./cmd/perspectivegraph genload --seeds 32 --jewels 16 --layers 8 --width 500 --fanout 4

## clean: remove build artifacts
clean:
	rm -rf backend/bin frontend/dist frontend/node_modules
