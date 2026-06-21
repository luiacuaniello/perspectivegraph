.DEFAULT_GOAL := help
.PHONY: help up down logs run-backend build-backend test tidy run-frontend install-frontend seed clean

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

## down: stop and remove infra containers
down:
	docker compose down

## logs: tail infra logs
logs:
	docker compose logs -f

## tidy: resolve Go module dependencies
tidy:
	cd backend && go mod tidy

## build-backend: compile the aegisgraph binary
build-backend:
	cd backend && $(GO) build -o bin/aegisgraph ./cmd/aegisgraph

## run-backend: run the backend (all layers) locally
run-backend:
	cd backend && $(GO) run ./cmd/aegisgraph

## test: run Go tests
test:
	cd backend && $(GO) test ./...

## install-frontend: install dashboard dependencies
install-frontend:
	cd frontend && npm install

## run-frontend: start the Vite dev server
run-frontend:
	cd frontend && npm run dev

## seed: feed sample infra context + a Trivy report; they correlate into one attack path
seed:
	@echo "→ posting infra/identity context (cloud + runtime stand-in)"
	curl -sS -X POST http://localhost:8081/ingest/events \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/context.json | jq .
	@echo "→ posting Trivy report (dependency CVEs)"
	curl -sS -X POST 'http://localhost:8081/ingest/trivy?slug=acme/payments-api&pr=42&sha=deadbeef' \
		-H 'Content-Type: application/json' \
		--data-binary @backend/testdata/trivy-sample.json | jq .
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
	@echo "→ open the dashboard or query: { attackPaths { id score runtimeConfirmed nodes { name label } } }"

## clean: remove build artifacts
clean:
	rm -rf backend/bin frontend/dist frontend/node_modules
