# Repository quality gates (AGENTS.md):
#   make fmt       format code and regenerate generated files
#   make lint      Go and TypeScript static analysis, secret and vulnerability scans
#   make test      unit and integration tests
#   make test-e2e  critical browser flows
#   make build     reproducible production artifacts (binary and image)
# CI additionally runs `make fmt-check` and `make gate-selftest`.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO ?= go
NPM ?= npm
IMAGE ?= qali:dev
POSTGRES_MAJORS ?= 18
RACE ?= 0
PLAYWRIGHT_INSTALL_FLAGS ?=

tool = $(GO) tool -modfile=tools/mod/$(1).mod $(1)
GOEXE := $(shell $(GO) env GOEXE)
BIN := bin/qali$(GOEXE)
WEB_DEPS := web/node_modules/.package-lock.json
GO_BUILD_FLAGS := -trimpath -buildvcs=false -ldflags="-s -w -buildid="

ifeq ($(RACE),1)
GO_TEST_FLAGS := -race
export CGO_ENABLED := 1
else
GO_TEST_FLAGS :=
export CGO_ENABLED := 0
endif

# Docker Desktop on Windows: testcontainers' reaper needs the VM socket path.
ifeq ($(OS),Windows_NT)
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE ?= //var/run/docker.sock
endif

.PHONY: help deps fmt fmt-check generate lint test test-unit test-integration \
	test-e2e build build-web build-binary image deploy-check test-deploy cover-check gate-selftest clean \
	docs-check docs-test docs-generate

help: ## Show available targets
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/'

$(WEB_DEPS): web/package.json web/package-lock.json
	cd web && $(NPM) ci --no-audit --no-fund
	@touch $@

deps: $(WEB_DEPS) ## Install locked frontend dependencies

# sqlc links the PostgreSQL parser through cgo.
SQLC := CGO_ENABLED=1 $(GO) tool -modfile=tools/mod/sqlc.mod sqlc

generate: $(WEB_DEPS) ## Regenerate OpenAPI server types, the TypeScript client, and sqlc queries
	$(GO) generate ./...
	$(SQLC) generate
	cd web && $(NPM) run --silent generate

fmt: generate docs-generate ## Format code and regenerate generated files
	$(call tool,golangci-lint) fmt ./...
	$(GO) mod tidy
	cd web && npx prettier --write --log-level warn .

fmt-check: $(WEB_DEPS) ## Fail on unformatted code, untidy modules, or stale generated files
	$(call tool,golangci-lint) fmt --diff ./...
	$(GO) mod tidy -diff
	$(SQLC) diff || { echo "stale: sqlc output; run make generate" >&2; exit 1; }
	bash tools/gencheck/gencheck.sh
	cd web && npx prettier --check --log-level warn .
	@tmp=bin/.fmt-check; rm -rf "$$tmp"; mkdir -p "$$tmp"; trap 'rm -rf "$$tmp"' EXIT; \
	$(call tool,oapi-codegen) -config api/oapi-codegen.yaml -o "$$tmp/openapi.gen.go" api/openapi.yaml; \
	(cd web && npx openapi-typescript ../api/openapi.yaml -o "../$$tmp/api.ts" >/dev/null 2>&1); \
	stale=0; \
	cmp -s "$$tmp/openapi.gen.go" internal/platform/httpserver/openapi/openapi.gen.go || { echo "stale: internal/platform/httpserver/openapi/openapi.gen.go"; stale=1; }; \
	cmp -s "$$tmp/api.ts" web/src/generated/api.ts || { echo "stale: web/src/generated/api.ts"; stale=1; }; \
	$(GO) run ./tools/permgen docs/rbac/permission-catalog.json "$$tmp/catalog_gen.go"; \
	cmp -s "$$tmp/catalog_gen.go" internal/authz/catalog_gen.go || { echo "stale: internal/authz/catalog_gen.go"; stale=1; }; \
	if [ $$stale = 1 ]; then echo "generated files are stale; run make generate" >&2; exit 1; fi
	$(NODE) tools/doccheck/doccheck.mjs check . >/dev/null

lint: $(WEB_DEPS) docs-check ## Static analysis, test hygiene, secret and vulnerability scans
	$(call tool,golangci-lint) run ./...
	$(GO) run ./tools/testguard .
	$(call tool,gitleaks) dir --config .gitleaks.toml --no-banner --redact --log-level warn .
	$(GO) mod verify
	$(call tool,govulncheck) ./...
	cd web && $(NPM) audit --audit-level=high
	cd web && $(NPM) run --silent typecheck
	cd web && $(NPM) run --silent lint

test: test-unit test-integration cover-check ## Unit and integration tests, then coverage thresholds

# Coverage thresholds (docs/TESTING_POLICY.md section 6): 90% for
# security-critical packages (secrets, crypto, configuration, tenancy, audit),
# 80% for domain, application, and adapters. Unit and integration profiles
# are combined.
COVER_THRESHOLDS := internal/platform/secret=90 internal/platform/crypto=90 \
	internal/platform/config=90 internal/platform/db=90 internal/platform/audit=90 \
	internal/platform/jobs=90 internal/platform/httpserver=80 \
	internal/identity/domain=90 internal/identity/app=80 \
	internal/identity/adapter/httpapi=80 internal/identity/adapter/postgres=80 \
	internal/authz=90 internal/platform/pagination=90 \
	internal/workspace/domain=90 internal/workspace/app=80 \
	internal/workspace/adapter/httpapi=80 internal/workspace/adapter/postgres=80

test-unit: $(WEB_DEPS) docs-test ## Go and frontend unit tests
	@mkdir -p bin
	$(GO) test $(GO_TEST_FLAGS) -count=1 -coverprofile=bin/cover-unit.out ./...
	cd web && $(NPM) run --silent test

test-integration: ## Integration tests against disposable PostgreSQL containers
	@mkdir -p bin
	for major in $(POSTGRES_MAJORS); do \
		echo "PostgreSQL $$major"; \
		QALI_TEST_POSTGRES_MAJOR=$$major $(GO) test $(GO_TEST_FLAGS) -tags integration -count=1 \
			-coverpkg=./internal/... -coverprofile=bin/cover-integration.out ./test/integration/...; \
	done

cover-check: ## Enforce coverage thresholds on the unit and integration profiles
	$(GO) run ./tools/covercheck bin/cover-unit.out,bin/cover-integration.out github.com/qali-project/qali $(COVER_THRESHOLDS)

test-e2e: build-binary ## Playwright journeys against the production binary
	cd web && npx playwright install $(PLAYWRIGHT_INSTALL_FLAGS) chromium
	rm -rf bin/e2e-secrets
	QALI_E2E_BINARY="../$(BIN)" $(GO) run ./tools/e2eenv -C web bin/e2e-secrets -- npx playwright test

build: build-binary image deploy-check test-deploy ## Production binary, container image, and verified Compose deployment

build-web: $(WEB_DEPS)
	cd web && $(NPM) run --silent build

build-binary: build-web
	CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BIN) ./cmd/qali

image:
	docker build -t $(IMAGE) .
	$(GO) run ./tools/imagecheck $(IMAGE)

deploy-check: ## Validate the rendered production Compose configuration
	$(GO) run ./tools/deploycheck static

test-deploy: ## Start the Compose stack with throwaway secrets and probe its exposure
	rm -rf bin/deploy-secrets && $(GO) run ./tools/devsecrets bin/deploy-secrets
	QALI_IMAGE=$(IMAGE) $(GO) run ./tools/deploycheck live bin/deploy-secrets

gate-selftest: ## Prove that every gate fails on an injected defect (slow)
	tools/gateselftest/run.sh

clean: ## Remove build outputs
	rm -rf bin internal/platform/webui/dist/app web/playwright-report web/test-results

NODE ?= node

docs-check: ## Validate links, IDs, ADRs, permission catalog, and acceptance maps
	$(NODE) tools/doccheck/doccheck.mjs check .

docs-test: ## Run the documentation checker's own tests
	$(NODE) --test "tools/doccheck/*.test.mjs"

docs-generate: ## Regenerate docs/rbac/permission-matrix.md from the catalog
	$(NODE) tools/doccheck/doccheck.mjs generate .
