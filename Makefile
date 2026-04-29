.PHONY: local dev dev-api dev-dashboard down test check fmt clippy migrate new-migration schema sqlx-prepare check-sqlx mock-target install-hooks \
       tofu-init tofu-fmt tofu-validate tofu-plan tofu-apply tofu-destroy \
       infra-shutdown infra-resume worktree-clean \
       dashboard-static web-build web build install \
       logs logs-deploy \
       shortener-dev shortener-down shortener-deploy

COMPOSE := $(shell command -v podman-compose 2>/dev/null || command -v docker-compose 2>/dev/null || echo "docker compose")
TOFU := $(shell command -v tofu 2>/dev/null || command -v terraform 2>/dev/null)
TOFU_DIR := infra
ENV ?= dev
TF_VAR_FILE := $(TOFU_DIR)/env/$(ENV).tfvars

# Load .env.local overrides if present (worktree isolation).
# Used by non-compose targets like `test` and `migrate` that read DATABASE_URL.
# Compose targets re-source .env.local inline below to handle the first-run case
# where the file is created by bin/worktree-env.sh just before being read.
-include .env.local
export

# Install prefix (default: ~/.local). Override: PREFIX=/usr/local make install
PREFIX ?= $(HOME)/.local

# Colors
GREEN := \033[0;32m
RED := \033[0;31m
YELLOW := \033[0;33m
NC := \033[0m

# Shell snippet: run worktree-env.sh, source .env.local (if created), then
# build PROJ_FLAG. In worktrees, this becomes `--project-name overslash-wt-XXX`,
# which overrides `name: overslash` in docker-compose.dev.yml (podman-compose
# 1.0.6 does NOT honor COMPOSE_PROJECT_NAME env var when `name:` is set in the
# file, so we must pass the flag explicitly). In the main repo, .env.local is
# not created and PROJ_FLAG is empty, so compose uses `name: overslash`.
WT_ENV = bash bin/worktree-env.sh && set -a && { [ -f .env.local ] && . ./.env.local; }; set +a; \
         PROJ_FLAG=$${COMPOSE_PROJECT_NAME:+--project-name $$COMPOSE_PROJECT_NAME}

# Start local infra (postgres only)
local:
	@$(WT_ENV); $(COMPOSE) $$PROJ_FLAG -f docker/docker-compose.dev.yml up -d postgres

# Start all dev services (postgres + api with cargo-watch + dashboard)
dev:
	@$(WT_ENV); $(COMPOSE) $$PROJ_FLAG -f docker/docker-compose.dev.yml down --remove-orphans 2>/dev/null; \
	$(COMPOSE) $$PROJ_FLAG -f docker/docker-compose.dev.yml up --build

# Start only the API (postgres + api)
dev-api:
	@$(WT_ENV); $(COMPOSE) $$PROJ_FLAG -f docker/docker-compose.dev.yml down --remove-orphans 2>/dev/null; \
	$(COMPOSE) $$PROJ_FLAG -f docker/docker-compose.dev.yml up --build postgres api

# Start only the dashboard dev server (no container)
dev-dashboard:
	cd dashboard && npm run dev

# Build the SvelteKit dashboard with adapter-static. Output: dashboard/build/.
# Required before `make web-build` so rust-embed has assets to embed.
dashboard-static:
	cd dashboard && npm install && npm run build:static

# Build the self-hosted single-binary release with embedded dashboard and MCP.
# Produces target/release/overslash. Run `overslash web` to start it.
build: dashboard-static
	SQLX_OFFLINE=1 cargo build --release -p overslash-cli --features embed-dashboard

# Alias kept for backward compatibility.
web-build: dashboard-static
	SQLX_OFFLINE=1 cargo build --release -p overslash-cli --features embed-dashboard

# Install overslash to $(PREFIX)/bin (default: ~/.local/bin).
# Override: PREFIX=/usr/local make install
install: build
	install -d $(PREFIX)/bin
	install -m 755 target/release/overslash $(PREFIX)/bin/overslash
	@echo -e "$(GREEN)Installed:$(NC) $(PREFIX)/bin/overslash"
	@echo "Make sure $(PREFIX)/bin is in your PATH, then run: overslash web"

# Build + run the self-hosted binary directly (foreground).
web: build
	./target/release/overslash web

# Stop services
down:
	@$(WT_ENV); $(COMPOSE) $$PROJ_FLAG -f docker/docker-compose.dev.yml down --remove-orphans

# Start the oversla.sh shortener dev stack (valkey + shortener on :8081)
shortener-dev:
	$(COMPOSE) -f docker/docker-compose.shortener.yml up --build

# Stop the shortener dev stack
shortener-down:
	$(COMPOSE) -f docker/docker-compose.shortener.yml down --remove-orphans

# Build, push, and deploy the oversla.sh shortener from local.
# Mirrors the cloud-build-shortener pipeline: builds crates/oversla-sh/Dockerfile,
# pushes :$(SHA) + :latest to Artifact Registry, then `gcloud run deploy`s.
# Usage:
#   make shortener-deploy ENV=prod               # prod with current HEAD sha
#   make shortener-deploy ENV=prod SHA=v0.1.0    # override tag
#   DEPLOY_AUTO_APPROVE=1 make shortener-deploy ENV=prod  # skip prod confirm
shortener-deploy:
	@test -f $(TF_VAR_FILE) || (echo -e "$(RED)Var file $(TF_VAR_FILE) not found. Use ENV=dev or ENV=prod.$(NC)" && exit 1)
	@command -v gcloud >/dev/null || (echo -e "$(RED)gcloud CLI not found.$(NC)" && exit 1)
	@command -v docker >/dev/null || (echo -e "$(RED)docker CLI not found.$(NC)" && exit 1)
	@test -n "$(GCP_PROJECT)" || (echo -e "$(RED)Could not read project_id from $(TF_VAR_FILE)$(NC)" && exit 1)
	$(eval BASE_PREFIX := overslash-$(ENV))
	$(eval REPO := $(BASE_PREFIX)-registry)
	$(eval SERVICE := $(BASE_PREFIX)-shortener)
	$(eval AR_HOST := $(REGION)-docker.pkg.dev)
	$(eval IMAGE := $(AR_HOST)/$(GCP_PROJECT)/$(REPO)/oversla-sh)
	$(eval SHA ?= $(shell git rev-parse --short HEAD))
	@if [ "$(ENV)" = "prod" ] && [ "$(DEPLOY_AUTO_APPROVE)" != "1" ]; then \
		echo -e "$(RED)About to deploy $(SERVICE) ($(IMAGE):$(SHA)) to PRODUCTION ($(GCP_PROJECT))$(NC)"; \
		echo -n "Type 'deploy' to confirm: "; \
		read confirm && [ "$$confirm" = "deploy" ] || (echo "Aborted." && exit 1); \
	fi
	@echo -e "$(GREEN)[1/3] docker build -> $(IMAGE):$(SHA)$(NC)"
	docker build \
		-f crates/oversla-sh/Dockerfile \
		-t $(IMAGE):$(SHA) \
		-t $(IMAGE):latest \
		.
	@echo -e "$(GREEN)[2/3] docker push (tags: $(SHA), latest)$(NC)"
	docker push $(IMAGE):$(SHA)
	docker push $(IMAGE):latest
	@echo -e "$(GREEN)[3/3] gcloud run deploy $(SERVICE) --image $(IMAGE):$(SHA)$(NC)"
	gcloud run deploy $(SERVICE) \
		--image $(IMAGE):$(SHA) \
		--region $(REGION) \
		--project $(GCP_PROJECT) \
		--quiet
	@echo -e "$(GREEN)Deployed $(SERVICE) at $(IMAGE):$(SHA)$(NC)"

# Remove worktree containers and volumes
worktree-clean:
	@$(WT_ENV); \
	if [ -n "$${COMPOSE_PROJECT_NAME:-}" ]; then \
		$(COMPOSE) $$PROJ_FLAG -f docker/docker-compose.dev.yml down -v; \
	else \
		echo "Not in a worktree — nothing to clean."; \
	fi

# Run all tests
test:
	cargo test --workspace

# CI check: fmt + clippy + test
check:
	cargo fmt --check
	cargo clippy --workspace -- -D warnings
	cargo test --workspace

# Format
fmt:
	cargo fmt

# Lint
clippy:
	cargo clippy --workspace -- -D warnings

# Run migrations
migrate:
	cd crates/overslash-db && sqlx migrate run

# Create new migration
new-migration:
	@read -p "Migration name: " name; \
	cd crates/overslash-db && sqlx migrate add -r "$$name"

# Regenerate SCHEMA.sql
schema:
	pg_dump --schema-only --no-owner --no-acl --schema=public --exclude-table=_sqlx_migrations "$${DATABASE_URL}" > SCHEMA.sql

# Regenerate sqlx offline caches
sqlx-prepare:
	cargo sqlx prepare --workspace -- --tests

# Verify sqlx offline cache is up-to-date
check-sqlx:
	cargo sqlx prepare --workspace --check -- --tests

# Start mock target
mock-target:
	cargo run -p mock-target

# Install git hooks
install-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed."

# ---------------------------------------------------------------------------
# Infrastructure (OpenTofu / Terraform)
#   Usage: make tofu-plan ENV=dev   (default)
#          make tofu-plan ENV=prod
# ---------------------------------------------------------------------------

tofu-init:
	@echo -e "$(GREEN)Initializing tofu ($(ENV))...$(NC)"
	cd $(TOFU_DIR) && $(TOFU) init

tofu-fmt:
	@echo -e "$(GREEN)Checking tofu formatting...$(NC)"
	cd $(TOFU_DIR) && $(TOFU) fmt -check -recursive

tofu-validate: tofu-init
	@echo -e "$(GREEN)Validating tofu configuration...$(NC)"
	cd $(TOFU_DIR) && $(TOFU) validate

tofu-plan:
	@test -f $(TF_VAR_FILE) || (echo -e "$(RED)Var file $(TF_VAR_FILE) not found. Use ENV=dev or ENV=prod.$(NC)" && exit 1)
	@echo -e "$(GREEN)Running tofu plan ($(ENV))...$(NC)"
	cd $(TOFU_DIR) && $(TOFU) workspace select -or-create $(ENV) && $(TOFU) plan -var-file=env/$(ENV).tfvars -out=$(ENV).tfplan

tofu-apply:
	@test -f $(TOFU_DIR)/$(ENV).tfplan || (echo -e "$(RED)No plan file found. Run 'make tofu-plan ENV=$(ENV)' first.$(NC)" && exit 1)
	@if [ "$(ENV)" = "prod" ] && [ "$(TF_AUTO_APPROVE)" != "1" ]; then \
		echo -e "$(RED)You are about to apply to PRODUCTION (project: overslash)$(NC)"; \
		echo -n "Type 'prod' to confirm: "; \
		read confirm && [ "$$confirm" = "prod" ] || (echo "Aborted." && exit 1); \
	fi
	@echo -e "$(GREEN)Applying tofu plan ($(ENV))...$(NC)"
	cd $(TOFU_DIR) && $(TOFU) workspace select $(ENV) && $(TOFU) apply $(ENV).tfplan

tofu-destroy:
	@test -f $(TF_VAR_FILE) || (echo -e "$(RED)Var file $(TF_VAR_FILE) not found. Use ENV=dev or ENV=prod.$(NC)" && exit 1)
	@if [ "$(ENV)" = "prod" ]; then \
		echo -e "$(RED)You are about to DESTROY production (project: overslash)$(NC)"; \
		echo -n "Type 'destroy prod' to confirm: "; \
		read confirm && [ "$$confirm" = "destroy prod" ] || (echo "Aborted." && exit 1); \
	fi
	@echo -e "$(GREEN)Destroying tofu resources ($(ENV))...$(NC)"
	cd $(TOFU_DIR) && $(TOFU) workspace select $(ENV) && $(TOFU) destroy -var-file=env/$(ENV).tfvars

# ---------------------------------------------------------------------------
# Infra scheduler — manual shutdown / resume
#   Usage: make infra-shutdown ENV=prod
#          make infra-resume ENV=prod
# ---------------------------------------------------------------------------

GCP_PROJECT = $(shell grep '^project_id' $(TF_VAR_FILE) 2>/dev/null | sed 's/.*= *"\(.*\)"/\1/')
SQL_INSTANCE = overslash-$(ENV)-db

infra-shutdown:
	@test -f $(TF_VAR_FILE) || (echo -e "$(RED)Var file $(TF_VAR_FILE) not found.$(NC)" && exit 1)
	@echo -e "$(GREEN)Shutting down infra ($(ENV), project: $(GCP_PROJECT))...$(NC)"
	gcloud sql instances patch $(SQL_INSTANCE) --activation-policy=NEVER --project=$(GCP_PROJECT) --quiet
	@echo -e "$(GREEN)Cloud SQL stopped.$(NC)"

infra-resume:
	@test -f $(TF_VAR_FILE) || (echo -e "$(RED)Var file $(TF_VAR_FILE) not found.$(NC)" && exit 1)
	@echo -e "$(GREEN)Resuming infra ($(ENV), project: $(GCP_PROJECT))...$(NC)"
	gcloud sql instances patch $(SQL_INSTANCE) --activation-policy=ALWAYS --project=$(GCP_PROJECT) --quiet
	@echo -e "$(GREEN)Cloud SQL started.$(NC)"

# ---------------------------------------------------------------------------
# Cloud Run logs
#   Usage: make logs                              (tail api)
#          make logs ENV=prod                     (tail prod api)
#          make logs SVC=api SINCE=30m            (last 30m of history, then tail)
#          make logs SVC=api,worker               (multiple services, comma-separated)
# ---------------------------------------------------------------------------

REGION ?= europe-west1
SVC ?= api

logs:
	@SVC_FILTER=$$(echo "$(SVC)" | sed 's/[^,]\+/resource.labels.service_name="overslash-$(ENV)-&"/g; s/,/ OR /g'); \
	FILTER="resource.type=\"cloud_run_revision\" AND ($$SVC_FILTER) AND logName:\"stdout\""; \
	STRIP_ANSI='s/\x1B\[[0-9;]*[A-Za-z]//g'; \
	FMT='value(timestamp.date("%Y-%m-%d %H:%M:%S"), severity, resource.labels.service_name, jsonPayload.level, jsonPayload.target, jsonPayload.span.name, jsonPayload.message, jsonPayload.fields, textPayload)'; \
	if [ -n "$(SINCE)" ]; then \
		echo -e "$(GREEN)Reading Cloud Run logs: $(SVC) ($(ENV)) — last $(SINCE), then tailing$(NC)"; \
		( set -x; \
		  gcloud logging read "$$FILTER" \
			--project=$(GCP_PROJECT) --freshness=$(SINCE) --limit=10000 \
			--format="$$FMT" \
		) | tac | sed -E "$$STRIP_ANSI"; \
	fi; \
	echo -e "$(GREEN)Tailing Cloud Run logs: $(SVC) ($(ENV))$(NC)"; \
	set -x; \
	gcloud beta logging tail "$$FILTER" \
		--project=$(GCP_PROJECT) --buffer-window=3s \
		--format="$$FMT" \
		| sed -uE "$$STRIP_ANSI"

# View Cloud Build deploy logs (last build per service)
# Usage: make logs-deploy                          (api only)
#        make logs-deploy SVC=api,worker           (multiple services)
logs-deploy:
	@for svc in $$(echo "$(SVC)" | tr ',' ' '); do \
		echo -e "$(GREEN)Latest deploy log: overslash-$(ENV)-$$svc$(NC)"; \
		BUILD_ID=$$(gcloud builds list --project=$(GCP_PROJECT) --region=$(REGION) \
			--filter="substitutions._SERVICE_NAME=overslash-$(ENV)-$$svc" \
			--sort-by=~createTime --limit=1 --format="value(id)"); \
		if [ -n "$$BUILD_ID" ]; then \
			gcloud builds log "$$BUILD_ID" --project=$(GCP_PROJECT) --region=$(REGION); \
		else \
			echo -e "$(YELLOW)No builds found for overslash-$(ENV)-$$svc$(NC)"; \
		fi; \
	done
