.PHONY: local local-down dev dev-api dev-dashboard down test check fmt clippy migrate new-migration schema sqlx-prepare check-sqlx mock-target install-hooks \
       tofu-init tofu-fmt tofu-validate tofu-plan tofu-apply tofu-destroy \
       infra-shutdown infra-resume env-setup worktree-clean

COMPOSE := $(shell command -v podman-compose 2>/dev/null || command -v docker-compose 2>/dev/null || echo "docker compose")
TOFU := $(shell command -v tofu 2>/dev/null || command -v terraform 2>/dev/null)
TOFU_DIR := infra
ENV ?= dev
TF_VAR_FILE := $(TOFU_DIR)/env/$(ENV).tfvars

# Load .env.local overrides if present (worktree isolation)
-include .env.local
export

# Compose project flag (set by .env.local in worktrees, empty in main repo)
COMPOSE_PROJECT := $(if $(COMPOSE_PROJECT_NAME),--project-name $(COMPOSE_PROJECT_NAME),)

# Colors
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m

# Detect worktree and write .env.local (no-op in main repo)
env-setup:
	@bash bin/worktree-env.sh

# Start local infra (postgres only)
local: env-setup
	$(COMPOSE) $(COMPOSE_PROJECT) -f docker/docker-compose.dev.yml up -d postgres

# Stop local infra
local-down:
	$(COMPOSE) $(COMPOSE_PROJECT) -f docker/docker-compose.dev.yml down

# Start all dev services (postgres + api with cargo-watch + dashboard)
dev: env-setup
	$(COMPOSE) $(COMPOSE_PROJECT) -f docker/docker-compose.dev.yml up --build

# Start only the API (postgres + api)
dev-api: env-setup
	$(COMPOSE) $(COMPOSE_PROJECT) -f docker/docker-compose.dev.yml up --build postgres api

# Start only the dashboard dev server (no container)
dev-dashboard:
	cd dashboard && npm run dev

# Stop services
down:
	$(COMPOSE) $(COMPOSE_PROJECT) -f docker/docker-compose.dev.yml down

# Remove worktree containers and volumes
worktree-clean:
	@if [ -n "$(COMPOSE_PROJECT_NAME)" ]; then \
		$(COMPOSE) $(COMPOSE_PROJECT) -f docker/docker-compose.dev.yml down -v; \
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
	cargo sqlx prepare --workspace

# Verify sqlx offline cache is up-to-date
check-sqlx:
	cargo sqlx prepare --workspace --check

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
