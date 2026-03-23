.PHONY: dev down test check fmt clippy migrate new-migration schema sqlx-prepare mock-target install-hooks

COMPOSE := $(shell command -v podman-compose 2>/dev/null || command -v docker-compose 2>/dev/null || echo "docker compose")

# Start postgres + run API server
dev:
	$(COMPOSE) -f docker-compose.dev.yml up -d postgres
	cargo run -p overslash-api

# Stop services
down:
	$(COMPOSE) -f docker-compose.dev.yml down

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
	pg_dump --schema-only --no-owner --no-acl "$${DATABASE_URL}" > SCHEMA.sql

# Regenerate sqlx offline caches
sqlx-prepare:
	cargo sqlx prepare --workspace

# Start mock target
mock-target:
	cargo run -p mock-target

# Install git hooks
install-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed."
