# Cloud Run Job image for the business-metrics exporter.
# Mirrors the API Dockerfile's two-stage layout so workspace dependency
# caching works the same way.

FROM rust:1.94-trixie AS builder

WORKDIR /app

# Workspace manifests for dependency caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/overslash-core/Cargo.toml crates/overslash-core/Cargo.toml
COPY crates/overslash-db/Cargo.toml crates/overslash-db/Cargo.toml
COPY crates/overslash-api/Cargo.toml crates/overslash-api/Cargo.toml
COPY crates/overslash-mcp/Cargo.toml crates/overslash-mcp/Cargo.toml
COPY crates/overslash-cli/Cargo.toml crates/overslash-cli/Cargo.toml
COPY crates/oversla-sh/Cargo.toml crates/oversla-sh/Cargo.toml
COPY crates/overslash-metrics/Cargo.toml crates/overslash-metrics/Cargo.toml
COPY crates/overslash-metrics-exporter/Cargo.toml crates/overslash-metrics-exporter/Cargo.toml
COPY tests/mock-target/Cargo.toml tests/mock-target/Cargo.toml

RUN mkdir -p crates/overslash-core/src \
    && echo "pub fn _dummy() {}" > crates/overslash-core/src/lib.rs \
    && mkdir -p crates/overslash-db/src \
    && echo "pub fn _dummy() {}" > crates/overslash-db/src/lib.rs \
    && mkdir -p crates/overslash-api/src \
    && echo "pub fn _dummy() {}" > crates/overslash-api/src/lib.rs \
    && mkdir -p crates/overslash-mcp/src \
    && echo "pub fn _dummy() {}" > crates/overslash-mcp/src/lib.rs \
    && mkdir -p crates/overslash-cli/src \
    && echo "fn main() {}" > crates/overslash-cli/src/main.rs \
    && mkdir -p crates/oversla-sh/src \
    && echo "pub fn _dummy() {}" > crates/oversla-sh/src/lib.rs \
    && echo "fn main() {}" > crates/oversla-sh/src/main.rs \
    && mkdir -p crates/overslash-metrics/src \
    && echo "pub fn _dummy() {}" > crates/overslash-metrics/src/lib.rs \
    && mkdir -p crates/overslash-metrics-exporter/src \
    && echo "fn main() {}" > crates/overslash-metrics-exporter/src/main.rs \
    && mkdir -p tests/mock-target/src \
    && echo "fn main() {}" > tests/mock-target/src/main.rs

# Build the dependency tree only (cached layer).
RUN cargo build --release --package overslash-metrics-exporter

COPY crates/ crates/
COPY .sqlx/ .sqlx/

# Touch sources to invalidate the dummy-only layer.
RUN find crates/ -name "*.rs" -exec touch {} +

ENV SQLX_OFFLINE=true
RUN cargo build --release --package overslash-metrics-exporter

# --- Runtime stage ---
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash overslash

WORKDIR /app

COPY --from=builder /app/target/release/overslash-metrics-exporter /app/overslash-metrics-exporter

RUN chown -R overslash:overslash /app
USER overslash

ENTRYPOINT ["/app/overslash-metrics-exporter"]
