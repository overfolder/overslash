FROM rust:1.94-trixie AS builder

WORKDIR /app

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/overslash-core/Cargo.toml crates/overslash-core/Cargo.toml
COPY crates/overslash-db/Cargo.toml crates/overslash-db/Cargo.toml
COPY crates/overslash-api/Cargo.toml crates/overslash-api/Cargo.toml
COPY crates/overslash-mcp/Cargo.toml crates/overslash-mcp/Cargo.toml
COPY crates/overslash-cli/Cargo.toml crates/overslash-cli/Cargo.toml
COPY tests/mock-target/Cargo.toml tests/mock-target/Cargo.toml

# Create dummy source files to cache dependency compilation
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
    && mkdir -p tests/mock-target/src \
    && echo "fn main() {}" > tests/mock-target/src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release --package overslash-cli

# Copy actual source code
COPY crates/ crates/
COPY services/ services/
COPY .sqlx/ .sqlx/

# Touch source files to invalidate the dummy builds
RUN find crates/ -name "*.rs" -exec touch {} +

# sqlx offline mode: use cached query metadata from .sqlx/ instead of a live DB
ENV SQLX_OFFLINE=true
RUN cargo build --release --package overslash-cli

# --- Runtime stage ---
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash overslash

WORKDIR /app

COPY --from=builder /app/target/release/overslash /app/overslash
COPY services/ /app/services/
COPY crates/overslash-api/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && chown -R overslash:overslash /app
USER overslash

ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
