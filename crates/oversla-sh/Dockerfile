FROM rust:1.95-trixie AS builder

WORKDIR /app

# Copy workspace manifests for dependency caching. We copy every member's
# Cargo.toml so the workspace resolver is happy, even though oversla-sh only
# depends on a subset of the deps.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/overslash-core/Cargo.toml crates/overslash-core/Cargo.toml
COPY crates/overslash-db/Cargo.toml crates/overslash-db/Cargo.toml
COPY crates/overslash-api/Cargo.toml crates/overslash-api/Cargo.toml
COPY crates/overslash-mcp/Cargo.toml crates/overslash-mcp/Cargo.toml
COPY crates/overslash-cli/Cargo.toml crates/overslash-cli/Cargo.toml
COPY crates/oversla-sh/Cargo.toml crates/oversla-sh/Cargo.toml
COPY crates/overslash-metrics/Cargo.toml crates/overslash-metrics/Cargo.toml
COPY crates/overslash-metrics-exporter/Cargo.toml crates/overslash-metrics-exporter/Cargo.toml
COPY crates/overslash-fakes/Cargo.toml crates/overslash-fakes/Cargo.toml
COPY tests/mock-target/Cargo.toml tests/mock-target/Cargo.toml

# Create dummy source files for every workspace member so `cargo build -p
# oversla-sh` can resolve the workspace graph without actually compiling the
# other crates.
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
    && mkdir -p crates/overslash-fakes/src/bin \
    && echo "pub fn _dummy() {}" > crates/overslash-fakes/src/lib.rs \
    && echo "fn main() {}" > crates/overslash-fakes/src/bin/overslash_fakes.rs \
    && mkdir -p tests/mock-target/src \
    && echo "fn main() {}" > tests/mock-target/src/main.rs

# Warm the dependency cache.
RUN cargo build --release --package oversla-sh

# Copy the real source.
COPY crates/oversla-sh/ crates/oversla-sh/

# Invalidate the dummy build so cargo picks up the real source.
RUN find crates/oversla-sh/ -name "*.rs" -exec touch {} +

RUN cargo build --release --package oversla-sh

# --- Runtime stage ---
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash oversla

WORKDIR /app

COPY --from=builder /app/target/release/oversla-sh /app/oversla-sh

RUN chown -R oversla:oversla /app
USER oversla

ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/oversla-sh"]
