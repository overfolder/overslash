# Cloud Run Job image for the business-metrics exporter.
# Mirrors the API Dockerfile's cargo-chef layout — see it for why the
# hand-maintained manifest/stub scaffold is gone.

FROM rust:1.97-trixie AS chef

WORKDIR /app

RUN cargo install cargo-chef --locked --version ^0.1

# --- Planner: workspace in, dependency recipe out ---
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- Builder ---
FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

# Dependencies only (cached layer).
RUN cargo chef cook --release --package overslash-metrics-exporter --recipe-path recipe.json

COPY . .

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
