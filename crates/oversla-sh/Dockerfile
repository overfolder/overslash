# Image for the oversla.sh URL shortener.
# Mirrors the API Dockerfile's cargo-chef layout — see it for why the
# hand-maintained manifest/stub scaffold is gone.

FROM rust:1.98-trixie AS chef

WORKDIR /app

RUN cargo install cargo-chef --locked --version ^0.1

# --- Planner: workspace in, dependency recipe out ---
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- Builder ---
FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

# Dependencies only (cached layer). Scoped to `oversla-sh`, so only its slice
# of the workspace dependency graph is compiled.
RUN cargo chef cook --release --package oversla-sh --recipe-path recipe.json

COPY . .

RUN cargo build --release --package oversla-sh

# --- Runtime stage ---
FROM debian:trixie-slim AS runtime

# `upgrade` pulls Debian security fixes the base image has not been re-cut
# with yet, so a rebuild clears an image-scan finding as soon as Debian ships
# the fix (docs/runbooks/image-scanning.md).
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
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
