# Dependency caching is cargo-chef's job (D54): `prepare` distills the workspace
# into a recipe of dependencies only, `cook` compiles it into a layer. That
# replaces the per-crate `COPY Cargo.toml` + `fn main(){}` stub scaffold this
# file used to hand-maintain — a new crate needs no edit here — and the
# `find crates/ -exec touch` that existed to defeat the stub fingerprints.
FROM rust:1.97-trixie AS chef

WORKDIR /app

# pg_query (the `sql_policy` feature, D42) generates its bindings with bindgen,
# which needs libclang at compile time. Builder stage only: pg_query's build.rs
# emits `cargo:rustc-link-lib=static=pg_query` and compiles the vendored
# libpg_query C sources into a static archive, so nothing from clang reaches the
# runtime stage. CI's sql-policy job installs the same package
# (.github/workflows/ci.yml).
RUN apt-get update && apt-get install -y --no-install-recommends libclang-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked --version ^0.1

# --- Planner: workspace in, dependency recipe out ---
# This stage re-runs on every source change, but it only reads manifests, so
# it costs seconds. Its single output — recipe.json — changes only when the
# dependency graph does, which is what keeps the `cook` layer below cached.
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- Builder ---
FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

# Dependencies only. Cached as an image layer, so a source-only change reuses
# it; Cloud Build restores it from the registry cache (infra/modules/cloud-build).
RUN cargo chef cook --release --package overslash-cli --features sql_policy --recipe-path recipe.json

# Real source. Everything after this line re-runs on any source change — which
# is why the ARGs below sit here and not above the cook step.
COPY . .

# Git commit of this build, reported by /health and GET /v1/version. The build
# context has no .git, so overslash-core's build.rs cannot discover it — Cloud
# Build passes its $COMMIT_SHA in (infra/modules/cloud-build/main.tf).
ARG OVERSLASH_GIT_SHA=unknown
ENV OVERSLASH_GIT_SHA=${OVERSLASH_GIT_SHA}

# Set to 1 by the prod Cloud Build trigger only (infra/modules/cloud-build).
# When set, build.rs emits the clean manifest version instead of "<version>-dev";
# dev leaves it empty and keeps the "-dev" marker. The release line itself comes
# from .release-please-manifest.json, since crate versions stay pinned at 0.1.0
# (D19).
ARG OVERSLASH_RELEASE=
ENV OVERSLASH_RELEASE=${OVERSLASH_RELEASE}

# sqlx offline mode: use cached query metadata from .sqlx/ instead of a live DB
ENV SQLX_OFFLINE=true
RUN cargo build --release --package overslash-cli --features sql_policy

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
