# Overslash — Decisions

Settled architectural decisions. Don't re-litigate without new information.

---

## D1: Standalone service, not a library

**Date**: 2026-03
**Decision**: Overslash is a standalone REST API service, not embedded in Overfolder's agent-runner.
**Rationale**: Auth, secrets, approvals, and action execution are general-purpose. Any agent platform should be able to use Overslash. Decoupling also simplifies agent-runner.

## D2: Replace Nango with native OAuth

**Date**: 2026-03
**Decision**: Overslash owns OAuth flows natively instead of using Nango.
**Rationale**: Nango adds a dependency and limits control over the token lifecycle. Overslash needs tight integration between OAuth tokens, permission rules, and approval workflows. See `docs/design/nango-integration.md` for the evaluation that led to this decision.

## D3: Rust + Axum (same stack as Overfolder)

**Date**: 2026-03
**Decision**: Use Rust/Axum, matching the Overfolder stack.
**Rationale**: Shared expertise, proven stack, consistent tooling. AES-256-GCM for secrets at rest.

## D4: Valkey over Redis

**Date**: 2026-03
**Decision**: Use Valkey (not Redis) for caching and pub/sub.
**Rationale**: Valkey is the open-source fork of Redis, maintained by the Linux Foundation. License-compatible, drop-in replacement, actively developed. No reason to use Redis's restrictive SSPL license.

## D5: Cloud SQL Auth Proxy by default (no VPC)

**Date**: 2026-03
**Decision**: Default to Cloud SQL Auth Proxy mode instead of VPC private networking.
**Rationale**: VPC connector costs ~$7/month even idle. Auth Proxy is free, secure (IAM-authenticated), and sufficient for pre-GA. VPC mode is available via `use_private_vpc = true` for production hardening later.

## D6: Podman-first container tooling

**Date**: 2026-03
**Decision**: Prefer Podman / podman-compose over Docker where available.
**Rationale**: Rootless by default, daemonless, OCI-compliant. Docker is supported as fallback. Makefile auto-detects `podman-compose` first.

## D7: Identity hierarchy with live inheritance

**Date**: 2026-03
**Decision**: `inherit_permissions` is a live pointer, not a copy. Child dynamically has parent's current + future rules.
**Rationale**: Static copies create drift. Live pointers mean granting a user a new permission automatically flows to their agents. See SPEC.md for full design.

## D8: Two-tier rate limiting (User bucket + identity caps)

**Date**: 2026-04
**Decision**: Rate limits use two counters per request: a User-level bucket (shared by all agents under that user) and optional per-identity caps. Not per-agent buckets alone.
**Rationale**: Per-agent-only limits are easily circumvented by spawning sub-agents. The User bucket ensures a hard ceiling regardless of agent topology. Identity caps are a convenience for isolating misconfigured agents from consuming the entire User budget. See SPEC.md §13.

## D9: Merge queue on `dev`, merge-commits on `master`

**Date**: 2026-04
**Decision**: PRs target `dev` and merge through GitHub's merge queue (squash, ALLGREEN, required check `ci-ok`, strict-up-to-date off — the queue handles rebasing). `dev` flows to `master` via **merge commits only** (`master` ruleset disallows squash/rebase) so feature history is preserved on `master`. Repo was made public to unlock merge queue without an Enterprise upgrade. The Stop hook arms `gh pr merge --auto --squash` once its three gates pass, but **only when the PR's base branch is `dev`** — never on PRs targeting `master`.
**Rationale**: Keeping branches up-to-date with base was a recurring source of agent churn. The merge queue serializes PRs and rebases them in-place, eliminating that responsibility. Squash on `dev` keeps feature PRs as single commits; merge-commits on `master` retain the full feature history at release-cut time. See `.claude/hooks/pr-mergeability-gate.sh` and rulesets `dev` (id 14770759) / `master` (id 14707284).

## D10: MCP over Streamable HTTP + OAuth 2.1

**Date**: 2026-04
**Decision**: MCP clients connect via `POST /mcp` on the API, gated by `Authorization: Bearer`. Two single-credential modes: user JWT (aud=mcp, minted via `/oauth/authorize` → `/oauth/token` on the same Axum process) or static `osk_…` agent API key. The dual-credential model and stdio-only transport are retired. `overslash mcp` becomes a thin stdio↔HTTP compat shim for editors whose MCP transport is stdio-only; `overslash mcp login` runs the standard OAuth Authorization Code + PKCE flow and writes `~/.config/overslash/mcp.json`.
**Rationale**: OAuth 2.1 is the standard auth flow in the MCP spec, and Streamable HTTP is the reference transport for remote MCP. Hosting the Authorization Server (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`) next to the API means DCR, consent, refresh, and revocation share infra and reuse the existing IdP login flow. Editors speaking stdio get the compat shim so Overslash doesn't break their setup. Implementation landed in PR #121 (single binary) and PR #123 (HTTP transport + AS). Full design at `docs/design/mcp-oauth-transport.md`.

## D11: Semantic search uses local pgvector + fastembed, not an API

**Date**: 2026-04
**Decision**: `GET /v1/search` (§10) ranks candidates with a hybrid of keyword + Jaro-Winkler fuzzy and pgvector cosine similarity, where the embeddings come from **locally hosted** `BAAI/bge-small-en-v1.5` (384-dim) via the `fastembed` crate. Dev, CI, and the shipped compose images run `pgvector/pgvector:pg16`; vanilla Postgres is supported — both the extension migration and the table migration are wrapped in `DO $$` blocks that probe `pg_available_extensions` and no-op cleanly. A boot-time preflight (`SELECT … FROM pg_extension`) plus the env kill-switch `OVERSLASH_EMBEDDINGS=off` force-disable embeddings at runtime; search then falls back to keyword + fuzzy transparently.
**Rationale**: The service/action catalog is tiny (~9 global templates × ~20 actions plus DB-tier templates) — an external embedding API would add a per-query cost, a new secret, and network latency for a corpus that fits trivially in CPU-embedded memory. The local model is a one-time ~130 MB download cached under `OVERSLASH_EMBED_CACHE_DIR`; ONNX runtime adds ~40 MB to the binary, which is acceptable for a single-binary server distribution (the `embeddings` Cargo feature lets library consumers opt out). Keyword + fuzzy alone handles exact matches and typos well but misses paraphrased intent — the embedding signal covers that gap, and the hybrid weighting (0.4 keyword + 0.6 embedding) keeps exact service / action names dominant when they match literally. The pgvector no-op path means a self-hosted deploy on vanilla Postgres still boots and serves search, just without the embedding signal.

## D12: Multi-org trust model — each IdP is its own trust domain

**Date**: 2026-04
**Decision**: Overslash treats each IdP as its own trust domain. An IdP can only admit members into resources it controls: Overslash-level IdPs admit into personal orgs and into corp orgs the user themselves created (the creator becomes a regular admin of the new org); per-org IdPs admit into that org only. Users are keyed at auth time by `(provider, subject)`, never by email. There are no invites and no cross-IdP account linking. A human who uses Google for their personal Overslash account and Okta for Acme simply has two distinct `users` rows.
**Rationale**: If email alone could attach a login to an existing membership, a user who registers a Google account claiming `amartcan@acme.org` would inherit whatever Acme provisioned for its real employee via Okta. By restricting each IdP to its own trust domain, an external IdP (Google) cannot vouch its way into resources controlled by an internal one (Acme's Okta). Invites fail the same threat model unless accompanied by explicit admin-scoped verification beyond email delivery — we drop them entirely rather than half-build them. Full design at `docs/design/multi_org_auth.md`.
