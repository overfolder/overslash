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
