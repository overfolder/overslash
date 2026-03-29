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
