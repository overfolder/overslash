# Overslash Design Documents

Design documents for Overslash, migrated from the Overfolder workspace repo.

> The live product spec is at [SPEC.md](../../SPEC.md). These design docs capture the original planning and alternatives considered.

---

| Document | Status | Summary |
|----------|--------|---------|
| [overslash.md](overslash.md) | Not Implemented | Core gateway design — identity hierarchy, secrets, OAuth, permissions, approvals, service registry |
| [nango-integration.md](nango-integration.md) | Superseded | Nango evaluation — superseded by Overslash owning OAuth natively |
| [audit-log.md](audit-log.md) | Implemented | Audit log expansion — IP capture, full CRUD coverage, filtered queries |
| [large-file-handling.md](large-file-handling.md) | Implemented | Large file handling — response size limits + streaming proxy (`prefer_stream`) |
| [permission-chain-implementation.md](permission-chain-implementation.md) | Not Implemented | Permission chain walk, approval bubbling, identity hierarchy — Phase 3 implementation design |
