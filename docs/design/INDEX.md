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
| [mcp-integration.md](mcp-integration.md) | Superseded | Original MCP design — dual-key inline-approval flow over stdio. Dual-key + `mcp setup` portions superseded by [mcp-oauth-transport.md](mcp-oauth-transport.md); the white-label and CLI-priority discussion still applies. |
| [mcp-oauth-transport.md](mcp-oauth-transport.md) | Approved | MCP over Streamable HTTP at `POST /mcp` with OAuth 2.1 Authorization Server endpoints. `overslash mcp` reshaped into a stdio↔HTTP compat shim; `mcp setup` replaced by `mcp login`. |
| [user-stories.md](user-stories.md) | Draft | End-to-end user stories: OpenClaw direct enrollment, corporate MCP usage, Overfolder/Telegram platform-mediated flow |
| [agent-self-management.md](agent-self-management.md) | Draft | Future shape for agent self-management via MCP — metaservice bridge for service/template creation, self-vs-downstream approval split, identity-scoped `list_secrets`, Claude Code permission-rule composition |
| [multi_org_auth.md](multi_org_auth.md) | Draft | Multi-org per user — global `users` table, per-org IDP trust domains, subdomain routing (`<slug>.app.overslash.com`), `/auth/switch-org`, corp-org bootstrap admin, self-hosted `SINGLE_ORG_MODE` / `ALLOW_ORG_CREATION` flags |
| [external-mcp-services.md](external-mcp-services.md) | Shipped | External MCP servers as first-class Overslash services — `x-overslash-runtime: mcp`, tools/list resync, bearer/none auth, executor envelope, disabled tool gating |
