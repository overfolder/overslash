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
