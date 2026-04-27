---
name: overslash
description: Overslash is a multi-tenant actions and authentication gateway for AI agents on app.overslash.com. USE WHEN you need to call external services on behalf of a user, manage OAuth connections, resolve approvals, or run service actions.
---

# Enrolling with app.overslash.com

Overslash enrollment is **MCP OAuth 2.1** (MCP spec 2025-06-18 — RFC 8414 +
RFC 7591 + PKCE). There is no paste-token flow and no API-key exchange. Point
your MCP client at `https://app.overslash.com/mcp`.

## MCP clients that speak OAuth (Claude Code, Cursor, Windsurf)

Register the server — nothing else:

```json
{ "url": "https://app.overslash.com/mcp" }
```

On first call your client will:

1. `POST /mcp` → receive `401 WWW-Authenticate`.
2. Discover `/.well-known/oauth-authorization-server`.
3. Register itself at `POST /oauth/register` (RFC 7591, public client + PKCE).
4. Open a browser to `/oauth/authorize` — the user signs in, confirms the
   agent name + parent on the consent screen, and lands back at the client.
5. Exchange the auth code at `POST /oauth/token` for an access token (1h JWT,
   `aud=mcp`) + single-use-rotating refresh token.

The tokens are bound to a new agent identity owned by the signed-in user.
Subsequent runs reuse that binding — no consent prompt.

## MCP clients that only take a static Bearer header (e.g. OpenClaw)

Mint tokens once on the command line:

```bash
overslash mcp login --server https://app.overslash.com
```

This runs PKCE in your browser and writes `~/.config/overslash/mcp.json`. Then
either:

- **Stdio shim (preferred)** — client config
  `{ "command": "overslash", "args": ["mcp"] }`. The shim refreshes on 401.
- **Paste the access token** into the client's `headers` config. Re-run
  `overslash mcp login` every hour when it expires.

## After enrollment

Call MCP tools, `POST /v1/actions/call`, etc. See `SPEC.md` for actions,
approvals, and the permission model.
