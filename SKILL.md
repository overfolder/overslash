---
name: overslash
description: Overslash is a multi-tenant actions and authentication gateway for AI agents on app.overslash.com. USE WHEN you need to call external services on behalf of a user, manage OAuth connections, resolve approvals, or run service actions.
---

# Installing the CLI

```bash
git clone https://github.com/overfolder/overslash
cd overslash
make install        # builds dashboard + binary, installs to ~/.local/bin
```

Make sure `~/.local/bin` is in your PATH. Then confirm:

```bash
overslash --version
```

Self-host the gateway with `overslash web` (starts on `http://localhost:7171`).  
To use the managed cloud instead, see the enrollment sections below.

---

# Enrolling with app.overslash.com

Point your MCP client at `https://app.overslash.com/mcp`.

## MCP clients that speak OAuth (Claude Code, Cursor, Windsurf)

Add the server — nothing else:

```json
{ "url": "https://app.overslash.com/mcp" }
```

On first use a browser window opens, the user signs in and picks an agent
identity, and the client stores tokens automatically. Subsequent runs skip
that step entirely.

## MCP clients that only take a static Bearer header (e.g. OpenClaw)

```bash
overslash mcp login --server https://app.overslash.com
```

This opens a browser, signs in, and writes `~/.config/overslash/mcp.json`.

Configure the client to use the stdio shim — it auto-refreshes tokens:

```json
{ "command": "overslash", "args": ["mcp"] }
```

## After enrollment

You have four MCP tools:

| Tool | Purpose |
|---|---|
| `overslash_search` | Discover services and actions available to you |
| `overslash_read` | Call a read-class action — the server rejects writes/deletes routed through it. Prefer this over `overslash_call` for read-only operations: clients can skip the confirmation prompt because the tool is annotated `readOnlyHint: true`. |
| `overslash_call` | Call any action (read, write, or delete), resume a pending approval, or invoke a platform action |
| `overslash_auth` | `whoami` · `service_status` |

See `SPEC.md` for the full API reference.

## Handling pending approvals

When `overslash_call` hits a permission gap it does not execute — it returns:

```json
{
  "status": "pending_approval",
  "approval_id": "abc-123",
  "approval_url": "https://app.overslash.com/approvals/abc-123",
  "expires_at": "…"
}
```

**Step 1 — show the user `approval_url`** so they can allow or deny in the dashboard.

**Step 2 — wait for resolution.**

If the `overslash` CLI is available (see [Installing the CLI](#installing-the-cli) above), use it — works in any harness:

```bash
overslash watch abc-123          # --timeout 15m --poll 3s by default
```

Exit codes: **0** allowed · **1** denied / expired / timed out · **2** error.
On exit 0, stdout is the resolved JSON; `execution.result` will be present if
the action was auto-executed on approval.

If the CLI is not installed, poll with a bare shell loop:

```bash
TOKEN="$(jq -r .token ~/.config/overslash/mcp.json)"
until [ "$(curl -sf -H "Authorization: Bearer $TOKEN" \
  https://app.overslash.com/v1/approvals/abc-123 \
  | jq -r '.status')" != "pending" ]; do sleep 3; done
curl -sf -H "Authorization: Bearer $TOKEN" \
  https://app.overslash.com/v1/approvals/abc-123
```

**Step 3 — execute.** If `execution.result` is not in the resolved JSON, call:

```
overslash_call { "approval_id": "abc-123" }
```

**Never re-submit the original parameters once an approval exists** — that
creates a second approval instead of resuming the first.

## Pending executions

An approved action sits as a pending execution (15-minute TTL) until the agent
triggers it. Use the built-in `overslash` platform service — handy at session
start to catch work that survived an interrupted session:

| Action | Effect |
|---|---|
| `list_pending` | Lists your approved-but-unexecuted actions |
| `call_pending` | Executes one — `params: { "approval_id": "…" }` |
| `cancel_pending` | Discards one — `params: { "approval_id": "…" }` |

```
overslash_call { "service": "overslash", "action": "list_pending" }
```
