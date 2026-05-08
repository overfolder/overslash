# Claude Code setup for Overslash MCP

This page is the canonical recommended configuration for using Overslash from
Claude Code. The same snippet is mirrored in the dashboard at
`/docs/claude-code` so it's copy-pasteable next to the surface that mints
your MCP connection. If the two ever drift, this file is the source of
truth.

The shape of the rules below comes out of
[docs/design/agent-self-management.md §4](../design/agent-self-management.md).
What it codifies: every Overslash MCP tool maps to a category of risk, and
Claude Code's permission engine should match that category — auto-allow
discovery and downstream approvals, always-ask the dangerous calls.

## Recommended `settings.json`

Add this to your project's `.claude/settings.json` (or to your user-level
settings if you want it across every project):

```json
{
  "permissions": {
    "allow": [
      "mcp__overslash__overslash_search",
      "mcp__overslash__overslash_auth(action:whoami)",
      "mcp__overslash__overslash_auth(action:service_status)",
      "mcp__overslash__overslash_approve_downstream"
    ],
    "ask": [
      "mcp__overslash__overslash_call(service:overslash)",
      "mcp__overslash__overslash_approve_self"
    ]
  }
}
```

## Why each rule is in the bucket it's in

- **`overslash_search`** is read-only discovery — surface what's
  configured, nothing else. Auto-allow is safe.
- **`overslash_auth(action:whoami)` / `(action:service_status)`** are
  identity introspection. They never mutate state; auto-allow is safe.
- **`overslash_approve_downstream`** resolves an approval whose requester
  is a *proper descendant* of the caller. This is the delegation model
  working as designed: a user approves their agent, an agent approves its
  sub-agent. The server-side classifier rejects this tool whenever the
  caller is not actually an ancestor, so allow-listing it does not give
  the agent power it wouldn't already have.
- **`overslash_call(service:overslash)`** wraps the platform's own
  self-management surface (creating services, minting subagents, etc.).
  Always ask — these calls have outsized blast radius.
- **`overslash_approve_self`** lets the agent rubber-stamp its own
  approval requests. The server only accepts this tool when the human
  operator has explicitly enabled `self_approve_enabled` on the MCP
  binding (via the dashboard toggle on the agent detail page). Always
  ask — this is the human-in-the-loop escape hatch, not a default mode.

## Choosing the `relationship` from `PendingApproval`

When `overslash_call` returns a `pending_approval` envelope, it now carries
a `relationship` field. Use it to pick the right approval tool on the
first try:

| `relationship`       | Tool to call                      |
| -------------------- | --------------------------------- |
| `"self"`             | `overslash_approve_self`          |
| `"downstream"`       | `overslash_approve_downstream`    |
| `"not_in_your_chain"`| Don't try — the server will reject either tool. Bubble up. |

The tool name is for Claude Code's permission rules; the actual
allow/reject decision is made server-side by comparing
`caller.identity_id` against `approval.requester_identity_id`. Calling
the "wrong" tool simply returns a typed `not_in_your_chain` envelope
(with `reason: "self_approval_disabled"` when self-approval is off for
this binding). No state changes on a misroute.
