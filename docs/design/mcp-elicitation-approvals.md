# MCP Elicitation as Approval Surface

**Status:** Adopted for Flow A, on by default (2026-09-22, D95). Flow B (tasks-augmented) still rejected — its revisit condition is unmet. URL mode is available client-side: Codex 0.157.0 offers it on `2025-06-18` (no work needed), Claude Code 2.1.282 only on `2026-07-28` (needs a protocol bump). Codex works interactively; **headless** Codex auto-declines, which D95 reads as a real denial — see the probed Codex section.
**Date:** 2026-04-24, revised 2026-09-22 and 2026-09-25
**Related:** [`overslash.md`](overslash.md), [`mcp-integration.md`](mcp-integration.md), [`mcp-oauth-transport.md`](mcp-oauth-transport.md), [`agent-self-management.md`](agent-self-management.md)

---

## Decision

**Form-mode elicitation (Flow A) is the default approval surface for MCP clients that
declare the capability.** URL-reject did not lose; it became the substrate. Every client
still gets the `pending_approval` envelope whenever a dialog is not available or not
answered, and elicitation is the fast path layered on top for the clients that can render
one.

What changed since the original rejection is not client support — Claude Code has done
form-mode elicitation since 2.1.76 — but the *failure mode*. The blocking objection was that
elicitation's failure modes are heterogeneous and one of them is invisible. That was a fair
description of a design in which a cancel meant a denial:

> a headless client auto-cancels within milliseconds because it has no UI, and the approval
> is resolved `denied` without a human ever seeing it.

So the rule is now two-sided, and it is the whole basis for turning this on by default:

- **`decline` denies.** A human said no. The approval resolves `denied`, the model sees
  `isError: true`, and a retry does not re-prompt for something already refused.
- **Everything else falls back.** `cancel`, a dismissed dialog, a client that answers with
  `-32601`/`-32602`, a poll timeout, a disconnect, a sweeper reap — the elicitation row is
  retired, the approval is left `pending`, and the original `tools/call` is closed with the
  *byte-identical* `pending_approval` envelope the non-elicitation path would have returned.
  Nothing is lost; the agent is exactly where it would have been with elicitation off.

Identical bytes is load-bearing. An "elicitation was skipped" marker on the envelope would
let the two paths drift and would add a prompt-injection surface nothing reads, so the
fallback and the synchronous path share one constructor
(`routes/mcp/tools_call.rs::pending_approval_result`).

Three supporting choices, each of which had a plausible alternative:

1. **The re-prompt bound is per-agent and time-windowed, not per-approval.** Every gated call
   mints a *fresh* approval row — there is no dedupe in `permission_gate` — so a per-approval
   counter never binds, and the replay path 409s unless the approval is already `allowed`, so
   it cannot re-promote either. A `cancelled` row is the only signal the protocol gives us
   that this peer cannot answer dialogs, so it suppresses further elicitation for that agent
   for `CANCEL_COOLDOWN` (120s), predicated on `completed_at` rather than `created_at`.
2. **No fast-cancel heuristic.** Telling a headless auto-cancel from a human dismissal by
   latency cannot work: a focused user dismisses in ~150ms, a loaded client takes longer, and
   the measurement spans a network hop plus a 500ms poll interval. Both cases want the same
   immediate behaviour anyway, and differ only in how long to back off — which the cooldown
   expresses without guessing.
3. **A caller that did not `Accept: text/event-stream` is never upgraded.** Streamable HTTP
   puts both content types on the POST, so its absence marks a `tools/call`-only bridge.
   Upgrading one to SSE would hang the call rather than answer it.

**Default-on, and where the default lives.** Migration 123 replaces
`mcp_client_agent_bindings.elicitation_enabled` with `elicitation_opted_out`, and the platform
default moves into code (`ELICITATION_DEFAULT_ENABLED`). The old column could not express the
thing that matters: it conflated "the user turned this off" with "nobody has said anything
yet", and the second is overwhelmingly the common case.

That distinction is not academic. `oauth_mcp_clients.capabilities` is written only by
`initialize`, which needs a token, which is issued *after* consent — so a freshly-registered
`client_id` **always** has NULL capabilities when the consent page renders and when
`consent_finish` resolves. Re-registration does not help: consent reads the new `client_id`'s
row. A default keyed on `elicitation_supported`, as the first cut of this change was, therefore
pins every genuine first connect to off and fires only in tests. Removing the consent-time
capability gate is what makes default-on real; it was never the gate doing the safety work.

**The capability check now lives in exactly one place**, `elicitation_eligible`, at request
time — by which point the client has actually told us what it can do. A client that never
announced `elicitation` is still never elicited, whatever its binding says.

Existing bindings carry over unchanged (`elicitation_opted_out = NOT elicitation_enabled`,
which makes every one of them opted out, since none could have been true). That is the
deliberate **no backfill** decision: a stored `false` under the old schema cannot be told apart
from a considered opt-out, so the installed base opts in from the dashboard. An explicit
opt-out survives reauth, including reauth under a re-registered `client_id`, because consent
reads the prior binding before the upsert and a missing field inherits it.

**Flow B (tasks-augmented `tools/call`) is still rejected**, and its revisit condition is
unchanged and still unmet:

- Claude Code (and ideally Codex) **declares `tasks.requests.tools.call`** at `initialize`, *and*
- `CreateTaskResult` round-trips correctly (i.e. the client polls `tasks/get` / `tasks/result`,
  surfaces task status to the user, and resumes the model with the real result).

Re-probed at 2.1.278 (see findings below): still not declared. One thing did improve — forcing
a `CreateTaskResult` is now rejected with a clear client-side validation error instead of being
silently swallowed, so the worst failure mode in the original analysis is gone. When the
condition is met the upgrade stays additive: URL-reject remains the fallback, and task
augmentation lets the model keep working while the approval pends.

URL mode is a different story as of 2026-09-25: it shipped in Claude Code 2.1.282, on
`2026-07-28` connections. Overslash cannot reach it yet, because `initialize` answers every
handshake with a hardcoded `2025-06-18` — so sensitive flows (provider OAuth, credential entry)
still live in the dashboard, but now for a reason on our side of the wire. See *Correction: URL
mode is live* below.

---

## Context

Overslash approvals today are out-of-band: a tool call lands on the API, a permission gap creates an Approval row, and the Approval is resolved through the dashboard, the `overslash_approve` tool, a Telegram callback, or some other caller-side surface. The MCP-side feedback to the agent is "execution failed, approval `xyz` pending" — the model either polls or moves on, with no protocol-level hook that wakes it up when the approval resolves.

The MCP spec has shipped two primitives in late 2025 that map almost 1:1 onto this problem:

- **Elicitation** (`2025-06-18`, `form` mode; `2025-11-25`, `url` mode added) — a server-initiated request that pauses a tool call until the *client* collects structured input from the *user*.
- **Tasks** (`2025-11-25`, experimental) — `tools/call` becomes call-now-fetch-later: the server returns `CreateTaskResult { status: "working" }`, the model can keep going via an `io.modelcontextprotocol/model-immediate-response` placeholder, and the client polls `tasks/get` / `tasks/result` to resume.

This doc captures (a) what the spec actually says, (b) which clients ship it today, and (c) how Overslash approvals could ride on top.

## Spec answers

### Who provides the elicitation answer — agent or user?

**The user.** The spec is unambiguous: clients **MUST** "provide UI that makes it clear which server is requesting information", **MUST** "respect user privacy and provide clear decline and cancel options", and **MUST** "for form mode, allow users to review and modify their responses before sending". There is no protocol field by which a server can demand "this must be the human, not the model" — but there is also no provision for the agent to silently auto-answer; the spec models elicitation as a UI prompt by default.

In practice, *clients* may add hooks that auto-answer (Claude Code ships `Elicitation` and `ElicitationResult` hooks for exactly this — sysadmins or the user-side config can short-circuit the dialog). That decision lives entirely on the client side; the server cannot prevent it and cannot detect it. For Overslash's threat model this is acceptable — auto-answering an approval is a *client-side* policy choice, equivalent to the user editing `permissions.json`. (See *Trust boundary* below.)

The schema for the request supports flat objects with primitive properties only — `string`, `number`, `integer`, `boolean`, plus enum-via-`enum` (no titles) or enum-via-`oneOf` with `{const, title}` pairs (titled radio choices). Arrays are only allowed as a multi-select wrapper around a primitive `enum`/`anyOf`. Three response actions are returned: `accept` (with `content` matching the schema), `decline`, `cancel`.

### Does elicitation combine with tasks for async answers?

**Yes, two ways.**

1. **`tasks.requests.elicitation.create`.** A client that declares this capability lets the server task-augment the elicitation itself: the elicitation request comes back with `CreateTaskResult { status: "working" }` and the *server* polls `tasks/get` / `tasks/result` for the user's eventual answer. This is the exotic direction; it presupposes a client willing to defer its own elicitation UI. Useful if Overslash is the *requestor* (server) and wants to fire-and-forget into a queued user inbox.

2. **`tasks.requests.tools.call` + nested elicitation (the ergonomic path).** The *client* task-augments the `tools/call`. The server immediately returns `CreateTaskResult { status: "working" }` plus an optional `_meta["io.modelcontextprotocol/model-immediate-response"]` string ("Approval pending — I'll continue when it resolves"). Claude/Codex passes that string back to the model as the tool result and **keeps working on other things**. Behind the scenes the server transitions the task to `input_required`; when the client opens the `tasks/result` SSE stream it sees the elicitation request, presents the dialog (or fires its hook, or routes the user to the dashboard via URL mode), and the answer flows back tagged with `_meta["io.modelcontextprotocol/related-task"] = { taskId }`. The server completes the task and the result becomes retrievable via `tasks/result`.

This second pattern is exactly the flow the user sketched: tool call → "approval pending" placeholder → model keeps working → user resolves out-of-band → model receives the real result later. Critically, the *tool call* is what's task-augmented, not the elicitation — the elicitation is just the resume signal.

3. **`URLElicitationRequiredError` (-32042) + URL mode + `notifications/elicitation/complete`.** A degraded but useful fallback for clients that *don't* support tasks: the tool call returns the `-32042` error pointing at a dashboard URL; the client renders a "click to authorize" prompt, returns `accept` immediately when the user opens the URL, and waits for `notifications/elicitation/complete` before retrying the original `tools/call`. The model still sees a synchronous failure on the first call, but the retry is automated.

### Does Claude Code support this?

Per Anthropic's [`CHANGELOG.md`](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md):

- **2.1.76** — added MCP elicitation support ("form fields or browser URL"), plus `Elicitation` and `ElicitationResult` hooks.
- **2.1.117** — fixed a regression where `elicitation/create` requests auto-cancelled in print/SDK mode when the server finished connecting mid-turn.

Probed empirically against the locally installed **Claude Code 2.1.119** by sniffing `initialize` from the mock server (see Mock implementation below). Capabilities declared:

```
client = claude-code 2.1.119
protocolVersion = 2025-11-25
capabilities = { "elicitation": {}, "roots": {} }
```

| Feature | Status in Claude Code 2.1.119 | Notes |
|---|---|---|
| Protocol version | `2025-11-25` (latest) | Negotiated automatically |
| `elicitation/create` form mode | **Yes** | Empty `elicitation: {}` is spec-equivalent to `{ form: {} }` |
| URL mode (`elicitation: { url: {} }`) | **No, not announced** | Despite shipping protocol 2025-11-25, the URL-mode capability bit is not advertised. Empirically confirmed by forcing the server to send `mode: "url"` anyway: client rejected with `-32602 "Client does not support URL-mode elicitation requests"` — the exact spec-prescribed error. So `URLElicitationRequiredError` and the dashboard-redirect approval pattern are both unreachable today. |
| `Elicitation` / `ElicitationResult` hooks | **Yes** | Per docs; can auto-answer the dialog |
| `notifications/elicitation/complete` retry | **Untestable until URL mode lands** | Server-side calls to `send_elicit_complete` succeed but the client never observes them (we never get past the `-32602`) |
| `tasks.requests.tools.call` augmentation | **No** | Capability not declared. Flow B is not reachable today. Empirically, when a server forces a `CreateTaskResult` reply to `tools/call` anyway, Claude Code 2.1.119 **silently swallows it as if it were an empty `CallToolResult`** — no error returned, no `tasks/get` / `tasks/result` polling, the model sees "tool completed with no output". The task continues to run on the server and eventually completes, but the agent has already moved on. **This is the worst failure mode of the three** — URL mode at least returns a clean `-32602`. |
| `tasks.requests.elicitation.create` | **No** | Same. |
| Behaviour in `--print` (headless) mode | Returns `action: "cancel"` automatically (≤5 ms) | No UI to render the dialog, so the elicitation is dismissed. The 2.1.117 fix only addressed a connect-mid-turn race; the broader "no UI in headless" auto-cancel is intentional. **Critical**: any agent reaching Overslash through headless Claude Code will cancel-by-default unless the user installs an `Elicitation` hook that auto-answers. |

So **Flow A works in interactive Claude Code today** (assuming a human is present to answer); **Flow B and URL mode are blocked** on Claude Code adopting the relevant capabilities. Headless usage is a hard fail unless the user pre-loads an `Elicitation` hook that auto-answers — which is a deliberate per-server policy decision the user must make.

### Does Codex support this?

**Probed 2026-09-25** against `codex-cli` 0.157.0, authenticated, via the same
`test-mcp-elicitation/` harness. These rows are measurements, not documentation.

```
client = codex-mcp-client 0.157.0
protocolVersion = 2025-06-18
capabilities = { "experimental": { "codex/auth-change": {} },
                 "elicitation": { "form": {}, "url": {} } }
```

| Feature | Status in Codex 0.157.0 | Evidence |
|---|---|---|
| `elicitation/create` form mode | **Declared and reached.** The server's `elicitation/create` arrives. | Probe: `sending elicitation/create mode=form` |
| URL mode | **Declared and reached — on `2025-06-18`.** Forcing `mode: "url"` is *accepted*, not rejected: no `-32602`, the request goes through and comes back with an answer. | Probe with `--elicit-mode url`; contrast Claude Code, which needs `2026-07-28` for this |
| Answer in **interactive** (`codex`) | **Works.** The form dialog renders and the answer reaches the server. | Verified by the maintainer at a real terminal, 2026-09-25 |
| Answer in **headless** (`codex exec`) | **Auto-`decline`, ~1–2 ms.** Both modes. Not `cancel` — `decline`. | Probe: `elicit_form result: action=decline` at `12:00:09.222`, request sent `12:00:09.220` |
| Codex's own MCP approval gate | Blocks the `tools/call` *before* the server is reached unless approvals are relaxed — `"MCP tool call requires approval, but approval policy is never"`. `codex exec` defaults to `never`. | Probe, first two runs |
| Feature flags | `tool_call_mcp_elicitation` **stable, true**. `mcp_2026_07_28` and `codex_apps_mcp_2026_07_28` both **under development, false**. | `codex features list` |
| Tasks augmentation | Not declared. | – |

Two findings matter more than the rest.

**URL mode is reachable today, on the protocol version Overslash already speaks.** Codex
declares `elicitation: { form: {}, url: {} }` on `2025-06-18` — it does not gate URL mode behind
the `2026-07-28` era the way Claude Code does. So the *Correction* block below is right about
Claude Code and wrong as a general statement: a protocol bump is what unblocks URL mode **for
Claude Code**, not what unblocks it at all. For Codex there is nothing in the way.

**Headless Codex auto-declines, and `decline` is the one negative D95 treats as a real denial.**
This is [openai/codex#45621](https://github.com/openai/codex/issues/45621) measured rather than
cited: under `codex exec` the app-server answers `elicitation/create` itself instead of
forwarding it. The answer it picks is `decline`, in about a millisecond, in both modes.

**It is headless-only.** Interactive Codex renders the dialog and round-trips the answer — an
earlier draft of this section inferred from #45621's wording ("the app-server", which backs both
surfaces) that interactive would be affected too, and that inference was wrong. Form-mode
elicitation on interactive Codex works today. The rest of this section is about `codex exec` and
anything else driving Codex non-interactively.

That is precisely the failure D95 removed for headless Claude Code, reintroduced through the
other client — and the D95 fix does not reach it. Claude Code's headless path answers `cancel`,
which D95 routes to the `pending_approval` fallback. Codex's answers `decline`, which D95 routes
to `deny`, because a decline is a human saying no. **On the wire the two are indistinguishable,
and Overslash should not try to tell them apart** — guessing which declines are real would break
the guarantee that makes `decline` meaningful.

So the practical position for a Codex-connected agent today:

- **Nothing needs enabling, and interactive Codex works.** D95's gate is
  `capabilities.get("elicitation").is_some()`, which is shape-agnostic, so
  `{ form: {}, url: {} }` satisfies it exactly as `{}` does. Codex agents already default to
  elicitation on, and for a human at a terminal that default is correct.
- **The hazard is headless Codex only**, and it is narrow but real: every gated call is silently
  denied, with no fallback to the approval URL.
- **Suppressing elicitation for `codex-mcp-client` would be the wrong fix.** It would disable a
  working feature for every interactive user to protect the headless case, and Overslash cannot
  tell the two apart at `initialize` — the capability object and `clientInfo` are identical.
  (There is precedent for client-specific handling — `dispatch.rs` carries a claude.ai
  argument-stringification workaround — but it would not help here even if D95's eligibility path
  were willing to sniff, which it deliberately is not.)
- **What is left is the per-agent opt-out and waiting for the fix.** An operator running Codex
  headlessly against Overslash should turn elicitation off for that agent; anyone else should
  leave it on. Re-probe before acting on any of this, since a point release could close #45621.

### What about OpenClaw / `mcp2cli`-style bridges?

The relevant question is **OpenClaw as an MCP client** (consuming Overslash's MCP server), *not* OpenClaw exposed-via-MCP. The two roles have opposite plumbing requirements:

| Role | What's needed | Relevant to this doc? |
|---|---|---|
| OpenClaw exposed *via* MCP | OpenClaw runs an MCP server; outsiders call its tools. Server-side spec compliance. | No |
| OpenClaw *as* MCP client (direct, or wrapped via `mcp2cli` / similar stdio bridges) | OpenClaw must speak MCP back at Overslash, which means handling server-initiated requests like `elicitation/create` and `sampling/createMessage`, plus tasks notifications | **Yes** |

OpenClaw today consumes Overslash through the REST meta-tools, not as an MCP client (see story 1 in [`user-stories.md`](user-stories.md)). When/if it grows MCP-client capability — natively or by wrapping the Overslash MCP server through a tool like `mcp2cli` that surfaces tool calls as CLI invocations — its support matrix needs to be evaluated independently:

| Feature | Status in OpenClaw-as-MCP-client | Notes |
|---|---|---|
| `tools/call` over stdio/HTTP | Implementable trivially; this is what `mcp2cli`-style bridges already cover | – |
| `elicitation/create` round-trip | **Depends on the bridge.** A naive `mcp2cli` bridge that only forwards `tools/call` and pipes results back will silently drop server-initiated requests, leaving Overslash hanging until the request times out | If OpenClaw goes this path, the bridge must declare `elicitation` capability *and* relay the request back to OpenClaw's prompt loop |
| URL mode | Trivial if the bridge can print a URL to OpenClaw's chat | – |
| `tasks` augmentation | Same as above — bridge must implement it | – |

**Implication for Overslash:** the elicitation flow described in this doc is gated on the *client* speaking full MCP. For OpenClaw and any other agent reached only through a `tools/call`-only bridge, Overslash must continue to fall back to the existing out-of-band approval surfaces (URL printed in chat, `overslash_approve`, dashboard). The mock server below should also exercise this case — connecting it through a stdio-bridge that only forwards `tools/call` should produce a deterministic "client doesn't declare `elicitation`" failure that Overslash can detect at `initialize` time and switch flows.

## Proposed Overslash flow

Two flows, depending on what the client supports. The *server* implementation is the same; the *behaviour observed by the model* differs based on the client's declared capabilities at `initialize`.

### Flow A — Synchronous elicitation (works today)

Available on Claude Code 2.1.76+, Codex v2 post-merge.

```
1. Claude → POST /mcp  tools/call  service_x.action_y(args)
2. Overslash determines a permission gap. Instead of returning "approval pending",
   it sends elicitation/create back to the client with mode="form". The form
   asks for the decision only:

   {
     "message": "Allow this agent to: <action description>?",
     "requestedSchema": {
       "type": "object",
       "properties": {
         "decision": {
           "type": "string",
           "title": "Decision",
           "oneOf": [
             { "const": "allow",          "title": "Allow once" },
             { "const": "allow_remember", "title": "Allow & remember" },
             { "const": "deny",           "title": "Deny" },
             { "const": "bubble_up",      "title": "Ask my parent" }
           ],
           "default": "allow"
         }
       },
       "required": ["decision"]
     },
     "_meta": { "io.overslash/suggested_tiers": ..., "io.overslash/disclosed_fields": ...,
                "io.overslash/risk": ... }
   }

3. Claude Code shows a dialog. User picks one of the four options.
4. Client returns { action: "accept", content: { decision: "allow_remember" } }.
5. Overslash:
     - "allow"           → resolve, execute the call, do not modify rules
     - "deny"            → return tool error
     - "bubble_up"       → hand the approval to the next resolver up, tool error
     - "allow_remember"  → do NOT resolve yet. Open a follow-up row
                           (`elicit_remember_<uuid>`), mark this row
                           `follow_up`, and the originator's stream emits a
                           second elicitation/create on the same SSE response:

       {
         "message": "Remember permission to: <action description>",
         "requestedSchema": { "type": "object", "properties": {
           "scope": { "type": "string", "title": "Remember for",
                      "oneOf": [ { "const": "[\"<tier 0 keys>\"]", "title": "<tier 0 description>" },
                                 ... one per suggested tier, narrowest first ... ],
                      "default": "[\"<tier 0 keys>\"]" },
           "ttl":   { "type": "string", "title": "For how long",
                      "oneOf": [ forever | 1h | 24h | 7d | 30d ], "default": "forever" } } }
       }

       Accepting it resolves `allow_remember` with `remember_keys` = the picked
       tier (a JSON-encoded key array, validated by /resolve like any
       dashboard pick) and the TTL, then executes.
6. Tool result flows back to the model, Claude continues.

Why two dialogs: MCP forms are flat — every field renders at once and none can
depend on another — so a single form had to show "for how long" next to Deny
and Allow once, where it means nothing, and had no room for a scope choice at
all. Only "Allow & remember" needs scope and duration, so only it asks.

action == "decline"  → tool error "denied by user", same as decision="deny".
                       On the *remember* dialog it is instead treated like
                       cancel: the user already said allow and backed out of
                       the details, which is not a denial.
action == "cancel"   → NOT a denial. Retire the elicitation row, leave the
                       approval pending, and close the tools/call with the
                       same pending_approval envelope the no-elicitation path
                       returns. Then suppress elicitation for this agent for
                       CANCEL_COOLDOWN, because a cancel is the only evidence
                       we get that this client cannot answer dialogs.
```

Sensitive flows (provider OAuth, credential entry) take URL mode instead — return `URLElicitationRequiredError` pointing at `/dashboard/approvals/<id>`. The dashboard handles the approval, then sends `notifications/elicitation/complete` back to the client and Claude Code retries the original tool call.

### Flow B — Asynchronous via task-augmented `tools/call` (when client opts in)

Triggered when the client's `initialize` declares `capabilities.tasks.requests.tools.call`.

```
1. Claude Code (with tasks capability) → POST /mcp
   tools/call ... params.task = { ttl: 600000 }

2. Overslash detects task-augmented request. Returns immediately:
   {
     "task": {
       "taskId": "approval-<uuid>",
       "status": "working",
       "ttl": 600000,
       "pollInterval": 2000
     },
     "_meta": {
       "io.modelcontextprotocol/model-immediate-response":
         "Approval pending for <service.action>. The user will resolve it; \
          continue with other work and check back."
     }
   }

3. Model gets the immediate-response string as the tool result, keeps working.

4. Overslash creates the Approval row and (optionally) pushes notifications
   through existing channels (Telegram, dashboard, email).

5. Client polls tasks/get every 2s. Once Overslash needs the actual decision
   (default: immediately) it transitions task → input_required.

6. Client opens tasks/result SSE; Overslash sends elicitation/create over that
   stream (form or URL mode, same shapes as Flow A) tagged with
   _meta["io.modelcontextprotocol/related-task"] = { taskId }.

7. User answers (in dialog, hook, or dashboard). Client returns elicitation
   response, also tagged with related-task.

8. Overslash applies the decision, executes the underlying action, transitions
   task → completed (or failed on deny / error).

9. Client's tasks/result completes, real CallToolResult flows back, model
   resumes the original line of reasoning.
```

The two flows share the *same elicitation schema and the same Overslash decision logic*. The branch is entirely on whether the client task-augmented the call. No protocol fork, no separate `overslash_approve_async` tool.

### Trust boundary

The agent can never silently bypass an approval by answering the elicitation itself, because:

1. **The elicitation request is sent to the client process, not back into the model's tool-call loop.** The model never sees the request as a tool call it can answer.
2. **Auto-answer hooks are user-side configuration.** A hook that always returns `decision: "allow_once"` is functionally equivalent to a user-side `permissions.json` rule that pre-authorizes the action — and Overslash already trusts user-side permission configuration. The mitigation is that hooks live in the user's editor config, not in any agent-controllable surface.
3. **Server-side rule reuse stays gated by Overslash's identity model.** "Allow & remember" creates an org/user-scoped permission rule via the existing rule machinery; the rule subsequently applies without re-prompting. This is identical to today's "approve then add rule" UX.

## Open questions / what to verify

1. **Does Claude Code 2.1.76 actually advertise `tasks` capability?** Inspect `initialize` from the mock server. If yes, Flow B works today.
2. **Codex URL-mode support and notifications/elicitation/complete handling.** Probably yes, not confirmed.
3. **`overslash_approve` semantics under Flow A.** Probably becomes redundant for the in-band case but remains useful for cross-identity approvals (a user resolving an approval raised by an agent in a different session).
4. ~~**Rate-limiting on elicitation prompts.**~~ **Answered.** Not a dedupe on (subject, action, resource) — that shape cannot work, because every gated call mints a fresh approval. Instead a per-agent cooldown keyed on the last *cancelled* elicitation (`CANCEL_COOLDOWN`, 120s). See Decision point 1.
5. **Hook-based auto-answer policy disclosure.** Should Overslash audit-log when an elicitation is answered without a visible user dialog? The client doesn't tell the server, so this is fundamentally invisible — document the limitation rather than try to detect it.

## Mock implementation

[`test-mcp-elicitation/`](../../test-mcp-elicitation/) at the repo root contains a minimal Python `mcp`-SDK server with a single `show_message(message)` tool that prompts the user via `elicitation/create` (titled `oneOf` choices: Allow once / Allow & remember session / Allow & remember forever / Deny) before logging the message. The companion `handshake_test.py` drives it through stdio as a stand-in MCP client and exercises the accept / decline / cancel / remember / no-capability scenarios.

Empirical findings from the mock (run 2026-04-24, `mcp` SDK 1.27.0, Claude Code 2.1.119):

- **Form-mode elicitation works end-to-end** with `oneOf` + `const` + `title` schemas: the SDK forwards them verbatim, accept/decline/cancel all behave per spec, and `_meta` plumbing for related-task IDs is present.
- **The Python `mcp` SDK does not gate `elicitation/create` on the client's declared capability.** A server calling `session.elicit_form(...)` will send the request even when the client's `initialize` did not declare `elicitation`. The spec says servers **MUST NOT** do this. *Implication for Overslash:* the application layer must inspect the negotiated client capabilities at `initialize` and short-circuit to the existing out-of-band approval surface when elicitation isn't on offer. We cannot rely on the SDK to refuse.
- **URL-mode elicitation rejected with `-32602` by Claude Code 2.1.119**, with the message "Client does not support URL-mode elicitation requests". Tested by running the mock with `--elicit-mode url --force --url https://example.com/overslash-approve`. This is the spec-prescribed rejection — clean and detectable. URL mode (and therefore the dashboard-redirect approval flow + `notifications/elicitation/complete` retry pattern) remains gated on Claude Code adopting `elicitation: { url: {} }`.
- **`CreateTaskResult` silently swallowed by Claude Code 2.1.119** when the server returns one without the client task-augmenting the request. Tested with `--use-tasks --force --task-resolve-after-ms 500`: server declares full `tasks.requests.tools.call` capability, returns a `CreateTaskResult { task: { taskId, status: "working" } }` plus an `io.modelcontextprotocol/model-immediate-response` placeholder, spawns a background resolver that fires elicitation and completes the task. **Claude Code reports "tool completed with no output" to the model and never polls `tasks/get` or `tasks/result`.** No error is surfaced; the call is effectively dropped on the floor. This is *worse* than the URL-mode rejection, because it gives no signal Overslash could detect to fall back. Until Claude Code declares `tasks` support, Flow B must not be attempted.
- **Tasks server-side support in the `mcp` SDK is sufficient.** `CreateTaskResult` can be returned from `@server.call_tool()`; `request_handlers[GetTaskRequest]` etc. accept hand-registered handlers. The mock implements the full lifecycle (working → completed) and a basic `tasks/cancel`. So the *server* side of Flow B is implementable today; what's missing is a client that participates.

### Re-probe: Claude Code 2.1.278 (run 2026-09-22, `mcp` SDK 1.30.0)

Same mock, same three scenarios, five months on. The 2.1.119 rows above are left
untouched — the point of keeping both is the trend.

```
client = claude-code 2.1.278
protocolVersion = 2025-11-25
capabilities = { "elicitation": {}, "roots": { "listChanged": true } }
```

| Feature | 2.1.119 | 2.1.278 | Notes |
|---|---|---|---|
| Protocol version | `2025-11-25` | `2025-11-25` | The bundle also carries `2026-07-28` wire schemas, but stdio still negotiates `2025-11-25`. |
| Form-mode elicitation | Yes | **Yes** | Unchanged. `oneOf` + `const` + `title` renders and round-trips. |
| URL mode | `-32602` | **`-32602`** — but see the correction below | *"Client does not support URL-mode elicitation requests"*, and `elicitation: {}` is form-only. Both true as measured, and both an artifact of the negotiated era: this probe cannot reach `2026-07-28`, where the answer is different. |
| `tasks.requests.tools.call` | Not declared; **silently swallowed** | Not declared; **rejected loudly** | *This is the one thing that changed.* Forcing a `CreateTaskResult` now fails client-side schema validation — *"content is required when the body carries 'task' — another result family cannot default into an empty tools/call success"* — and the model is told the call failed. The worst failure mode in the original table is gone. Flow B is still unreachable, but it is no longer invisible. |
| `--print` / headless | auto-`cancel` | **auto-`cancel`, ~6 ms** | Measured: `elicitation/create` sent at `15:12:40.659`, `action=cancel` at `15:12:40.665`. `handleElicitation` opens with `if (!this.hostAnswersElicitations) return { action: "cancel" }`. An `Elicitation` hook still gets first refusal. |

The headless number is the one that matters. With the mock's own `cancel → deny` mapping —
the same mapping Overslash shipped — the run ended with Claude reporting to the user:

> *"The call was denied — the elicitation prompt came back as a rejection, so the message was
> not logged on the server."*

Nobody denied anything. That is the failure this design has to rule out before elicitation can
be a default, and it is why `cancel` no longer means `deny` (see the Decision section).

**Flow B's revisit condition is still unmet.** `tasks.requests.tools.call` is not declared;
the capability producer in the 2.1.278 bundle emits `{ roots: { listChanged: true },
elicitation: {} }`, with a `tasks.requests.elicitation.create` branch sitting behind a function
that hard-returns `false`. Flow B stays out of scope.

### Correction: URL mode is live (2026-09-25)

**The row above is a measurement, not a verdict, and the verdict drawn from it was wrong.**
Claude Code **2.1.282** (2026-09-24) shipped URL-mode elicitation — two days after the probe
run. From its changelog:

> Added MCP URL-mode elicitation on 2026-07-28 protocol connections, so servers can ask Claude
> Code to open a browser-based flow; no waiting dialog is left on screen when the server has no
> way to confirm completion

Confirmed in the 2.1.282 bundle. There are two capability producers, and which one runs depends
on the negotiated era:

```js
function qfn(){ return { roots:{listChanged:true}, elicitation:{}, ... } }   // legacy
function _dr(){ let e = B5(); if(!m3e()) return e;
                return { ...e, elicitation:{ form:{}, url:{} } } }           // 2026-07-28
function m3e(){ return x("tengu_mcp_url_elicitation", true) }                // flag, default on
```

So on a `2026-07-28` connection Claude Code declares `elicitation: { form: {}, url: {} }`, gated
behind a remote flag that defaults **on**. (A per-server `bareElicitationCapability` option in
`.mcp.json` forces the old bare shape back, for servers that choke on the richer one.)

**Two compounding reasons the probe said otherwise**, both worth remembering before trusting a
future negative result from it:

1. The run was on 2.1.278, which predates the feature.
2. The probe is pinned to `mcp>=1.10.0,<2`, and the 1.x Python SDK tops out at `2025-11-25`.
   That pin was added *by this work*, to keep the low-level `Server` API the probe is built on.
   It therefore guarantees a legacy negotiation — and a legacy negotiation guarantees
   `elicitation: {}`. **A negative URL-mode result from this harness is currently unfalsifiable**
   until the probe is ported to `mcp` 2.x. Treat the row above as "not reachable from here",
   never as "not supported".

**The blocker is ours, for Claude Code specifically.** `routes/mcp/initialize.rs` answers every
handshake with a hardcoded `"protocolVersion": "2025-06-18"`, so an Overslash connection never
reaches the era where *Claude Code* offers `url`. Supporting `2026-07-28` is real work — a
different wire schema, not a constant bump — and is deliberately out of scope here. What changed
is *why* URL mode is unavailable to that client: it is no longer "the client doesn't do it."

**This does not generalise, and the first draft of this block wrongly implied it did.** Codex
0.157.0 declares `elicitation: { form: {}, url: {} }` on `2025-06-18` — see the probed Codex
section above — so for a Codex-connected agent URL mode needs no protocol work at all. The era
gate is a Claude Code property, not a property of URL mode.

What that would unlock, when someone picks it up — the URL-returning paths that form mode can
never serve, because the spec forbids credentials and OAuth in a form and because a browser
round trip needs `notifications/elicitation/complete` to report back:

| Path | Envelope | Note |
|---|---|---|
| `auth_url` | `needs_authentication`, `reauth_required`, `missing_scopes` | The canonical case: authorize at the provider, `elicitation/complete`, client retries the original `tools/call`. |
| `provide_url` | `request_secret` | Credential entry. Form mode is forbidden here even where it would work. |
| `setup_url` | `create_service` setup bundle | Wrinkle: a multi-slot template hands over *several* links (`requests[]`), and elicitation is one request / one answer. Needs design even once URL mode is available. |
| `download_url` | `_full_result` (D61) | **Not** a candidate — the agent fetches it, no human in the loop. Same for `hint_url`. |

`approval_url` already moved, under D95. It was the only one of the set that is a pure
structured decision with no secret in it, which is exactly why it was reachable in form mode.

One line in the code reads differently in this light. `routes/mcp/tools_call.rs` says the typed
envelopes bypass elicitation because *"the agent has structured branching info already, no
human-in-the-loop dialog applies."* That is half true: no dialog applies **to the agent**, but
every one of those envelopes ends with a human opening a URL. Worth rewording whenever URL mode
is picked up, because as written it reads as a design decision rather than a client limitation.

See the test directory's README for run instructions and the exact `claude mcp add` / `.mcp.json` setup to wire it into Claude Code.
