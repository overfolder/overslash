# test-mcp-elicitation

Minimal MCP server used to probe how Claude Code (and other clients) handle
`elicitation/create` and the experimental `tasks` primitive. Backs the analysis
in [`docs/design/mcp-elicitation-approvals.md`](../docs/design/mcp-elicitation-approvals.md).

## What it does

One tool: `show_message(message: string)`.

On every call (unless the user previously chose "remember"), the server sends
an `elicitation/create` request to the client with a 4-way `oneOf` schema:

- **Allow once** — log the message, no rule stored
- **Allow & remember (this session)** — log the message, skip future prompts in this session
- **Allow & remember (forever)** — same but in-process "permanent" (not actually persisted)
- **Deny** — refuse the call

All server-side logs go to **stderr**. stdout is reserved for the MCP JSON-RPC
frames; printing anything there breaks the protocol.

## Run it

```sh
cd test-mcp-elicitation
uv sync
uv run python server.py            # speaks MCP over stdio
uv run python handshake_test.py    # automated bidirectional smoke test (5 scenarios)
```

## Wire it into Claude Code

A project-scope `.mcp.json` is checked in, so just `cd` into this folder and run
Claude Code from here — it will auto-discover the server. The accompanying
`.claude/settings.local.json` pre-allows `mcp__test-elicit__show_message` so the
harness-level permission prompt doesn't get in the way of the elicitation prompt
we actually care about.

Headless one-shot:

```sh
cd test-mcp-elicitation
claude --print 'Call the show_message tool with message="hello".' \
  --allowedTools 'mcp__test-elicit__show_message' \
  --permission-mode acceptEdits
tail -n 30 /tmp/test-mcp-elicitation.log   # see the elicitation round-trip
```

Interactive (run from inside this folder):

```sh
cd test-mcp-elicitation
claude
# inside the session: "Use the show_message tool with message='hi'."
# the elicitation dialog will appear; pick one of the four options.
```

To wire it globally (any directory) instead:

```sh
claude mcp add test-elicit -- uv --directory /home/arturo/code/overslash/test-mcp-elicitation run python server.py
```

Server logs go to **stderr** *and* `/tmp/test-mcp-elicitation.log` (the file is
the easiest way to inspect what happened during a `--print` run, since stderr
gets multiplexed with Claude Code's own output).

## What we're checking

Per the design doc, we want empirical answers to:

1. **Does Claude Code render the elicitation as a UI dialog?** Yes in
   interactive mode; **automatically `cancel`s within ~5ms in `--print` mode**
   (no UI to render). Confirmed against 2.1.119.
2. **Does it support `oneOf` titled choices?** Yes (rendered, picks fine in
   tests via the handshake driver).
3. **Does it declare `tasks.requests.tools.call` at initialize?** **No** in
   2.1.119 — capabilities are `{ "elicitation": {}, "roots": {} }` with
   protocol `2025-11-25`. Flow B is not reachable today.
4. **URL mode?** **Not declared** by Claude Code 2.1.119. Forcing a URL-mode
   elicitation gets a clean `-32602 "Client does not support URL-mode
   elicitation requests"` rejection.
5. **What happens if the server returns `CreateTaskResult` anyway?** Claude
   Code 2.1.119 **silently swallows it as if it were an empty `CallToolResult`**
   and never polls `tasks/get` / `tasks/result`. Worst failure mode of all —
   gives no signal the application layer could detect to fall back.
6. **What happens through a `tools/call`-only stdio bridge** (e.g. an
   OpenClaw-style `mcp2cli` wrapper that doesn't relay server-initiated
   requests)? Expect the elicitation to time out or be rejected with `-32601`
   Method not found — Overslash needs to detect this at `initialize` and route
   to the existing out-of-band approval surface instead.

## CLI flags

```
--elicit-mode {auto,form,url}     # form | url | auto (pick by client caps)
--force                           # send the chosen mode even if client didn't declare it
--url URL                         # URL to use in URL-mode elicitations
--url-outcome {approve,deny}      # simulated out-of-band outcome after client opens URL
--url-complete-after-ms N         # send notifications/elicitation/complete after N ms
--use-tasks                       # declare tasks.requests.tools.call AND return CreateTaskResult
--task-resolve-after-ms N         # delay between CreateTaskResult and the elicitation
```

The shipped `.mcp.json` currently uses `--use-tasks --force` to exercise Flow B;
flip it to `--elicit-mode form` (or remove the args entirely → defaults to
`--elicit-mode auto`) to test plain Flow A, or `--elicit-mode url --force --url
https://example.com/anything` for URL mode.

## Notes / known limits

- The "remember forever" decision is only kept in-memory; restarting the server
  resets it. Real Overslash would write a permission rule.
- `decline` and `cancel` are both treated as `deny` for this mock.
- The `mcp` Python SDK supports elicitation server-side; tasks (SEP-1686) are
  not yet exposed as a stable server-side API there as of writing, so this
  mock only covers Flow A from the design doc. Flow B verification will
  require either a tasks-aware fork of the SDK or a hand-written JSON-RPC
  layer.
- `handshake_test.py` confirms that the SDK sends `elicitation/create` even
  when the client did not declare the `elicitation` capability — a spec
  violation the application layer (real Overslash) must guard against.
