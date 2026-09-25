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

A project-scope `.mcp.json` is checked in and carries **no absolute path** — it runs
`uv run python server.py` against the current directory. So `cd` into this folder and
run Claude Code from here; anywhere else and `uv` won't find `server.py`.

`--allowedTools` below covers the harness-level permission prompt, so the only prompt
you see is the elicitation dialog we actually care about.

Headless one-shot:

```sh
cd test-mcp-elicitation
claude --print 'Call the show_message tool with message="hello".' \
  --allowedTools 'mcp__test-elicit__show_message' \
  --permission-mode acceptEdits
cat /tmp/test-mcp-elicitation.log   # see the elicitation round-trip
```

Interactive (run from inside this folder):

```sh
cd test-mcp-elicitation
claude
# inside the session: "Use the show_message tool with message='hi'."
# the elicitation dialog will appear; pick one of the four options.
```

To probe URL mode or tasks without editing `.mcp.json`, point Claude Code at a
throwaway config instead — `--strict-mcp-config` stops it also loading this folder's:

```sh
cat > /tmp/probe-url.json <<'JSON'
{"mcpServers":{"test-elicit":{"type":"stdio","command":"uv","args":[
  "run","python","server.py",
  "--elicit-mode","url","--force","--url","https://example.com/overslash-approve"]}}}
JSON
claude --print 'Call the show_message tool with message="urlprobe".' \
  --mcp-config /tmp/probe-url.json --strict-mcp-config \
  --allowedTools 'mcp__test-elicit__show_message' --permission-mode acceptEdits
```

Server logs go to **stderr** *and* `/tmp/test-mcp-elicitation.log` (the file is
the easiest way to inspect what happened during a `--print` run, since stderr
gets multiplexed with Claude Code's own output).

## What we're checking

Per the design doc, we want empirical answers to the questions below. Answers
carry the version they were measured on — re-run and add a version rather than
overwriting, since the value of this harness is the trend.

**Read the caveat on question 4 before trusting a negative result.**

1. **Does Claude Code render the elicitation as a UI dialog?** Yes in
   interactive mode; **automatically `cancel`s in `--print` mode** (no UI to
   render). 2.1.119: ~5 ms. 2.1.278: measured 6 ms.
2. **Does it support `oneOf` titled choices?** Yes (rendered, picks fine in
   tests via the handshake driver). Unchanged in 2.1.278.
3. **Does it declare `tasks.requests.tools.call` at initialize?** **No**, in
   both 2.1.119 and 2.1.278 — capabilities are `{ "elicitation": {}, "roots":
   { "listChanged": true } }` with protocol `2025-11-25`. Flow B is not
   reachable.
4. **URL mode?** **Not reachable from this harness** — which is *not* the same
   as not supported, and the difference has already misled us once. Forcing one
   gets a clean `-32602 "Client does not support URL-mode elicitation
   requests"`, because `elicitation: {}` is form-only. But Claude Code 2.1.282
   declares `elicitation: { form: {}, url: {} }` on `2026-07-28` connections,
   and this probe is pinned to `mcp<2`, which tops out at `2025-11-25`.
   **The pin makes a negative URL-mode result unfalsifiable.** Port to `mcp`
   2.x before claiming anything about URL mode either way.
5. **What happens if the server returns `CreateTaskResult` anyway?** *Changed.*
   2.1.119 **silently swallowed it** as an empty `CallToolResult` — the worst
   failure mode, since nothing downstream could detect it. 2.1.278 **rejects it
   loudly**: "content is required when the body carries 'task' — another result
   family cannot default into an empty tools/call success". Still unreachable,
   but no longer invisible.
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
- **Pinned to `mcp>=1.10.0,<2`.** The low-level `Server` API this probe is built
  on was reshaped in mcp 2.x, so an unpinned dependency resolves to 2.x and the
  server dies at import with `'Server' object has no attribute 'list_tools'`.
  Porting is only worth it when we need to probe the `2026-07-28` revision; 1.x
  already negotiates `2025-11-25`, which is what Claude Code offers today.
- The `mcp` Python SDK supports elicitation server-side; tasks (SEP-1686) are
  not yet exposed as a stable server-side API there as of writing, so this
  mock only covers Flow A from the design doc. Flow B verification will
  require either a tasks-aware fork of the SDK or a hand-written JSON-RPC
  layer.
- `handshake_test.py` confirms that the SDK sends `elicitation/create` even
  when the client did not declare the `elicitation` capability — a spec
  violation the application layer (real Overslash) must guard against.
