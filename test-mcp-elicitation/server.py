"""Mock MCP server that gates a single tool behind an elicitation prompt.

Goal: empirically verify how Claude Code (and other MCP clients) handle the
flow Overslash wants to use for approvals — server sends `elicitation/create`
mid-tool-call, user picks Allow / Allow & Remember / Deny, server logs the
decision and either returns the message or refuses.

Also probes the client's declared capabilities at `initialize` so we can see
whether it has `elicitation` (and which sub-modes), `roots`, and the
experimental `tasks` support that would unlock async approvals.

CLI flags let us deliberately violate the negotiated capabilities — e.g.,
send a URL-mode elicitation to a client that only declared form mode — to
see what each MCP client actually does in that situation.

Run via stdio:
    uv run python server.py [flags]
or hooked into Claude Code via the project's .mcp.json (see README.md).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server


# --- Logging -----------------------------------------------------------------
# CRITICAL: stdio MCP uses stdout for JSON-RPC. Logs MUST go to stderr or a
# file, never stdout, or the client will reject the frames as malformed.

_LOG_FILE = "/tmp/test-mcp-elicitation.log"
logging.basicConfig(
    level=logging.INFO,
    format="[test-mcp-elicit %(asctime)s %(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(_LOG_FILE, mode="a"),
    ],
)
log = logging.getLogger("test-mcp-elicitation")
log.info("=== new server process (PID %d) argv=%s ===", os.getpid(), sys.argv)


# --- CLI ---------------------------------------------------------------------

@dataclass
class Config:
    elicit_mode: str = "auto"          # auto | form | url
    force: bool = False                # send even if client didn't declare it
    url: str = "https://example.com/approve"
    url_outcome: str = "approve"       # what to do after client accepts URL: approve | deny
    url_complete_after_ms: int = 0     # if >0, send notifications/elicitation/complete after this delay
    use_tasks: bool = False            # try to wrap the tool result as a CreateTaskResult
    task_resolve_after_ms: int = 300   # delay between CreateTaskResult and task completion


def parse_args() -> Config:
    p = argparse.ArgumentParser(prog="test-mcp-elicitation")
    p.add_argument(
        "--elicit-mode", choices=["auto", "form", "url"], default="auto",
        help="Which elicitation mode to send. 'auto' inspects the client's "
             "declared capabilities and picks form if available, else url.",
    )
    p.add_argument(
        "--force", action="store_true",
        help="Send the chosen mode even if the client did not declare it. "
             "Useful for probing how clients react to spec violations.",
    )
    p.add_argument(
        "--url", default="https://example.com/approve",
        help="URL to send for URL-mode elicitations. Per spec, must be a "
             "valid URL; the client should display it for user consent.",
    )
    p.add_argument(
        "--url-outcome", choices=["approve", "deny"], default="approve",
        help="After the client returns accept (user opened URL), simulate "
             "the out-of-band approval outcome.",
    )
    p.add_argument(
        "--url-complete-after-ms", type=int, default=0,
        help="If >0, wait this many ms after the URL accept and then send "
             "notifications/elicitation/complete to simulate the out-of-band "
             "flow finishing.",
    )
    p.add_argument(
        "--use-tasks", action="store_true",
        help="Declare server-side tasks.requests.tools.call capability AND "
             "return a CreateTaskResult from tools/call (Flow B). The "
             "elicitation/resolution then runs as a background task; the "
             "client is expected to poll tasks/get and tasks/result. "
             "Will violate the spec if the client did not also declare tasks "
             "support, but lets us observe what the client does.",
    )
    p.add_argument(
        "--task-resolve-after-ms", type=int, default=300,
        help="When --use-tasks: after creating the task, wait this many ms "
             "before sending the elicitation and resolving the task. Lets "
             "the client receive CreateTaskResult and start polling first.",
    )
    args = p.parse_args()
    return Config(
        elicit_mode=args.elicit_mode,
        force=args.force,
        url=args.url,
        url_outcome=args.url_outcome,
        url_complete_after_ms=args.url_complete_after_ms,
        use_tasks=args.use_tasks,
        task_resolve_after_ms=args.task_resolve_after_ms,
    )


# --- The tool ----------------------------------------------------------------

TOOL_NAME = "show_message"

TOOL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "message": {
            "type": "string",
            "description": "Message to log on the server side after approval.",
        }
    },
    "required": ["message"],
    "additionalProperties": False,
}

# The form-mode elicitation we send back to the client.
# Uses oneOf+const+title to render as titled radio choices per spec.
APPROVAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "decision": {
            "type": "string",
            "title": "Decision",
            "description": "How should this show_message call be handled?",
            "oneOf": [
                {"const": "allow_once",            "title": "Allow once"},
                {"const": "allow_remember_session","title": "Allow & remember (this session)"},
                {"const": "allow_remember_forever","title": "Allow & remember (forever)"},
                {"const": "deny",                  "title": "Deny"},
            ],
            "default": "allow_once",
        }
    },
    "required": ["decision"],
    "additionalProperties": False,
}


@dataclass
class State:
    """In-memory remembered approvals (mock substitute for Overslash rules)."""
    remember_session: bool = False
    remember_forever: bool = False  # would be persisted to disk in real life
    client_capabilities: dict[str, Any] = field(default_factory=dict)
    client_name: str = "<unknown>"
    client_version: str = "<unknown>"
    protocol_version: str = "<unknown>"

    def is_pre_approved(self) -> bool:
        return self.remember_session or self.remember_forever


@dataclass
class TaskRecord:
    task_id: str
    status: str = "working"  # working | input_required | completed | failed | cancelled
    status_message: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_ms: int = 60000
    result_event: asyncio.Event = field(default_factory=asyncio.Event)
    final_result: types.CallToolResult | None = None

    def to_task(self) -> types.Task:
        return types.Task(
            taskId=self.task_id,
            status=self.status,  # type: ignore[arg-type]
            statusMessage=self.status_message,
            createdAt=self.created_at,
            lastUpdatedAt=self.updated_at,
            ttl=self.ttl_ms,
            pollInterval=500,
        )


def make_server(cfg: Config) -> Server:
    server: Server = Server("test-mcp-elicitation")
    state = State()
    tasks: dict[str, TaskRecord] = {}

    def _record_client_caps() -> None:
        if state.client_capabilities:
            return
        try:
            params = server.request_context.session._client_params  # type: ignore[attr-defined]
            state.client_capabilities = params.capabilities.model_dump(exclude_none=True)
            state.client_name = params.clientInfo.name
            state.client_version = params.clientInfo.version
            state.protocol_version = params.protocolVersion
            log.info(
                "client name=%s version=%s protocol=%s capabilities=%s",
                state.client_name, state.client_version,
                state.protocol_version,
                json.dumps(state.client_capabilities),
            )
        except Exception as e:
            log.warning("could not introspect client capabilities: %s", e)

    def _client_supports(elicit_mode: str) -> bool:
        elicit = state.client_capabilities.get("elicitation")
        if elicit is None:
            return False
        # Per spec: empty elicitation: {} == form mode only
        if not elicit:
            return elicit_mode == "form"
        return elicit_mode in elicit

    def _resolve_effective_mode() -> str | None:
        """Pick form / url / None depending on cfg + client caps."""
        if cfg.elicit_mode in ("form", "url"):
            wanted = cfg.elicit_mode
            if _client_supports(wanted):
                return wanted
            if cfg.force:
                log.warning(
                    "client did NOT declare elicitation.%s — sending anyway "
                    "because --force was passed (spec violation; observing "
                    "client behaviour)", wanted,
                )
                return wanted
            log.warning(
                "client did NOT declare elicitation.%s and --force is off; "
                "no fallback set — will deny", wanted,
            )
            return None
        # auto
        if _client_supports("form"):
            return "form"
        if _client_supports("url"):
            return "url"
        if cfg.force:
            log.warning(
                "client declared no elicitation modes; --force on, defaulting "
                "to form-mode anyway",
            )
            return "form"
        return None

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        _record_client_caps()
        return [
            types.Tool(
                name=TOOL_NAME,
                title="Show Message (gated)",
                description=(
                    "Logs the given message on the server. Each call (unless a "
                    "previous answer remembered the decision) prompts the user "
                    "via MCP elicitation. Server-side flags decide whether to "
                    "use form mode, URL mode, or experimental task augmentation."
                ),
                inputSchema=TOOL_SCHEMA,
            )
        ]

    async def _do_show_message_sync(message: str) -> types.CallToolResult:
        """Run the elicitation flow inline and produce a CallToolResult."""
        decision = await _resolve_decision(
            server, state, cfg, _resolve_effective_mode,
        )
        log.info("resolved decision: %s", decision)
        if decision == "deny":
            return types.CallToolResult(
                content=[types.TextContent(
                    type="text",
                    text=f"DENIED. Message was not shown: {message!r}",
                )],
                isError=False,
            )

        if decision == "allow_remember_session":
            state.remember_session = True
        elif decision == "allow_remember_forever":
            state.remember_forever = True

        ts = datetime.now(timezone.utc).isoformat()
        log.info("=== SHOW_MESSAGE [%s] %s ===", ts, message)

        return types.CallToolResult(
            content=[types.TextContent(
                type="text",
                text=(
                    f"Shown at {ts}.\n"
                    f"Message: {message}\n"
                    f"Decision applied: {decision}"
                ),
            )],
            isError=False,
        )

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> types.CallToolResult | types.CreateTaskResult:
        if name != TOOL_NAME:
            raise ValueError(f"unknown tool {name!r}")

        _record_client_caps()
        message = (arguments or {}).get("message", "")
        log.info("tool call: show_message(message=%r) use_tasks=%s",
                 message, cfg.use_tasks)
        log.info(
            "current state: remember_session=%s remember_forever=%s",
            state.remember_session, state.remember_forever,
        )

        if not cfg.use_tasks:
            return await _do_show_message_sync(message)

        # --- Flow B: task-augmented response ---------------------------------
        client_tasks = state.client_capabilities.get("tasks")
        if not client_tasks and not cfg.force:
            log.warning(
                "client did not declare tasks capability and --force is off; "
                "falling back to synchronous flow",
            )
            return await _do_show_message_sync(message)
        if not client_tasks:
            log.warning(
                "client did not declare tasks capability; sending "
                "CreateTaskResult anyway because --force was passed",
            )

        task_id = f"task-{uuid.uuid4()}"
        rec = TaskRecord(task_id=task_id, status="working",
                         status_message="Approval pending")
        tasks[task_id] = rec
        log.info("created task %s for show_message(%r)", task_id, message)

        async def _resolver() -> None:
            try:
                if cfg.task_resolve_after_ms:
                    await asyncio.sleep(cfg.task_resolve_after_ms / 1000)
                log.info("task %s: resolving (sending elicitation)", task_id)
                result = await _do_show_message_sync(message)
                rec.final_result = result
                rec.status = "completed" if not result.isError else "failed"
                rec.status_message = "Done."
                rec.updated_at = datetime.now(timezone.utc)
                rec.result_event.set()
                log.info("task %s: %s", task_id, rec.status)
                # Best-effort status notification
                try:
                    sess = server.request_context.session
                    await sess.send_notification(
                        types.ServerNotification(
                            types.TaskStatusNotification(
                                method="notifications/tasks/status",
                                params=types.TaskStatusNotificationParams(
                                    taskId=task_id,
                                    status=rec.status,  # type: ignore[arg-type]
                                    statusMessage=rec.status_message,
                                    createdAt=rec.created_at,
                                    lastUpdatedAt=rec.updated_at,
                                    ttl=rec.ttl_ms,
                                    pollInterval=500,
                                ),
                            )
                        )
                    )
                except Exception as e:
                    log.warning("could not send tasks/status notification: %s", e)
            except Exception as e:
                log.exception("task %s resolver crashed: %s", task_id, e)
                rec.status = "failed"
                rec.status_message = str(e)
                rec.updated_at = datetime.now(timezone.utc)
                rec.result_event.set()

        asyncio.create_task(_resolver())

        log.info("returning CreateTaskResult for task %s", task_id)
        return types.CreateTaskResult(
            task=rec.to_task(),
            meta={
                "io.modelcontextprotocol/model-immediate-response": (
                    "Approval pending for show_message. The user will resolve "
                    "this out-of-band. Continue with other work; you can poll "
                    "tasks/get or wait for tasks/result."
                )
            },
        )

    # --- tasks/get / tasks/result handlers ----------------------------------

    async def _handle_get_task(
        req: types.GetTaskRequest,
    ) -> types.ServerResult:
        tid = req.params.taskId
        rec = tasks.get(tid)
        log.info("tasks/get %s -> %s", tid, rec.status if rec else "MISSING")
        if rec is None:
            raise types.McpError(
                types.ErrorData(code=-32602, message=f"Task not found: {tid}")
            )
        return types.ServerResult(
            types.GetTaskResult(
                taskId=rec.task_id,
                status=rec.status,  # type: ignore[arg-type]
                statusMessage=rec.status_message,
                createdAt=rec.created_at,
                lastUpdatedAt=rec.updated_at,
                ttl=rec.ttl_ms,
                pollInterval=500,
            )
        )

    async def _handle_get_task_result(
        req: types.GetTaskPayloadRequest,
    ) -> types.ServerResult:
        tid = req.params.taskId
        rec = tasks.get(tid)
        log.info("tasks/result %s -> awaiting", tid)
        if rec is None:
            raise types.McpError(
                types.ErrorData(code=-32602, message=f"Task not found: {tid}")
            )
        await rec.result_event.wait()
        log.info("tasks/result %s -> ready (status=%s)", tid, rec.status)
        if rec.final_result is None:
            raise types.McpError(
                types.ErrorData(code=-32603, message="Task has no result"),
            )
        return types.ServerResult(rec.final_result)

    async def _handle_cancel_task(
        req: types.CancelTaskRequest,
    ) -> types.ServerResult:
        tid = req.params.taskId
        rec = tasks.get(tid)
        log.info("tasks/cancel %s", tid)
        if rec is None:
            raise types.McpError(
                types.ErrorData(code=-32602, message=f"Task not found: {tid}")
            )
        if rec.status in {"completed", "failed", "cancelled"}:
            raise types.McpError(types.ErrorData(
                code=-32602,
                message=f"Cannot cancel task: terminal status {rec.status!r}",
            ))
        rec.status = "cancelled"
        rec.status_message = "Cancelled by client request"
        rec.updated_at = datetime.now(timezone.utc)
        rec.result_event.set()
        return types.ServerResult(types.CancelTaskResult(
            taskId=rec.task_id,
            status="cancelled",
            statusMessage=rec.status_message,
            createdAt=rec.created_at,
            lastUpdatedAt=rec.updated_at,
            ttl=rec.ttl_ms,
            pollInterval=500,
        ))

    if cfg.use_tasks:
        server.request_handlers[types.GetTaskRequest] = _handle_get_task
        server.request_handlers[types.GetTaskPayloadRequest] = _handle_get_task_result
        server.request_handlers[types.CancelTaskRequest] = _handle_cancel_task
        log.info("registered tasks/get, tasks/result, tasks/cancel handlers")

    return server


async def _resolve_decision(
    server: Server,
    state: State,
    cfg: Config,
    pick_mode: Any,
) -> str:
    """Either reuse a remembered approval, or prompt via the configured mode."""
    if state.remember_forever:
        return "allow_remember_forever"
    if state.remember_session:
        return "allow_remember_session"

    mode = pick_mode()
    if mode is None:
        log.warning("no usable elicitation mode; denying")
        return "deny"

    session = server.request_context.session
    log.info("sending elicitation/create mode=%s ...", mode)

    if mode == "form":
        return await _resolve_via_form(session)
    if mode == "url":
        return await _resolve_via_url(session, cfg)
    raise RuntimeError(f"unknown mode {mode!r}")


async def _resolve_via_form(session: Any) -> str:
    try:
        result = await session.elicit_form(
            message=(
                "test-mcp-elicitation wants to log a message. "
                "Approve once, approve & remember, or deny?"
            ),
            requestedSchema=APPROVAL_SCHEMA,
        )
    except Exception as e:
        log.warning("elicit_form failed (%s) — denying", e)
        return "deny"

    log.info("elicit_form result: action=%s content=%s",
             result.action, result.content)

    if result.action != "accept":
        return "deny"

    decision = (result.content or {}).get("decision", "allow_once")
    if decision not in {"allow_once", "allow_remember_session",
                        "allow_remember_forever", "deny"}:
        log.warning("unexpected decision %r — denying", decision)
        return "deny"
    return decision


async def _resolve_via_url(session: Any, cfg: Config) -> str:
    elicitation_id = str(uuid.uuid4())
    url = cfg.url
    if "{id}" in url:
        url = url.replace("{id}", elicitation_id)
    elif "?" not in url and not url.endswith("/"):
        # Append the elicitation id so each prompt has a unique URL — useful
        # for testing how clients display the URL and dedup.
        url = f"{url}/{elicitation_id}"
    elif "?" not in url:
        url = f"{url}?id={elicitation_id}"

    log.info("URL elicitation: id=%s url=%s", elicitation_id, url)

    try:
        result = await session.elicit_url(
            message=(
                "test-mcp-elicitation needs you to authorize this call. "
                f"Open {url} to continue."
            ),
            url=url,
            elicitation_id=elicitation_id,
        )
    except Exception as e:
        log.warning("elicit_url failed (%s) — denying", e)
        return "deny"

    log.info("elicit_url result: action=%s content=%s",
             result.action, result.content)

    if result.action != "accept":
        # decline / cancel — user refused to even open the URL
        return "deny"

    # Per spec, accept means "user consented to open URL", not the actual
    # outcome. Simulate the out-of-band flow:
    if cfg.url_complete_after_ms > 0:
        import asyncio
        log.info("simulating out-of-band wait %dms ...", cfg.url_complete_after_ms)
        await asyncio.sleep(cfg.url_complete_after_ms / 1000)
        try:
            await session.send_elicit_complete(elicitation_id=elicitation_id)
            log.info("sent notifications/elicitation/complete for %s", elicitation_id)
        except Exception as e:
            log.warning("send_elicit_complete failed: %s", e)

    if cfg.url_outcome == "deny":
        log.info("simulated URL-mode outcome: deny")
        return "deny"
    log.info("simulated URL-mode outcome: approve (allow_once)")
    return "allow_once"


# --- Entry point -------------------------------------------------------------

async def amain() -> None:
    cfg = parse_args()
    log.info("config: %s", cfg)

    server = make_server(cfg)

    notification_options = NotificationOptions()
    capabilities = server.get_capabilities(
        notification_options=notification_options,
        experimental_capabilities={},
    )
    if cfg.use_tasks:
        capabilities = capabilities.model_copy(update={
            "tasks": types.ServerTasksCapability(
                list=None,
                cancel=types.TasksCancelCapability(),
                requests=types.ServerTasksRequestsCapability(
                    tools=types.TasksToolsCapability(call=types.TasksCallCapability()),
                ),
            ),
        })

    init_options = InitializationOptions(
        server_name="test-mcp-elicitation",
        server_version="0.1.0",
        capabilities=capabilities,
    )

    log.info(
        "server starting. Declared capabilities: %s",
        json.dumps(init_options.capabilities.model_dump(exclude_none=True)),
    )

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, init_options)


def main() -> None:
    import asyncio
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        log.info("shutting down (KeyboardInterrupt)")


if __name__ == "__main__":
    main()
