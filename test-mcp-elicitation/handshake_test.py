"""Drive the server with raw JSON-RPC over its stdio.

Acts as a tiny stand-in MCP client to verify:
- handshake (initialize / initialized / tools/list)
- the server sends elicitation/create as a server-to-client request mid-tools/call
- the tool call completes after we answer the elicitation
- accept / decline / cancel all behave as documented
- "remember" persists for subsequent calls

Run: uv run python handshake_test.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys


class Driver:
    def __init__(self, declare_elicitation: bool = True):
        self.declare_elicitation = declare_elicitation
        self.proc: asyncio.subprocess.Process | None = None
        self._next_id = 100  # client request ids start at 100 to avoid collisions

    async def start(self) -> None:
        server_dir = os.path.dirname(os.path.abspath(__file__))
        self.proc = await asyncio.create_subprocess_exec(
            sys.executable, "server.py",
            cwd=server_dir,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stop(self) -> str:
        assert self.proc and self.proc.stdin
        self.proc.stdin.close()
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            self.proc.kill()
        err = (await self.proc.stderr.read()).decode()
        return err

    async def send(self, obj: dict) -> None:
        assert self.proc and self.proc.stdin
        line = json.dumps(obj) + "\n"
        self.proc.stdin.write(line.encode())
        await self.proc.stdin.drain()
        print(">>>", line.strip())

    async def recv(self) -> dict:
        assert self.proc and self.proc.stdout
        line = await self.proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        decoded = line.decode().strip()
        print("<<<", decoded)
        return json.loads(decoded)

    async def initialize(self) -> dict:
        capabilities: dict = {}
        if self.declare_elicitation:
            capabilities["elicitation"] = {"form": {}, "url": {}}
        await self.send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": capabilities,
                "clientInfo": {"name": "handshake-test", "version": "0"},
            },
        })
        resp = await self.recv()
        await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp

    async def list_tools(self) -> dict:
        await self.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        return await self.recv()

    async def call_show_message(self, message: str, decision: str | None) -> dict:
        """Call show_message and answer the elicitation with `decision`.

        decision: "allow_once" / "allow_remember_session" /
                  "allow_remember_forever" / "deny" / None (=> action="cancel")
        Special prefix "decline:" makes us reply action=decline with no content.
        """
        call_id = self._next_id
        self._next_id += 1
        await self.send({
            "jsonrpc": "2.0", "id": call_id, "method": "tools/call",
            "params": {"name": "show_message", "arguments": {"message": message}},
        })

        # Server may either:
        # - send elicitation/create (a request from server to us), or
        # - skip it (if it has remembered an answer) and reply directly.
        while True:
            msg = await self.recv()
            if msg.get("method") == "elicitation/create":
                req_id = msg["id"]
                if decision is None:
                    reply = {"jsonrpc": "2.0", "id": req_id,
                             "result": {"action": "cancel"}}
                elif decision.startswith("decline:"):
                    reply = {"jsonrpc": "2.0", "id": req_id,
                             "result": {"action": "decline"}}
                else:
                    reply = {"jsonrpc": "2.0", "id": req_id,
                             "result": {"action": "accept",
                                        "content": {"decision": decision}}}
                await self.send(reply)
                continue
            if msg.get("id") == call_id and "result" in msg:
                return msg
            if msg.get("id") == call_id and "error" in msg:
                return msg


async def scenario_full_flow() -> None:
    print("\n=== scenario: full elicitation flow (declares elicitation) ===")
    d = Driver(declare_elicitation=True)
    await d.start()
    await d.initialize()
    await d.list_tools()

    # 1. allow_once — should NOT remember
    r = await d.call_show_message("first", decision="allow_once")
    text = r["result"]["content"][0]["text"]
    assert "Decision applied: allow_once" in text, text

    # 2. another call should re-prompt because nothing was remembered
    r = await d.call_show_message("second", decision="allow_remember_session")
    text = r["result"]["content"][0]["text"]
    assert "Decision applied: allow_remember_session" in text, text

    # 3. third call should NOT prompt (session-remembered) — server returns
    #    immediately with allow_remember_session decision
    r = await d.call_show_message("third", decision="UNUSED")
    text = r["result"]["content"][0]["text"]
    assert "Decision applied: allow_remember_session" in text, text

    err = await d.stop()
    print("\n--- stderr ---\n" + err)
    print("scenario OK")


async def scenario_deny() -> None:
    print("\n=== scenario: explicit deny ===")
    d = Driver(declare_elicitation=True)
    await d.start()
    await d.initialize()
    r = await d.call_show_message("forbidden", decision="deny")
    text = r["result"]["content"][0]["text"]
    assert "DENIED" in text, text
    await d.stop()
    print("scenario OK")


async def scenario_cancel() -> None:
    print("\n=== scenario: user cancels dialog ===")
    d = Driver(declare_elicitation=True)
    await d.start()
    await d.initialize()
    r = await d.call_show_message("ignored", decision=None)  # action=cancel
    text = r["result"]["content"][0]["text"]
    assert "DENIED" in text, text  # cancel collapses to deny in this mock
    await d.stop()
    print("scenario OK")


async def scenario_decline() -> None:
    print("\n=== scenario: user declines dialog ===")
    d = Driver(declare_elicitation=True)
    await d.start()
    await d.initialize()
    r = await d.call_show_message("ignored", decision="decline:")
    text = r["result"]["content"][0]["text"]
    assert "DENIED" in text, text
    await d.stop()
    print("scenario OK")


async def scenario_no_capability() -> None:
    print("\n=== scenario: client declares NO elicitation capability ===")
    print("    (the server *should* detect this at init and not send "
          "elicitation/create — current SDK still sends it; documenting the gap)")
    d = Driver(declare_elicitation=False)
    await d.start()
    await d.initialize()
    # If the server sent elicitation/create anyway, we still need to answer it.
    r = await d.call_show_message("hi", decision="deny")
    print("client absorbed elicitation despite not declaring capability — "
          "this is the spec violation we noted in the design doc.")
    await d.stop()


async def main() -> None:
    await scenario_full_flow()
    await scenario_deny()
    await scenario_cancel()
    await scenario_decline()
    await scenario_no_capability()
    print("\nALL SCENARIOS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
