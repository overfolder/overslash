import { spawn } from "node:child_process";
import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { JsonRpcClient, JsonRpcError } from "./jsonrpc.ts";

// Build a minimal stdio JSON-RPC server as a `node -e` child. Only runs on
// platforms where `node` is on PATH (CI / local dev).
function spawnFakeServer(script: string): ReturnType<typeof spawn> {
  return spawn("node", ["-e", script], { stdio: ["pipe", "pipe", "pipe"] });
}

describe("JsonRpcClient", () => {
  it("resolves a successful call", async () => {
    const proc = spawnFakeServer(`
      require("readline").createInterface({ input: process.stdin }).on("line", (l) => {
        const m = JSON.parse(l);
        process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { echoed: m.method } }) + "\\n");
      });
    `);
    try {
      const c = new JsonRpcClient(proc as never);
      const r = await c.call<{ echoed: string }>("ping");
      assert.equal(r.echoed, "ping");
    } finally {
      proc.kill("SIGTERM");
    }
  });

  it("rejects with JsonRpcError on server-reported error", async () => {
    const proc = spawnFakeServer(`
      require("readline").createInterface({ input: process.stdin }).on("line", (l) => {
        const m = JSON.parse(l);
        process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } }) + "\\n");
      });
    `);
    try {
      const c = new JsonRpcClient(proc as never);
      await assert.rejects(
        () => c.call("nope"),
        (err: unknown) => {
          assert.ok(err instanceof JsonRpcError);
          assert.equal((err as JsonRpcError).code, -32601);
          return true;
        },
      );
    } finally {
      proc.kill("SIGTERM");
    }
  });

  it("routes non-JSON stdout lines to the onNonJsonLine callback", async () => {
    const proc = spawnFakeServer(`
      process.stdout.write("startup banner line 1\\n");
      process.stdout.write("not-json but printed to stdout\\n");
      require("readline").createInterface({ input: process.stdin }).on("line", (l) => {
        const m = JSON.parse(l);
        process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: "ok" }) + "\\n");
      });
    `);
    const captured: string[] = [];
    try {
      const c = new JsonRpcClient(proc as never, (line) => captured.push(line));
      // Give the subprocess a tick to flush its banner before the first call.
      await new Promise((r) => setTimeout(r, 50));
      const r = await c.call("noop");
      assert.equal(r, "ok");
      assert.deepEqual(captured, ["startup banner line 1", "not-json but printed to stdout"]);
    } finally {
      proc.kill("SIGTERM");
    }
  });

  it("handles multiple frames in a single stdout chunk", async () => {
    // Emit both replies in one write so they arrive as one chunk.
    const proc = spawnFakeServer(`
      const replies = [];
      require("readline").createInterface({ input: process.stdin }).on("line", (l) => {
        const m = JSON.parse(l);
        replies.push(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: m.method }));
        if (replies.length === 2) process.stdout.write(replies.join("\\n") + "\\n");
      });
    `);
    try {
      const c = new JsonRpcClient(proc as never);
      const [a, b] = await Promise.all([c.call<string>("a"), c.call<string>("b")]);
      assert.equal(a, "a");
      assert.equal(b, "b");
    } finally {
      proc.kill("SIGTERM");
    }
  });

  it("times out when the server never replies", async () => {
    const proc = spawnFakeServer(`
      require("readline").createInterface({ input: process.stdin }).on("line", () => { /* swallow */ });
    `);
    try {
      const c = new JsonRpcClient(proc as never);
      await assert.rejects(() => c.call("silent", {}, 100), /timeout/);
    } finally {
      proc.kill("SIGTERM");
    }
  });
});
