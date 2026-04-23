import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { SubprocessPool } from "./pool.ts";
import type { Config } from "./config.ts";

// Mini MCP server as a `node -e` argument. Used by the pool tests to
// exercise the JSON-RPC lifecycle without pulling a real MCP package.
const FAKE_SERVER = `
const rl = require("readline").createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let m;
  try { m = JSON.parse(line); } catch { return; }
  if (!m || typeof m.id !== "number") return;
  const reply = (result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }) + "\\n");
  if (m.method === "initialize") return reply({ protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "fake", version: "0" } });
  if (m.method === "tools/list") return reply({ tools: [] });
  if (m.method === "tools/call") return reply({ echoed: m.params?.arguments ?? null, tool: m.params?.name, env_flag: process.env.FAKE_FLAG ?? null });
});
`;

function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    port: 0,
    host: "127.0.0.1",
    sharedSecret: null,
    invokeTimeoutMs: 5_000,
    invokeMaxBytes: 1_048_576,
    idlePauseMs: 60_000,
    idleShutdownMs: 300_000,
    logRingSize: 50,
    packageCacheDir: "/tmp/mcp-cache-test",
    // Resource-unlimited for unit tests; pool fallbacks to bare spawn
    // (no prlimit wrapper) because all limits are 0.
    defaultLimits: { memoryMb: 0, cpuSeconds: 0, openFiles: 0, processes: 0 },
    requirePrlimit: false,
    ...overrides,
  };
}

describe("SubprocessPool", () => {
  it("first call is cold, second is warm", async () => {
    const pool = new SubprocessPool(testConfig());
    try {
      const a = await pool.invoke(
        "si_warm",
        { command: ["node", "-e", FAKE_SERVER] },
        {},
        "h1",
        "foo",
        {},
      );
      assert.equal(a.warm, false, "first call should be cold");
      const b = await pool.invoke(
        "si_warm",
        { command: ["node", "-e", FAKE_SERVER] },
        {},
        "h1",
        "foo",
        {},
      );
      assert.equal(b.warm, true, "second call with same env should be warm");
    } finally {
      await pool.shutdownAll();
    }
  });

  it("env rotation reports warm=false on the restarted call", async () => {
    const pool = new SubprocessPool(testConfig());
    try {
      await pool.invoke(
        "si_rot",
        { command: ["node", "-e", FAKE_SERVER] },
        { FAKE_FLAG: "v1" },
        "h1",
        "bar",
        {},
      );
      const after = await pool.invoke(
        "si_rot",
        { command: ["node", "-e", FAKE_SERVER] },
        { FAKE_FLAG: "v2" },
        "h2",
        "bar",
        {},
      );
      assert.equal(after.warm, false, "env rotation must force cold semantics");
      // New env must be visible to the subprocess.
      const r = after.result as { env_flag: string };
      assert.equal(r.env_flag, "v2");
    } finally {
      await pool.shutdownAll();
    }
  });

  it("passes tool arguments through to the server", async () => {
    const pool = new SubprocessPool(testConfig());
    try {
      const out = await pool.invoke(
        "si_args",
        { command: ["node", "-e", FAKE_SERVER] },
        {},
        "h1",
        "echo",
        { hello: "world", n: 42 },
      );
      const r = out.result as { tool: string; echoed: { hello: string; n: number } };
      assert.equal(r.tool, "echo");
      assert.deepEqual(r.echoed, { hello: "world", n: 42 });
    } finally {
      await pool.shutdownAll();
    }
  });

  it("shutdown removes the entry and releases the subprocess", async () => {
    const pool = new SubprocessPool(testConfig());
    try {
      await pool.invoke(
        "si_shut",
        { command: ["node", "-e", FAKE_SERVER] },
        {},
        "h1",
        "foo",
        {},
      );
      assert.ok(pool.get("si_shut"), "entry should exist after invoke");
      await pool.shutdown("si_shut");
      assert.equal(pool.get("si_shut"), undefined, "entry removed after shutdown");
    } finally {
      await pool.shutdownAll();
    }
  });

  it("rejects results larger than INVOKE_MAX_BYTES", async () => {
    // Make the cap tiny; the fake server's reply JSON is well over 10 bytes.
    const pool = new SubprocessPool(testConfig({ invokeMaxBytes: 10 }));
    try {
      await assert.rejects(
        () =>
          pool.invoke(
            "si_big",
            { command: ["node", "-e", FAKE_SERVER] },
            {},
            "h1",
            "foo",
            {},
          ),
        /INVOKE_MAX_BYTES/,
      );
    } finally {
      await pool.shutdownAll();
    }
  });

  it("captures lifecycle events in the log ring", async () => {
    const pool = new SubprocessPool(testConfig());
    try {
      await pool.invoke(
        "si_log",
        { command: ["node", "-e", FAKE_SERVER] },
        {},
        "h1",
        "foo",
        {},
      );
      const entry = pool.get("si_log");
      assert.ok(entry);
      const events = entry.logRing.filter((l) => l.level === "event").map((l) => l.text);
      assert.ok(
        events.some((e) => e.startsWith("starting")),
        `expected start event, got: ${events.join(" | ")}`,
      );
      assert.ok(events.some((e) => e.startsWith("ready")));
    } finally {
      await pool.shutdownAll();
    }
  });
});
