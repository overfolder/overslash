import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { buildServer } from "./server.ts";
import { SubprocessPool } from "./pool.ts";
import type { Config } from "./config.ts";

function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    port: 0,
    host: "127.0.0.1",
    sharedSecret: "test-secret",
    invokeTimeoutMs: 5_000,
    invokeMaxBytes: 1_048_576,
    idlePauseMs: 60_000,
    idleShutdownMs: 300_000,
    logRingSize: 50,
    packageCacheDir: "/tmp/mcp-cache-test",
    defaultLimits: { memoryMb: 0, cpuSeconds: 0, openFiles: 0, processes: 0 },
    requirePrlimit: false,
    ...overrides,
  };
}

const FAKE_SERVER = `
const rl = require("readline").createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let m;
  try { m = JSON.parse(line); } catch { return; }
  if (!m || typeof m.id !== "number") return;
  const reply = (result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }) + "\\n");
  if (m.method === "initialize") return reply({ protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "fake", version: "0" } });
  if (m.method === "tools/list") return reply({ tools: [{ name: "echo" }] });
  if (m.method === "tools/call") return reply({ tool: m.params.name });
});
`;

describe("http server", () => {
  it("/healthz returns ok without auth", async () => {
    const cfg = testConfig();
    const pool = new SubprocessPool(cfg);
    const app = buildServer(cfg, pool);
    try {
      const res = await app.inject({ method: "GET", url: "/healthz" });
      assert.equal(res.statusCode, 200);
      assert.deepEqual(res.json(), { ok: true });
    } finally {
      await app.close();
      await pool.shutdownAll();
    }
  });

  it("rejects requests without bearer token", async () => {
    const cfg = testConfig();
    const pool = new SubprocessPool(cfg);
    const app = buildServer(cfg, pool);
    try {
      const res = await app.inject({
        method: "POST",
        url: "/ensure",
        payload: { service_instance_id: "x", env: {}, env_hash: "h" },
      });
      assert.equal(res.statusCode, 401);
    } finally {
      await app.close();
      await pool.shutdownAll();
    }
  });

  it("/status/:id returns stopped for unknown ids", async () => {
    const cfg = testConfig();
    const pool = new SubprocessPool(cfg);
    const app = buildServer(cfg, pool);
    try {
      const res = await app.inject({
        method: "GET",
        url: "/status/unknown",
        headers: { authorization: "Bearer test-secret" },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.json().state, "stopped");
      assert.equal(res.json().pid, null);
    } finally {
      await app.close();
      await pool.shutdownAll();
    }
  });

  it("/invoke end-to-end with fake server", async () => {
    const cfg = testConfig();
    const pool = new SubprocessPool(cfg);
    const app = buildServer(cfg, pool);
    try {
      const res = await app.inject({
        method: "POST",
        url: "/invoke",
        headers: { authorization: "Bearer test-secret" },
        payload: {
          service_instance_id: "si_http",
          tool: "echo",
          arguments: {},
          env: {},
          env_hash: "h1",
          command: ["node", "-e", FAKE_SERVER],
        },
      });
      assert.equal(res.statusCode, 200);
      const body = res.json() as { result: { tool: string }; warm: boolean };
      assert.equal(body.result.tool, "echo");
      assert.equal(body.warm, false);
    } finally {
      await app.close();
      await pool.shutdownAll();
    }
  });

  it("/logs filters by level", async () => {
    const cfg = testConfig();
    const pool = new SubprocessPool(cfg);
    const app = buildServer(cfg, pool);
    try {
      await app.inject({
        method: "POST",
        url: "/invoke",
        headers: { authorization: "Bearer test-secret" },
        payload: {
          service_instance_id: "si_logs",
          tool: "echo",
          arguments: {},
          env: {},
          env_hash: "h1",
          command: ["node", "-e", FAKE_SERVER],
        },
      });
      const res = await app.inject({
        method: "GET",
        url: "/logs/si_logs?level=event",
        headers: { authorization: "Bearer test-secret" },
      });
      assert.equal(res.statusCode, 200);
      const body = res.json() as { lines: { level: string }[] };
      assert.ok(body.lines.length > 0);
      assert.ok(body.lines.every((l) => l.level === "event"));
    } finally {
      await app.close();
      await pool.shutdownAll();
    }
  });
});
