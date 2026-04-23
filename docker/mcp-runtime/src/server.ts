import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { Config } from "./config.ts";
import type {
  EnsureRequest,
  EnsureResponse,
  InvokeRequest,
  InvokeResponse,
  LogsResponse,
  ShutdownRequest,
  StatusResponse,
} from "./contract.ts";
import { SubprocessPool } from "./pool.ts";

export function buildServer(cfg: Config, pool: SubprocessPool): FastifyInstance {
  const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" } });

  // Auth: shared bearer token. Internal-only service — Cloud Run ingress
  // restriction + IAM is the primary gate; the bearer is defence-in-depth.
  app.addHook("onRequest", async (req, reply) => {
    if (req.url === "/healthz") return;
    if (!cfg.sharedSecret) return;
    const header = req.headers["authorization"];
    const expected = `Bearer ${cfg.sharedSecret}`;
    if (header !== expected) {
      reply.code(401).send({ error: { code: "unauthorized", message: "bad bearer token" } });
    }
  });

  app.get("/healthz", async () => ({ ok: true }));

  app.post("/ensure", async (req: FastifyRequest<{ Body: EnsureRequest }>, reply) => {
    const b = req.body;
    if (!b?.service_instance_id) {
      reply.code(400).send(badReq("service_instance_id required"));
      return;
    }
    try {
      const e = await pool.ensure(
        b.service_instance_id,
        {
          package: b.package,
          version: b.version,
          command: b.command ?? null,
          limits: b.limits,
        },
        b.env ?? {},
        b.env_hash ?? "",
      );
      const res: EnsureResponse = {
        state: e.state,
        pid: e.proc?.pid ?? null,
        since: new Date(e.since).toISOString(),
      };
      reply.send(res);
    } catch (err) {
      reply.code(500).send(serverErr(err));
    }
  });

  app.post("/invoke", async (req: FastifyRequest<{ Body: InvokeRequest }>, reply) => {
    const b = req.body;
    if (!b?.service_instance_id || !b?.tool) {
      reply.code(400).send(badReq("service_instance_id and tool required"));
      return;
    }
    try {
      const out = await pool.invoke(
        b.service_instance_id,
        {
          package: b.package,
          version: b.version,
          command: b.command ?? null,
          limits: b.limits,
        },
        b.env ?? {},
        b.env_hash ?? "",
        b.tool,
        b.arguments ?? {},
      );
      const res: InvokeResponse = {
        result: out.result,
        warm: out.warm,
        duration_ms: out.durationMs,
      };
      reply.send(res);
    } catch (err) {
      reply.code(500).send(serverErr(err));
    }
  });

  app.post("/shutdown", async (req: FastifyRequest<{ Body: ShutdownRequest }>, reply) => {
    const id = req.body?.service_instance_id;
    if (!id) {
      reply.code(400).send(badReq("service_instance_id required"));
      return;
    }
    await pool.shutdown(id);
    reply.code(204).send();
  });

  app.get("/status/:id", async (req, reply) => {
    const id = (req.params as { id: string }).id;
    const e = pool.get(id);
    if (!e) {
      const empty: StatusResponse = {
        state: "stopped",
        pid: null,
        last_used: null,
        since: null,
        memory_mb: null,
        env_hash: null,
        package: null,
        version: null,
        last_error: null,
      };
      reply.send(empty);
      return;
    }
    const res: StatusResponse = {
      state: e.state,
      pid: e.proc?.pid ?? null,
      last_used: new Date(e.lastUsed).toISOString(),
      since: new Date(e.since).toISOString(),
      memory_mb: null, // Resident-set reading is Linux-specific; leave null for MVP.
      env_hash: e.envHash || null,
      package: e.spec.package ?? null,
      version: e.spec.version ?? null,
      last_error: e.lastError,
    };
    reply.send(res);
  });

  app.get("/logs/:id", async (req, reply) => {
    const id = (req.params as { id: string }).id;
    const q = req.query as { lines?: string; level?: string };
    const n = Math.min(Math.max(Number(q?.lines ?? cfg.logRingSize), 1), cfg.logRingSize);
    const allowed = new Set(
      (q?.level ?? "stderr,stdio,event").split(",").map((s) => s.trim()),
    );
    const e = pool.get(id);
    const filtered = (e?.logRing ?? []).filter((l) => allowed.has(l.level));
    const res: LogsResponse = { lines: filtered.slice(-n) };
    reply.send(res);
  });

  return app;
}

function badReq(msg: string) {
  return { error: { code: "invalid_request", message: msg } };
}
function serverErr(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  return { error: { code: "runtime_error", message } };
}
