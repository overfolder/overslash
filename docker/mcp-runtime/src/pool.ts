// Per-service-instance subprocess pool. Each Overslash service instance owns
// exactly one MCP subprocess (ready/paused/stopped). Identities sharing the
// service share the subprocess.
//
// Pausing is done with SIGSTOP/SIGCONT so the process keeps its memory and
// FDs but consumes no CPU. Env rotation is detected via env_hash — when a
// mismatched hash arrives we gracefully restart before forwarding the call.

import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import type { Config } from "./config.ts";
import type { LogLine, Limits, State } from "./contract.ts";
import { JsonRpcClient } from "./jsonrpc.ts";

interface LaunchSpec {
  package?: string;
  version?: string;
  command?: string[] | null;
  limits?: Limits;
}

export interface Entry {
  serviceInstanceId: string;
  state: State;
  proc: ChildProcessWithoutNullStreams | null;
  client: JsonRpcClient | null;
  envHash: string;
  env: Record<string, string>;
  spec: LaunchSpec;
  lastUsed: number;
  since: number;
  logRing: LogLine[];
  lastError: string | null;
}

function resolveLimits(cfg: Config, spec: LaunchSpec): {
  memoryMb: number;
  cpuSeconds: number;
  openFiles: number;
  processes: number;
} {
  const d = cfg.defaultLimits;
  const l = spec.limits ?? {};
  return {
    memoryMb: l.memory_mb ?? d.memoryMb,
    cpuSeconds: l.cpu_seconds ?? d.cpuSeconds,
    openFiles: l.open_files ?? d.openFiles,
    processes: l.processes ?? d.processes,
  };
}

// Build `prlimit --as=... --cpu=... --nofile=... --nproc=... -- <cmd> <args...>`.
// Falls back to the raw command on platforms where prlimit isn't available
// (controlled by cfg.requirePrlimit).
function buildArgv(
  cfg: Config,
  spec: LaunchSpec,
): { cmd: string; args: string[]; usingPrlimit: boolean } {
  let inner: { cmd: string; args: string[] };
  if (spec.command && spec.command.length > 0) {
    const [c, ...a] = spec.command;
    if (!c) throw new Error("command array is empty");
    inner = { cmd: c, args: a };
  } else {
    if (!spec.package) throw new Error("package or command required");
    const pkgRef = spec.version ? `${spec.package}@${spec.version}` : spec.package;
    inner = { cmd: "npx", args: ["-y", pkgRef] };
  }

  if (process.platform !== "linux") {
    if (cfg.requirePrlimit) {
      throw new Error(
        "REQUIRE_PRLIMIT=true but platform is not linux — set REQUIRE_PRLIMIT=false for dev on macOS/Windows",
      );
    }
    return { ...inner, usingPrlimit: false };
  }

  const lim = resolveLimits(cfg, spec);
  const prlimitArgs: string[] = [];
  // Each zero-valued limit is skipped (unlimited). See config.ts for the
  // reasoning — especially on --nproc, which is per-UID not per-subtree.
  if (lim.memoryMb > 0) prlimitArgs.push(`--as=${lim.memoryMb * 1024 * 1024}`);
  if (lim.cpuSeconds > 0) prlimitArgs.push(`--cpu=${lim.cpuSeconds}`);
  if (lim.openFiles > 0) prlimitArgs.push(`--nofile=${lim.openFiles}`);
  if (lim.processes > 0) prlimitArgs.push(`--nproc=${lim.processes}`);
  if (prlimitArgs.length === 0) {
    // Nothing to enforce — skip the prlimit wrapper entirely.
    return { ...inner, usingPrlimit: false };
  }
  prlimitArgs.push("--", inner.cmd, ...inner.args);
  return { cmd: "prlimit", args: prlimitArgs, usingPrlimit: true };
}

export class SubprocessPool {
  private entries = new Map<string, Entry>();

  constructor(private cfg: Config) {
    const tick = Math.min(cfg.idlePauseMs, cfg.idleShutdownMs, 30_000);
    const timer = setInterval(() => this.sweep(), Math.max(tick / 4, 5_000));
    // Don't keep the event loop alive just for the sweeper.
    timer.unref();
  }

  list(): Entry[] {
    return [...this.entries.values()];
  }

  get(id: string): Entry | undefined {
    return this.entries.get(id);
  }

  async ensure(
    serviceInstanceId: string,
    spec: LaunchSpec,
    env: Record<string, string>,
    envHash: string,
  ): Promise<Entry> {
    let e = this.entries.get(serviceInstanceId);
    if (!e) {
      e = this.makeEmpty(serviceInstanceId, spec, env, envHash);
      this.entries.set(serviceInstanceId, e);
    }
    // Env rotation → restart before returning.
    if (e.state !== "stopped" && e.envHash !== envHash) {
      this.log(e, "event", `env rotated (hash changed); restarting`);
      await this.shutdownProc(e);
      e.env = env;
      e.envHash = envHash;
      e.spec = spec;
    }
    if (e.state === "paused") {
      this.resume(e);
    }
    if (e.state === "stopped" || e.state === "error") {
      e.env = env;
      e.envHash = envHash;
      e.spec = spec;
      await this.start(e);
    }
    return e;
  }

  async invoke(
    serviceInstanceId: string,
    spec: LaunchSpec,
    env: Record<string, string>,
    envHash: string,
    tool: string,
    argsIn: Record<string, unknown>,
  ): Promise<{ result: unknown; warm: boolean; durationMs: number }> {
    // `warm` tracks whether this call reused a live subprocess that was
    // already in `ready`/`paused` state with a matching env hash. A cold
    // spawn — first use, state==stopped/error, or an env-rotation
    // restart — reports warm=false even if the entry existed before.
    const prior = this.entries.get(serviceInstanceId);
    const warm =
      prior !== undefined &&
      (prior.state === "ready" || prior.state === "paused") &&
      prior.envHash === envHash;
    const e = await this.ensure(serviceInstanceId, spec, env, envHash);
    if (!e.client) throw new Error(`subprocess not ready: ${e.state}`);

    const started = Date.now();
    try {
      let result: unknown;
      if (tool === "tools/list") {
        result = await e.client.call("tools/list", {}, this.cfg.invokeTimeoutMs);
      } else {
        result = await e.client.call(
          "tools/call",
          { name: tool, arguments: argsIn },
          this.cfg.invokeTimeoutMs,
        );
      }
      e.lastUsed = Date.now();
      const serialized = JSON.stringify(result ?? null);
      if (serialized.length > this.cfg.invokeMaxBytes) {
        throw new Error(
          `result exceeds INVOKE_MAX_BYTES (${serialized.length} > ${this.cfg.invokeMaxBytes})`,
        );
      }
      return { result, warm, durationMs: Date.now() - started };
    } catch (err) {
      e.lastError = (err as Error).message;
      throw err;
    }
  }

  async shutdown(serviceInstanceId: string): Promise<void> {
    const e = this.entries.get(serviceInstanceId);
    if (!e) return;
    await this.shutdownProc(e);
    this.entries.delete(serviceInstanceId);
  }

  async shutdownAll(): Promise<void> {
    await Promise.allSettled([...this.entries.values()].map((e) => this.shutdownProc(e)));
    this.entries.clear();
  }

  // ── lifecycle internals ───────────────────────────────────────────

  private log(e: Entry, level: LogLine["level"], text: string): void {
    e.logRing.push({ ts: new Date().toISOString(), level, text });
    if (e.logRing.length > this.cfg.logRingSize) e.logRing.shift();
  }

  private makeEmpty(
    id: string,
    spec: LaunchSpec,
    env: Record<string, string>,
    envHash: string,
  ): Entry {
    const now = Date.now();
    return {
      serviceInstanceId: id,
      state: "stopped",
      proc: null,
      client: null,
      envHash,
      env,
      spec,
      lastUsed: now,
      since: now,
      logRing: [],
      lastError: null,
    };
  }

  private async start(e: Entry): Promise<void> {
    e.state = "starting";
    e.since = Date.now();
    const { cmd, args, usingPrlimit } = buildArgv(this.cfg, e.spec);
    const lim = resolveLimits(this.cfg, e.spec);
    this.log(
      e,
      "event",
      `starting ${cmd} ${args.join(" ")} (limits: memory=${lim.memoryMb}MB cpu=${lim.cpuSeconds}s nofile=${lim.openFiles} nproc=${lim.processes}${usingPrlimit ? "" : " DISABLED"})`,
    );
    const proc = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        // Inherit only PATH + HOME so `npx` can find node/npm; everything
        // else comes from the caller's env bindings.
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        NPM_CONFIG_CACHE: this.cfg.packageCacheDir,
        ...e.env,
      },
    });

    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => {
      for (const line of chunk.split("\n")) {
        if (line.length === 0) continue;
        this.log(e, "stderr", line);
      }
    });

    e.proc = proc;
    const client = new JsonRpcClient(proc, (line) => this.log(e, "stdio", line));
    e.client = client;

    // Exit handler binds to THIS spawn's (proc, client) pair. If the entry
    // has been re-spawned (env rotation) by the time the old proc exits,
    // we must not clobber the new process/client references.
    proc.on("exit", (code, signal) => {
      if (e.proc === proc) {
        if (e.state !== "stopped") {
          e.lastError = `subprocess exited (code=${code} signal=${signal})`;
          e.state = "error";
        }
        e.proc = null;
      }
      if (e.client === client) {
        e.client = null;
      }
      client.close();
      this.log(e, "event", `subprocess exited code=${code} signal=${signal}`);
    });

    try {
      // MCP initialize handshake. Protocol version matches the 2024-11-05
      // revision of the MCP spec; servers that only support older versions
      // should still accept this as the client's preference.
      await client.call(
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "overslash-mcp-runtime", version: "0.1.0" },
        },
        this.cfg.invokeTimeoutMs,
      );
      client.notify("notifications/initialized");
      e.state = "ready";
      e.since = Date.now();
      e.lastUsed = e.since;
      this.log(e, "event", `ready (pid=${proc.pid})`);
    } catch (err) {
      e.lastError = (err as Error).message;
      e.state = "error";
      this.log(e, "event", `initialize failed: ${e.lastError}`);
      proc.kill("SIGTERM");
      throw err;
    }
  }

  private resume(e: Entry): void {
    if (!e.proc) return;
    try {
      e.proc.kill("SIGCONT");
      e.state = "ready";
      e.lastUsed = Date.now();
      this.log(e, "event", "resumed (SIGCONT)");
    } catch (err) {
      e.lastError = (err as Error).message;
    }
  }

  private pause(e: Entry): void {
    if (!e.proc || e.state !== "ready") return;
    try {
      e.proc.kill("SIGSTOP");
      e.state = "paused";
      this.log(e, "event", "paused on idle (SIGSTOP)");
    } catch (err) {
      e.lastError = (err as Error).message;
    }
  }

  private async shutdownProc(e: Entry): Promise<void> {
    if (!e.proc) {
      e.state = "stopped";
      e.client = null;
      return;
    }
    // If paused, resume so SIGTERM is deliverable.
    if (e.state === "paused") {
      try {
        e.proc.kill("SIGCONT");
      } catch {
        // Process may already be gone; ignore.
      }
    }
    this.log(e, "event", "shutdown requested (SIGTERM)");
    e.state = "stopped";
    e.client?.close();
    e.client = null;
    const proc = e.proc;
    e.proc = null;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        try {
          proc.kill("SIGKILL");
        } catch {
          // Process may already be gone; ignore.
        }
        resolve();
      }, 3_000);
      proc.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
      try {
        proc.kill("SIGTERM");
      } catch {
        clearTimeout(timer);
        resolve();
      }
    });
  }

  private sweep(): void {
    const now = Date.now();
    for (const e of this.entries.values()) {
      const idle = now - e.lastUsed;
      if (e.state === "ready" && idle > this.cfg.idlePauseMs) {
        this.pause(e);
      } else if (e.state === "paused" && idle > this.cfg.idleShutdownMs) {
        this.log(e, "event", "idle past retention; stopping");
        // Fire-and-forget the async shutdown; entry stays but state flips.
        void this.shutdownProc(e);
      }
    }
  }
}
