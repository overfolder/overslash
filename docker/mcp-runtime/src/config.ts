// Runtime config loaded from env vars at startup. All env reads happen
// here so the rest of the code depends on a typed config object.

export interface Config {
  port: number;
  host: string;
  // Shared-secret bearer token for /ensure, /invoke, /shutdown, /status.
  // When unset (local dev), auth is disabled.
  sharedSecret: string | null;
  // Per-call wall-clock cap.
  invokeTimeoutMs: number;
  // Max bytes a tool result may carry back to the caller.
  invokeMaxBytes: number;
  // Subprocess transitions to "paused" (SIGSTOP) after this many ms idle.
  idlePauseMs: number;
  // Paused subprocesses are killed after this many ms with no traffic.
  idleShutdownMs: number;
  // Max stderr lines retained per subprocess for /logs.
  logRingSize: number;
  // Path for the shared npm package cache.
  packageCacheDir: string;
  // Fallback resource quotas applied when a template doesn't declare its own.
  // Each spawn is wrapped in `prlimit` with these caps.
  defaultLimits: {
    memoryMb: number;
    cpuSeconds: number;
    openFiles: number;
    processes: number;
  };
  // When true, `prlimit` is required on PATH; startup fails otherwise. Set
  // to false for macOS / dev where prlimit isn't available (Linux-only).
  requirePrlimit: boolean;
}

function envNum(name: string, def: number): number {
  const v = process.env[name];
  if (!v) return def;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`${name} must be a number, got ${v}`);
  return n;
}

export function loadConfig(): Config {
  return {
    port: envNum("PORT", 8080),
    host: process.env.HOST ?? "0.0.0.0",
    sharedSecret: process.env.MCP_RUNTIME_SHARED_SECRET ?? null,
    invokeTimeoutMs: envNum("INVOKE_TIMEOUT_MS", 30_000),
    invokeMaxBytes: envNum("INVOKE_MAX_BYTES", 1_048_576),
    idlePauseMs: envNum("IDLE_PAUSE_MS", 300_000),
    idleShutdownMs: envNum("IDLE_SHUTDOWN_MS", 1_800_000),
    logRingSize: envNum("LOG_RING_SIZE", 200),
    packageCacheDir: process.env.PACKAGE_CACHE_DIR ?? "/tmp/mcp-cache",
    // Each default of 0 means "no limit" — the corresponding --<flag> is
    // omitted from the prlimit invocation.
    //
    // `memoryMb` maps to `RLIMIT_AS` (virtual memory). Node/V8 reserves a
    // lot of VM up front (~1GB just for the code range), so this must
    // stay loose; 4GB catches runaway mallocs without breaking startup.
    // The real memory ceiling should be the runtime container's Cloud
    // Run/compose memory cap — use cgroups (`memory.max`) for true RSS
    // enforcement in a follow-up.
    //
    // `processes` maps to `RLIMIT_NPROC`, which is per-UID *global* —
    // it counts every process owned by this Linux user, not just this
    // process's children. Unlimited by default to avoid collisions on
    // shared dev hosts. Safe to enable in the Cloud Run container where
    // the runtime has a dedicated UID.
    defaultLimits: {
      memoryMb: envNum("DEFAULT_LIMIT_MEMORY_MB", 4096),
      cpuSeconds: envNum("DEFAULT_LIMIT_CPU_SECONDS", 300),
      openFiles: envNum("DEFAULT_LIMIT_OPEN_FILES", 1024),
      processes: envNum("DEFAULT_LIMIT_PROCESSES", 0),
    },
    requirePrlimit: (process.env.REQUIRE_PRLIMIT ?? "true") !== "false",
  };
}
