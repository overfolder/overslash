// HTTP contract types shared with the Rust api-side client (kept in sync
// by hand — this runtime has no codegen dep on the Rust side).

export type State = "stopped" | "starting" | "ready" | "paused" | "error";

export interface Limits {
  memory_mb?: number;
  cpu_seconds?: number;
  open_files?: number;
  processes?: number;
}

export interface EnsureRequest {
  service_instance_id: string;
  package?: string;
  version?: string;
  command?: string[] | null;
  env: Record<string, string>;
  env_hash: string;
  limits?: Limits;
}

export interface EnsureResponse {
  state: State;
  pid: number | null;
  since: string | null;
}

export interface InvokeRequest {
  service_instance_id: string;
  // Special tool "tools/list" triggers a tools/list handshake instead of tools/call.
  tool: string;
  arguments: Record<string, unknown>;
  env: Record<string, string>;
  env_hash: string;
  // Optional: set on first /invoke (avoids a separate /ensure) to describe how to launch.
  package?: string;
  version?: string;
  command?: string[] | null;
  limits?: Limits;
  request_id?: string;
}

export interface InvokeResponse {
  result: unknown;
  warm: boolean;
  duration_ms: number;
}

export interface ShutdownRequest {
  service_instance_id: string;
}

export interface StatusResponse {
  state: State;
  pid: number | null;
  last_used: string | null;
  since: string | null;
  memory_mb: number | null;
  env_hash: string | null;
  package: string | null;
  version: string | null;
  last_error: string | null;
}

export interface LogLine {
  // ISO-8601 with milliseconds.
  ts: string;
  // "stderr"  — lines from the subprocess's stderr (diagnostics, warnings).
  // "stdio"   — non-JSON-RPC lines on stdout (startup banners, leaked prints).
  //             JSON-RPC frames are intentionally NOT captured here — those
  //             carry tool arguments and results that may include user data
  //             or secrets.
  // "event"   — runtime lifecycle events (start, pause, resume, exit, restart).
  level: "stderr" | "stdio" | "event";
  text: string;
}

export interface LogsResponse {
  lines: LogLine[];
}

export interface ErrorBody {
  error: { code: string; message: string };
}
