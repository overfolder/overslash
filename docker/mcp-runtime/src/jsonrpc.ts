// Minimal newline-delimited JSON-RPC 2.0 client over a ChildProcess's stdio.
// MCP servers speak this framing: one JSON object per line on stdin/stdout.
//
// This file is intentionally tiny — we call `initialize`, `tools/list`, and
// `tools/call` only. Notifications from the server (`notifications/*`) are
// ignored. Errors are surfaced as thrown `JsonRpcError`.

import type { ChildProcessWithoutNullStreams } from "node:child_process";

export class JsonRpcError extends Error {
  constructor(
    public code: number,
    message: string,
    public data?: unknown,
  ) {
    super(message);
    this.name = "JsonRpcError";
  }
}

type Pending = {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
};

export class JsonRpcClient {
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private buffer = "";
  private closed = false;

  constructor(
    private proc: ChildProcessWithoutNullStreams,
    private onNonJsonLine?: (line: string) => void,
  ) {
    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => this.onData(chunk));
    proc.on("exit", () => this.failAll(new Error("mcp subprocess exited")));
    proc.on("error", (e) => this.failAll(e));
  }

  async call<T = unknown>(method: string, params?: unknown, timeoutMs = 30_000): Promise<T> {
    if (this.closed) throw new Error("client closed");
    const id = this.nextId++;
    const msg = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    return await new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`jsonrpc timeout: ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v as T);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.proc.stdin.write(msg + "\n", (err) => {
        if (err) {
          this.pending.delete(id);
          clearTimeout(timer);
          reject(err);
        }
      });
    });
  }

  notify(method: string, params?: unknown): void {
    if (this.closed) return;
    const msg = JSON.stringify({ jsonrpc: "2.0", method, params });
    this.proc.stdin.write(msg + "\n");
  }

  close(): void {
    this.closed = true;
    this.failAll(new Error("client closed"));
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let nl = this.buffer.indexOf("\n");
    while (nl !== -1) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (line.length > 0) this.handleLine(line);
      nl = this.buffer.indexOf("\n");
    }
  }

  private handleLine(line: string): void {
    let msg: {
      id?: number;
      result?: unknown;
      error?: { code: number; message: string; data?: unknown };
      method?: string;
    };
    try {
      msg = JSON.parse(line);
    } catch {
      // Non-JSON stdout: startup banner, debug print, etc. Surface to the
      // log ring so operators can see it.
      this.onNonJsonLine?.(line);
      return;
    }
    if (typeof msg.id !== "number") {
      // Notification or server-initiated request; ignore for now.
      return;
    }
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    if (msg.error) {
      p.reject(new JsonRpcError(msg.error.code, msg.error.message, msg.error.data));
    } else {
      p.resolve(msg.result);
    }
  }

  private failAll(e: Error): void {
    for (const { reject } of this.pending.values()) reject(e);
    this.pending.clear();
  }
}
