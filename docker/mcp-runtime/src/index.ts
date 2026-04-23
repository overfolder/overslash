import { loadConfig } from "./config.ts";
import { SubprocessPool } from "./pool.ts";
import { buildServer } from "./server.ts";

const cfg = loadConfig();
const pool = new SubprocessPool(cfg);
const app = buildServer(cfg, pool);

async function shutdown(signal: NodeJS.Signals): Promise<void> {
  app.log.info({ signal }, "shutting down");
  // Give in-flight requests a moment to drain before killing subprocesses.
  await app.close().catch(() => {});
  await pool.shutdownAll();
  process.exit(0);
}

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

app.listen({ host: cfg.host, port: cfg.port }).catch((err) => {
  app.log.error(err, "listen failed");
  process.exit(1);
});
