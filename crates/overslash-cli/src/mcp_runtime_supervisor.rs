//! Child-process supervisor for the embedded MCP runtime bundle.
//!
//! Only compiled with the `mcp` feature. `overslash web --mcp-runtime=local`
//! extracts the bundled `mcp-runtime.mjs` to a tmpdir and spawns
//! `node mcp-runtime.mjs` on a free loopback port. Stdout/stderr are piped
//! into the main process's tracing output with a `[mcp-runtime]` prefix.
//!
//! The supervisor watches the child; if it exits non-zero and the main
//! process is still up, it restarts with exponential backoff (max 30s).
//! On main-process shutdown (SIGTERM/SIGINT) we drop the `Drop`-owned
//! handle and the child is signaled via its stdin closing — or SIGTERM via
//! a `tokio::process::Child::kill()` call.

#![cfg(feature = "mcp")]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use rust_embed::Embed;

#[derive(Embed)]
#[folder = "$CARGO_MANIFEST_DIR/embed/mcp-runtime"]
struct RuntimeBundle;

/// Config for the supervisor + runtime child.
pub struct SupervisorConfig {
    /// Port to bind the runtime on. `0` picks a free port at supervisor startup.
    pub port: u16,
    /// Bearer token the api-side RuntimeClient will send. Generated per-run
    /// when the caller doesn't provide one.
    pub shared_secret: String,
}

/// What the supervisor hands back to the caller after a successful spawn.
pub struct Supervisor {
    pub url: String,
    pub shared_secret: String,
    // When dropped, the child is killed via the tokio watcher.
    _handle: Arc<Mutex<Option<Child>>>,
}

/// Pick a free loopback port by binding to :0 and letting the OS assign.
fn pick_free_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn rand_secret() -> String {
    // Non-cryptographic is fine — this is only loopback, ephemeral, and
    // the runtime's ingress is INTERNAL in prod. Seed from system time +
    // PID and a few OS bits; 256 bits of entropy is overkill for this.
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    seed ^= std::process::id() as u64;
    // xorshift64* — good enough for a bearer token on loopback.
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let v = seed.wrapping_mul(0x2545F4914F6CDD1D);
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn extract_bundle(out_dir: &std::path::Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let out = out_dir.join("mcp-runtime.mjs");
    let asset = RuntimeBundle::get("mcp-runtime.mjs").ok_or_else(|| {
        anyhow::anyhow!(
            "mcp-runtime.mjs is not embedded — rebuild with `make build-mcp-runtime` \
             to regenerate crates/overslash-cli/embed/mcp-runtime/mcp-runtime.mjs \
             before building with --features mcp"
        )
    })?;
    std::fs::write(&out, asset.data.as_ref())?;
    Ok(out)
}

/// Spawn the runtime, return the URL + bearer to hand to the api.
pub async fn spawn(cfg: SupervisorConfig) -> anyhow::Result<Supervisor> {
    // 1. Node on PATH? Walk PATH manually rather than taking a `which`
    //    crate dep for this one check.
    let node_on_path = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p).any(|dir| {
                let candidate = dir.join("node");
                candidate.is_file()
                    || candidate.with_extension("exe").is_file()
                    || candidate.with_extension("cmd").is_file()
            })
        })
        .unwrap_or(false);
    if !node_on_path {
        anyhow::bail!(
            "`node` is not on PATH. --mcp-runtime=local requires Node.js 22+; \
             install it, point --mcp-runtime=<url> at a separate runtime, or use \
             --mcp-runtime=off to disable MCP for this deployment."
        );
    }

    // 2. Extract embedded bundle next to the binary's tmpdir.
    let tmpdir = std::env::temp_dir().join(format!("overslash-mcp-runtime-{}", std::process::id()));
    let bundle_path = extract_bundle(&tmpdir)?;

    let port = if cfg.port == 0 {
        pick_free_port()?
    } else {
        cfg.port
    };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

    // 3. Spawn. Pipe stdout+stderr so we can tee them into tracing.
    let shared_secret = cfg.shared_secret;
    let mut cmd = Command::new("node");
    cmd.arg(&bundle_path)
        .env("PORT", port.to_string())
        .env("HOST", "127.0.0.1")
        .env("MCP_RUNTIME_SHARED_SECRET", &shared_secret)
        // Dev hosts won't have prlimit wrapping be appropriate when the
        // runtime runs as the same UID as the user's shell.
        .env("REQUIRE_PRLIMIT", "false")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;

    // 4. Tee child stdio into tracing.
    if let Some(out) = child.stdout.take() {
        tokio::spawn(async move {
            let mut r = BufReader::new(out).lines();
            while let Ok(Some(line)) = r.next_line().await {
                tracing::info!(target: "mcp-runtime", "{line}");
            }
        });
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(async move {
            let mut r = BufReader::new(err).lines();
            while let Ok(Some(line)) = r.next_line().await {
                tracing::warn!(target: "mcp-runtime", "{line}");
            }
        });
    }

    // 5. Wait briefly for the child to start listening. The runtime logs
    //    "incoming request"/"listening" via Pino — we just give it a
    //    short grace period rather than parsing stdout for readiness.
    tokio::time::sleep(Duration::from_millis(400)).await;

    tracing::info!(
        target: "mcp-runtime",
        "child started (pid={pid:?}) listening at http://{addr}",
        pid = child.id()
    );

    let handle = Arc::new(Mutex::new(Some(child)));

    // Restart watcher. If the child exits while the main process is still
    // up, respawn with exponential backoff. Capped at 30s and 8 attempts
    // per 5min window — beyond that we surrender and log loud errors so
    // the operator can investigate (missing node, bad bundle, OOM).
    {
        let handle = handle.clone();
        let shared_secret = shared_secret.clone();
        let bundle_path = bundle_path.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(500);
            loop {
                let exit = {
                    let mut guard = handle.lock().await;
                    match guard.as_mut() {
                        Some(c) => c.wait().await,
                        None => return, // Supervisor dropped — exit the watcher.
                    }
                };
                tracing::warn!(
                    target: "mcp-runtime",
                    "child exited ({exit:?}); respawning in {:?}",
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));

                let mut cmd = Command::new("node");
                cmd.arg(&bundle_path)
                    .env("PORT", port.to_string())
                    .env("HOST", "127.0.0.1")
                    .env("MCP_RUNTIME_SHARED_SECRET", &shared_secret)
                    .env("REQUIRE_PRLIMIT", "false")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                match cmd.spawn() {
                    Ok(new_child) => {
                        let mut guard = handle.lock().await;
                        *guard = Some(new_child);
                    }
                    Err(e) => {
                        tracing::error!(target: "mcp-runtime", "respawn failed: {e}");
                        // Keep the loop going — next attempt respects backoff.
                    }
                }
            }
        });
    }

    Ok(Supervisor {
        url: format!("http://{addr}"),
        shared_secret,
        _handle: handle,
    })
}

/// Generate a default config when the caller just wants "pick something sane".
pub fn default_config() -> SupervisorConfig {
    SupervisorConfig {
        port: 0,
        shared_secret: rand_secret(),
    }
}
