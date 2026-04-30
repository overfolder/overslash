//! Fakes for end-to-end tests and local dev.
//!
//! Each module exposes a `start()` function that binds to a TCP port (default
//! `127.0.0.1:0` — OS-assigned), spawns the server, and returns a [`Handle`]
//! carrying the resolved URL and a shutdown trigger. A captured-state struct
//! (per fake) is also returned via the handle for assertions.
//!
//! The same fakes power:
//! - in-process backend integration tests (one `tokio::spawn` per test),
//! - the `overslash-fakes` binary that boots them all on a per-worktree harness.

use std::net::SocketAddr;

pub mod combined;
pub mod mcp;
pub mod oauth;
pub mod openapi;
pub mod stripe;

/// Handle returned by every fake's `start()`. Drop the handle (or call
/// `shutdown()`) to stop the server. Each fake exposes its captured state via
/// its own typed accessor on a more specific handle type.
pub struct Handle {
    pub addr: SocketAddr,
    pub url: String,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl Handle {
    pub fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.join.abort();
    }
}

/// Helper: bind on the requested address (use `127.0.0.1:0` for OS-assigned)
/// and return the listener + resolved URL.
pub(crate) async fn bind(
    bind_addr: &str,
) -> std::io::Result<(tokio::net::TcpListener, SocketAddr, String)> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let addr = listener.local_addr()?;
    let url = format!("http://{addr}");
    Ok((listener, addr, url))
}

/// Wrap an axum router with the listener + a oneshot shutdown channel and
/// return the standard [`Handle`].
pub(crate) fn serve(
    listener: tokio::net::TcpListener,
    addr: SocketAddr,
    url: String,
    app: axum::Router,
) -> Handle {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
    });
    Handle {
        addr,
        url,
        shutdown_tx: Some(tx),
        join,
    }
}
