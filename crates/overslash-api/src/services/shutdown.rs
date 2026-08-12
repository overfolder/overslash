//! Process-wide "we are going away" signal.
//!
//! Deliberately **not** wired into `axum::serve(...).with_graceful_shutdown(...)`.
//! Draining HTTP would mean waiting on `/v1/events/stream` responses that are
//! designed to stay open for `events_stream_max_connection_secs` (30s by
//! default), which cannot finish inside Cloud Run's ~10s SIGTERM→SIGKILL
//! window — so it would end in SIGKILL anyway, while changing request-path
//! semantics for every endpoint and adding a new hang mode to tests that build
//! the router many times in one process.
//!
//! The only thing that genuinely benefits from advance notice is the async
//! worker, which must hand its leases back before the process dies. So that is
//! the only subscriber, and the server keeps serving until SIGKILL exactly as
//! it does today.

use tokio::sync::watch;

static CHANNEL: std::sync::OnceLock<(watch::Sender<bool>, watch::Receiver<bool>)> =
    std::sync::OnceLock::new();

fn channel() -> &'static (watch::Sender<bool>, watch::Receiver<bool>) {
    CHANNEL.get_or_init(|| watch::channel(false))
}

/// A receiver that flips to `true` once shutdown begins. Already-true if
/// shutdown started before the caller subscribed.
pub fn subscribe() -> watch::Receiver<bool> {
    channel().1.clone()
}

/// Announce shutdown. Idempotent — a second signal is a no-op.
pub fn trigger() {
    let _ = channel().0.send(true);
}

/// True once [`trigger`] has fired.
pub fn is_shutting_down() -> bool {
    *channel().1.borrow()
}

/// Spawn the SIGTERM/Ctrl-C listener.
///
/// Called once, and only when async execution is enabled, so a deployment with
/// the flag off installs no handler at all and its behaviour is bit-identical
/// to before this feature existed.
pub fn install_signal_handler() {
    tokio::spawn(async {
        wait_for_signal().await;
        tracing::info!("shutdown signal received; async worker will release its leases");
        trigger();
    });
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not install SIGTERM handler: {e}");
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => {},
        _ = tokio::signal::ctrl_c() => {},
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
