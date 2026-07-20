use std::time::{Duration, Instant};

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::AppState;

/// Upper bound on how long a probe may wait for Postgres.
///
/// Without this, `PgPool::acquire` blocks for the pool's `acquire_timeout`
/// (30 s by default) when the database is unreachable — long enough for the
/// Cloud Run liveness probe to time out and recycle the container, which is
/// exactly what the always-200 `/health` below exists to prevent.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Cap on the error text echoed into an unauthenticated response body, so a
/// sqlx error can't spill a full connection string to the public internet.
const MAX_ERROR_LEN: usize = 200;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

/// Result of a bounded `SELECT 1` against the pool.
enum DbProbe {
    Up { latency_ms: u128 },
    Down { error: String },
}

impl DbProbe {
    fn is_up(&self) -> bool {
        matches!(self, DbProbe::Up { .. })
    }

    /// Merge the probe outcome into a response body under `db` / `db_latency_ms`
    /// / `db_error`.
    fn extend(&self, body: &mut Value) {
        let obj = body.as_object_mut().expect("body is a JSON object");
        match self {
            DbProbe::Up { latency_ms } => {
                obj.insert("db".into(), json!("up"));
                obj.insert("db_latency_ms".into(), json!(latency_ms));
            }
            DbProbe::Down { error } => {
                obj.insert("db".into(), json!("down"));
                obj.insert("db_error".into(), json!(error));
            }
        }
    }
}

/// Runtime sqlx rather than `query_scalar!`: `SELECT 1` references no schema,
/// so the compile-time macro has nothing to check and would only add an
/// offline-cache entry. Same exemption `has_pgvector` takes for the pgvector
/// preflight in `lib.rs`.
#[allow(clippy::disallowed_methods)]
async fn probe_db(pool: &PgPool) -> DbProbe {
    let started = Instant::now();
    let query = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool);

    match tokio::time::timeout(PROBE_TIMEOUT, query).await {
        Ok(Ok(_)) => DbProbe::Up {
            latency_ms: started.elapsed().as_millis(),
        },
        Ok(Err(e)) => DbProbe::Down {
            error: truncate(&e.to_string()),
        },
        Err(_) => DbProbe::Down {
            error: "timeout".into(),
        },
    }
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_ERROR_LEN {
        return s.to_string();
    }
    // Walk down to a char boundary at or below the byte cap — slicing
    // mid-codepoint would panic on a multi-byte error message.
    // (`str::floor_char_boundary` does exactly this but is stable only since
    // 1.91, above this workspace's 1.85 MSRV.)
    let mut end = MAX_ERROR_LEN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Liveness. **Always 200**, even when Postgres is unreachable.
///
/// This endpoint backs the Cloud Run startup *and* liveness probes
/// (`infra/modules/cloud-run/main.tf`) plus the Better Stack P0 monitor. If it
/// failed on a Cloud SQL blip, Cloud Run would kill and restart every container
/// mid-outage and the startup probe would block redeploys until the database
/// recovered — the probe would amplify the incident instead of reporting it.
///
/// So DB state is reported in the body (`db`, `db_latency_ms` / `db_error`) and
/// never in the status code. For a check that *fails* when the database is
/// down, use [`ready`].
async fn health(State(state): State<AppState>) -> Json<Value> {
    let probe = probe_db(&state.db).await;
    let mut body = json!({ "status": "ok" });
    probe.extend(&mut body);
    Json(body)
}

/// Readiness — 503 when Postgres is unreachable.
///
/// The gated counterpart to [`health`]: this is the one safe to point a
/// load-balancer or an alerting monitor at, because failing it takes the
/// instance out of rotation rather than restarting it.
async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let probe = probe_db(&state.db).await;
    let (code, status) = if probe.is_up() {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "degraded")
    };
    let mut body = json!({ "status": status });
    probe.extend(&mut body);
    (code, Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_caps_long_errors() {
        let long = "x".repeat(500);
        let out = truncate(&long);
        assert_eq!(out.chars().count(), MAX_ERROR_LEN + 1);
        assert!(out.ends_with('…'));
    }

    /// A cut landing mid-codepoint must not panic.
    #[test]
    fn truncate_respects_char_boundaries() {
        // '€' is 3 bytes and MAX_ERROR_LEN is not a multiple of 3, so the byte
        // cap lands *inside* a codepoint — a raw `&s[..MAX_ERROR_LEN]` would
        // panic here. Assert that precondition so the test can't silently stop
        // covering the panic case if the cap changes.
        assert_ne!(MAX_ERROR_LEN % 3, 0, "cap must not fall on a '€' boundary");

        let long = "€".repeat(500);
        let out = truncate(&long);

        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), MAX_ERROR_LEN / 3 + 1);
    }

    #[test]
    fn truncate_leaves_short_errors_alone() {
        assert_eq!(truncate("connection refused"), "connection refused");
    }

    #[test]
    fn extend_reports_up_with_latency() {
        let mut body = json!({ "status": "ok" });
        DbProbe::Up { latency_ms: 7 }.extend(&mut body);
        assert_eq!(body["db"], "up");
        assert_eq!(body["db_latency_ms"], 7);
        assert!(body.get("db_error").is_none());
    }

    /// The down path, without touching the shared test database: a lazy pool
    /// pointed at a closed port never connects. `acquire_timeout` is set below
    /// `PROBE_TIMEOUT` so this exercises the sqlx-error branch; the timeout
    /// branch is the same code path with a slower failure.
    #[tokio::test]
    async fn probe_reports_down_when_postgres_is_unreachable() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(250))
            .connect_lazy("postgres://nobody@127.0.0.1:1/nonexistent")
            .expect("lazy pool");

        let started = Instant::now();
        let probe = probe_db(&pool).await;

        assert!(!probe.is_up());
        assert!(
            started.elapsed() < PROBE_TIMEOUT + Duration::from_secs(1),
            "probe must fail fast, took {:?}",
            started.elapsed()
        );

        let mut body = json!({ "status": "ok" });
        probe.extend(&mut body);
        assert_eq!(body["db"], "down");
        assert!(body["db_error"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn extend_reports_down_with_error() {
        let mut body = json!({ "status": "degraded" });
        DbProbe::Down {
            error: "timeout".into(),
        }
        .extend(&mut body);
        assert_eq!(body["db"], "down");
        assert_eq!(body["db_error"], "timeout");
        assert!(body.get("db_latency_ms").is_none());
    }
}
