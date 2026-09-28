use std::time::{Duration, Instant};

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use overslash_core::build_info::build_info;
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

// The `version` / `commit` / `sql_policy` fields in both bodies are
// deliberate: they identify the build to uptime monitors and to anyone
// diagnosing a deploy, and they reveal nothing an attacker couldn't infer from
// behaviour. `GET /v1/version` reports the same values (also unauthenticated,
// for the same reason) without the database probe.
//
// What the bodies do *not* carry is the database error. Both endpoints are
// unauthenticated, and a sqlx error names hosts, ports, database and role
// names (CASA 6.2.1). The error goes to the log, where the on-call reads it;
// the body says only `"db": "down"`.

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

/// Result of a bounded `SELECT 1` against the pool. `Down` carries no detail
/// on purpose — see the note above [`router`].
enum DbProbe {
    Up { latency_ms: u128 },
    Down,
}

impl DbProbe {
    fn is_up(&self) -> bool {
        matches!(self, DbProbe::Up { .. })
    }

    /// Merge the probe outcome into a response body under `db` /
    /// `db_latency_ms`.
    fn extend(&self, body: &mut Value) {
        let obj = body.as_object_mut().expect("body is a JSON object");
        match self {
            DbProbe::Up { latency_ms } => {
                obj.insert("db".into(), json!("up"));
                obj.insert("db_latency_ms".into(), json!(latency_ms));
            }
            DbProbe::Down => {
                obj.insert("db".into(), json!("down"));
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
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "health probe: database query failed");
            DbProbe::Down
        }
        Err(_) => {
            tracing::warn!(
                timeout_ms = PROBE_TIMEOUT.as_millis(),
                "health probe: database query timed out"
            );
            DbProbe::Down
        }
    }
}

/// Liveness. **Always 200**, even when Postgres is unreachable.
///
/// This endpoint backs the Cloud Run startup *and* liveness probes
/// (`infra/modules/cloud-run/main.tf`) plus the Better Stack P0 monitor. If it
/// failed on a Cloud SQL blip, Cloud Run would kill and restart every container
/// mid-outage and the startup probe would block redeploys until the database
/// recovered — the probe would amplify the incident instead of reporting it.
///
/// So DB state is reported in the body (`db`, plus `db_latency_ms` when up) and
/// never in the status code. For a check that *fails* when the database is
/// down, use [`ready`].
async fn health(State(state): State<AppState>) -> Json<Value> {
    let probe = probe_db(&state.db).await;
    let info = build_info();
    let mut body = json!({
        "status": "ok",
        "version": info.version,
        "commit": info.commit,
        "sql_policy": overslash_core::sql_policy::available(),
    });
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
    let info = build_info();
    let mut body = json!({
        "status": status,
        "version": info.version,
        "commit": info.commit,
        "sql_policy": overslash_core::sql_policy::available(),
    });
    probe.extend(&mut body);
    (code, Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(
            body.get("db_error").is_none(),
            "the sqlx error must stay in the log, not the public body"
        );
    }

    #[test]
    fn extend_reports_down_without_detail() {
        let mut body = json!({ "status": "degraded" });
        DbProbe::Down.extend(&mut body);
        assert_eq!(body["db"], "down");
        assert!(body.get("db_error").is_none());
        assert!(body.get("db_latency_ms").is_none());
    }
}
