use std::time::{Duration, Instant};

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use overslash_core::build_info::build_info;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::AppState;

/// Upper bound on how long a probe may wait for Postgres.
///
/// Without this, `PgPool::acquire` blocks for the pool's `acquire_timeout`
/// (30 s by default) when the database is unreachable, and the uptime check
/// (10 s timeout) would read a hung database as a timeout rather than a 503.
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

/// Origin health: 200 when the process *and* Postgres are up, 503 otherwise.
///
/// This is what the GCM uptime check (`[P0] API Down`) and the Better Stack
/// monitor probe, so a database outage pages. It used to be always-200 because
/// the Cloud Run probes pointed here; they are TCP probes now
/// (`infra/modules/cloud-run/main.tf`), so nothing restarts a container on a
/// 503 from this endpoint.
async fn health(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    respond(probe_db(&state.db).await, "ok")
}

/// Readiness. Same gate as [`health`]; kept for the callers that use it.
async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    respond(probe_db(&state.db).await, "ready")
}

/// Shared body + status for both endpoints: `up_status` when the database
/// answered, 503 `degraded` when it did not.
fn respond(probe: DbProbe, up_status: &str) -> (StatusCode, Json<Value>) {
    let (code, status) = if probe.is_up() {
        (StatusCode::OK, up_status)
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
    fn respond_is_503_degraded_when_db_is_down() {
        let (code, Json(body)) = respond(DbProbe::Down, "ok");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["db"], "down");

        let (code, Json(body)) = respond(DbProbe::Up { latency_ms: 1 }, "ok");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "ok");
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
