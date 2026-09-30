//! [`AsyncExecutionConfig`] — the async-execution knobs, nested under
//! `Config::async_execution`.

/// Async (non-blocking) action execution — see DECISIONS D62.
///
/// Nested rather than five flat `Config` fields on purpose. Every `Config`
/// field has to be repeated in the test builder and in ~14 test fixtures that
/// list fields explicitly, so five flat knobs would be ~75 mechanical edits and
/// every future async knob another 15. One nested field costs one line each.
#[derive(Clone, Debug)]
pub struct AsyncExecutionConfig {
    /// `ASYNC_EXECUTION_ENABLED`. Off means `execution: "async"` is rejected at
    /// the boundary and no worker or signal handler is spawned, so a
    /// flag-off deployment behaves exactly as it did before this feature.
    pub enabled: bool,
    /// `ASYNC_CALL_TIMEOUT_MAX_MS`. The deployment ceiling for an async call,
    /// passed to the same `call_timeout::resolve` the sync path uses.
    ///
    /// Much larger than `call_timeout_max_ms` because that number exists to sit
    /// under a proxy's request cap, and no proxy is counting an async call. The
    /// binding constraints instead are instance lifetime (Cloud Run may recycle
    /// at any time) and retry economics (`max_attempts` defaults to 1, so a lost
    /// job is a failed job).
    pub call_timeout_max_ms: u64,
    /// `ASYNC_WORKER_CONCURRENCY`. Jobs one replica runs at once.
    ///
    /// Default 2 is a *connection* budget, not a throughput guess: the request
    /// pool (25) plus the background pool (6) is 31 per instance, and with
    /// `max_instances = 3` that is 93 against a Postgres ceiling around 97.
    /// Raising this requires raising `DB_BACKGROUND_MAX_CONNECTIONS` by the
    /// same amount, and 3 x (DB_MAX_CONNECTIONS + DB_BACKGROUND_MAX_CONNECTIONS)
    /// must stay under that ceiling.
    pub worker_concurrency: usize,
    /// `ASYNC_LEASE_TTL_SECS`. How long a claim stays valid without a
    /// heartbeat. Independent of job duration — the heartbeat is what keeps a
    /// long job alive — so this only needs to tolerate a GC pause or a slow
    /// database, not a slow upstream.
    pub lease_ttl_secs: u64,
    /// `ASYNC_MAX_ATTEMPTS`. Attempts before a row that keeps losing its lease
    /// is failed outright.
    ///
    /// Defaults to **1**: an action call is not idempotent and there is no
    /// idempotency-key concept, so a POST that already reached the upstream
    /// must not be replayed because a worker died. Operators who know their
    /// actions are safe to retry raise it.
    pub max_attempts: i32,
    /// `HYBRID_HANDOFF_MS`. How long a `execution: "hybrid"` call waits on the
    /// connection before answering 202 and letting the job finish off it.
    ///
    /// A deployment default, so it is *clamped* against the call's own budget
    /// rather than refused — see `services::hybrid::resolve_handoff`. A caller
    /// who names `handoff_after_ms` explicitly gets a 400 instead, which is the
    /// same split `timeout_ms` already makes between a template default and a
    /// number a caller asked for.
    pub hybrid_handoff_ms: u64,
    /// `HYBRID_HANDOFF_MAX_MS`. Ceiling on a caller-supplied `handoff_after_ms`.
    ///
    /// Well under `call_timeout_max_ms`: a handoff longer than the synchronous
    /// connection ceiling cannot fire before the proxy cuts the connection, so
    /// permitting one would only produce a 504 where the caller asked for a 202.
    pub hybrid_handoff_max_ms: u64,
    /// `HYBRID_MAX_INFLIGHT`. Hybrid jobs one replica runs at once.
    ///
    /// A hybrid call spawns its job from the *request* path, so unlike the
    /// worker loop nothing else bounds it — N concurrent requests would be N
    /// detached tasks against the same background pool `worker_concurrency` is
    /// sized for. Over this, a hybrid call is accepted onto the ordinary async
    /// queue instead: same envelope, same poll URL, no shape change the caller
    /// can observe.
    pub hybrid_max_inflight: usize,
}

impl Default for AsyncExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            call_timeout_max_ms: 900_000,
            worker_concurrency: 2,
            lease_ttl_secs: 60,
            max_attempts: 1,
            hybrid_handoff_ms: 5_000,
            hybrid_handoff_max_ms: 30_000,
            hybrid_max_inflight: 32,
        }
    }
}
