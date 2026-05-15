//! Background-task instrumentation. Each loop iteration should call
//! `record_tick` once with its outcome and, on success, `set_last_success`
//! so the silent-hang alert can detect a wedged loop.
//!
//! Task names are stable strings used both as Prom labels and in alert
//! PromQL — keep them lowercase, snake_case, and short.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use metrics::{counter, gauge, histogram};

/// `status` ∈ {`ok`, `noop`, `err`}. Use `noop` for ticks where nothing
/// needed doing — they still count as liveness signals.
pub fn record_tick(task: &str, status: &str, elapsed: Duration) {
    counter!(
        "overslash_background_task_ticks_total",
        "task" => task.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);
    histogram!(
        "overslash_background_task_duration_seconds",
        "task" => task.to_string(),
    )
    .record(elapsed.as_secs_f64());
}

/// Set the unix timestamp of the most recent successful (or noop) tick.
/// The P1 staleness alert fires when `time() - max(this) > 300s`.
pub fn set_last_success(task: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    gauge!(
        "overslash_background_task_last_success_timestamp",
        "task" => task.to_string(),
    )
    .set(now);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_helpers_do_not_panic() {
        record_tick("test_task", "ok", Duration::from_millis(2));
        record_tick("test_task", "noop", Duration::from_micros(50));
        record_tick("test_task", "err", Duration::from_secs(1));
        set_last_success("test_task");
    }
}
