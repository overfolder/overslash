//! Derived timing windows: the wall clocks a call is measured against, and
//! the ages at which a background sweeper gives up on a row.
//!
//! They live together because they are one chain — each sweeper window is its
//! subsystem's own deadline plus [`Config::sweep_grace_secs`], and that single
//! knob is what stops three sweepers from drifting apart. None of them is
//! configured directly; deriving them is what keeps a window from ever being
//! set below the deadline it is supposed to be guarding.

use super::Config;

/// Slack added to [`Config::call_timeout_max_ms`] to get the replay wall.
///
/// Covers what the replay future does *after* the upstream answers — secret
/// decryption, jq filtering, finalising the execution row — so the wall never
/// fires on a call that merely used its full, legitimate budget.
const REPLAY_WALL_SLACK_MS: u64 = 5_000;

impl Config {
    /// Outer wall-clock guard for `POST /v1/approvals/{id}/call`.
    ///
    /// Derived rather than configured, so a per-call timeout can never be
    /// silently shadowed by the wall and an operator never has to bump two env
    /// vars in lockstep. Always at least the largest timeout the D56 resolver
    /// can return, plus slack for the post-call work.
    pub fn replay_wall_clock(&self) -> std::time::Duration {
        let floor_ms = self.call_timeout_max_ms + REPLAY_WALL_SLACK_MS;
        std::time::Duration::from_millis((self.execution_replay_timeout_secs * 1_000).max(floor_ms))
    }

    /// Grace before the sweeper reclaims an `executing` execution row as
    /// orphaned. [`Self::sweep_grace_secs`] past the wall: if the wall had been
    /// going to fire, it already would have, so anything still `executing`
    /// lost its process.
    pub fn orphan_execution_grace_secs(&self) -> i64 {
        self.replay_wall_clock().as_secs() as i64 + self.sweep_grace_secs as i64
    }

    /// How often a worker renews its lease. Derived as a third of the TTL, so
    /// a job gets three chances to renew before it is presumed dead — and so
    /// the two can never be configured into contradiction.
    ///
    /// This interval also bounds cancel latency: the heartbeat's
    /// `RETURNING cancel_requested` *is* the cancel poll, deliberately, so
    /// "I still own this row" and "I should stop" are one atomic observation.
    pub fn async_heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs((self.async_execution.lease_ttl_secs / 3).max(1))
    }

    /// Outer wall-clock guard for one async job. Mirrors [`Self::replay_wall_clock`]:
    /// the largest budget the resolver can hand out, plus slack for the work
    /// after the upstream answers.
    pub fn async_wall_clock(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.async_execution.call_timeout_max_ms + REPLAY_WALL_SLACK_MS,
        )
    }

    /// Grace before the sweeper fails an async row that is still `executing`
    /// past its wall. Same slack, on the same reasoning as
    /// [`Self::orphan_execution_grace_secs`].
    pub fn async_orphan_grace_secs(&self) -> i64 {
        self.async_wall_clock().as_secs() as i64 + self.sweep_grace_secs as i64
    }

    /// Age at which a `pending`/`claimed` `pending_mcp_elicitations` row is
    /// presumed orphaned and cancelled by the sweeper.
    ///
    /// Derived from the originator's own poll ceiling
    /// ([`crate::services::mcp_session::DEFAULT_TIMEOUT`]) rather than
    /// configured, so it can never be set *below* it — a shorter window would
    /// retire a row somebody is still polling, and `await_completion` reads
    /// that as a cancellation the user never asked for. Past the ceiling the
    /// originator has either cancelled the row itself or lost its process.
    pub fn mcp_elicitation_reap_after_secs(&self) -> i64 {
        crate::services::mcp_session::DEFAULT_TIMEOUT.as_secs() as i64
            + self.sweep_grace_secs as i64
    }

    /// Age at which a terminal `pending_mcp_elicitations` row is deleted.
    ///
    /// Twice the reap window, so the two phases stay ordered: every row is
    /// cancelled before it is deleted, the way `subagent_archive` precedes
    /// `subagent_purge`. Deliberately short — `final_response` holds a full
    /// `ApprovalResponse` snapshot, `disclosed_fields` included, and nothing
    /// reads it once the originator's stream has closed.
    pub fn mcp_elicitation_retention_secs(&self) -> i64 {
        self.mcp_elicitation_reap_after_secs() * 2
    }
}
