//! The event vocabulary shared by the webhook dispatcher and the SSE stream.
//!
//! These strings were string literals scattered across the dispatch call sites
//! until the stream needed to map each one to a topic and to validate
//! subscriber-supplied topic filters. Both transports read `as_str()`, so the
//! wire name of an event is defined exactly once — renaming a variant's string
//! silently breaks existing webhook subscriptions (which store the name
//! verbatim), so treat these as public API.

use std::fmt;
use std::str::FromStr;

/// Coarse subscription groups. Clients filter with `?topics=a,b`; omitting the
/// parameter subscribes to all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    Approvals,
    Connections,
    Secrets,
    /// Per-call traffic — one pair of events per action call, and the only
    /// topic whose volume scales with the gateway's hot path rather than with
    /// operator activity. Emission is gated on `live_map_enabled`; the topic
    /// itself stays permanently subscribable so a client that asks for it on a
    /// deployment with the flag off gets silence rather than a 400 that varies
    /// by environment.
    Activity,
}

impl Topic {
    pub const ALL: [Topic; 4] = [
        Topic::Approvals,
        Topic::Connections,
        Topic::Secrets,
        Topic::Activity,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Topic::Approvals => "approvals",
            Topic::Connections => "connections",
            Topic::Secrets => "secrets",
            Topic::Activity => "activity",
        }
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Topic {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "approvals" => Ok(Topic::Approvals),
            "connections" => Ok(Topic::Connections),
            "secrets" => Ok(Topic::Secrets),
            "activity" => Ok(Topic::Activity),
            _ => Err(()),
        }
    }
}

/// Every event Overslash emits. Both the webhook dispatcher and the SSE stream
/// carry the same payload for a given variant (SPEC.md §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    ApprovalCreated,
    /// Derived signal: this approval is now waiting on a decision from its
    /// current resolver. Fired after creation and again after every
    /// reassignment, so a caller that only wants an inbox wake-up can
    /// subscribe to one type instead of interpreting creation and bubbling
    /// separately.
    ///
    /// Deliberately has no audit-log counterpart — it restates a fact
    /// `approval.created` and `approval.bubbled` already recorded, and an
    /// audit row per gated agent call would be pure volume.
    ApprovalPending,
    ApprovalBubbled,
    ApprovalResolved,
    ApprovalExecuted,
    ApprovalExecutionFailed,
    ApprovalExecutionCancelled,
    ConnectionCreated,
    ConnectionUpdated,
    ConnectionScopesUpgraded,
    ConnectionDeleted,
    SecretRequestCreated,
    SecretRequestFulfilled,
    /// An action call has started. Paired with [`EventType::ActionCompleted`]
    /// by a `call_id` minted in the request wrapper.
    ///
    /// Unlike every other variant here, these two fire on the gateway's
    /// hottest path — one durable `events` row each, per call. That is why
    /// both are emitted only when `live_map_enabled` is set, and why the
    /// dashboard's Live Map is a dev-gated view rather than a default one.
    ///
    /// The pair is *not* ordered: they bracket the upstream call, so
    /// [`emit_all`](super::emit_all) cannot cover them and each `emit` spawns
    /// its own task. A consumer must tolerate `completed` arriving first.
    ActionCalled,
    /// An action call finished, however it finished. `outcome` carries the
    /// same classification the metrics wrapper uses (`called`, `denied`,
    /// `rejected`, `failed`, `upstream_error`), so a 403 and an upstream 500
    /// stay distinguishable.
    ActionCompleted,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::ApprovalCreated => "approval.created",
            EventType::ApprovalPending => "approval.pending",
            EventType::ApprovalBubbled => "approval.bubbled",
            EventType::ApprovalResolved => "approval.resolved",
            EventType::ApprovalExecuted => "approval.executed",
            EventType::ApprovalExecutionFailed => "approval.execution_failed",
            EventType::ApprovalExecutionCancelled => "approval.execution_cancelled",
            EventType::ConnectionCreated => "connection.created",
            EventType::ConnectionUpdated => "connection.updated",
            EventType::ConnectionScopesUpgraded => "connection.scopes_upgraded",
            EventType::ConnectionDeleted => "connection.deleted",
            EventType::SecretRequestCreated => "secret_request.created",
            EventType::SecretRequestFulfilled => "secret_request.fulfilled",
            EventType::ActionCalled => "action.called",
            EventType::ActionCompleted => "action.completed",
        }
    }

    pub fn topic(&self) -> Topic {
        match self {
            EventType::ApprovalCreated
            | EventType::ApprovalPending
            | EventType::ApprovalBubbled
            | EventType::ApprovalResolved
            | EventType::ApprovalExecuted
            | EventType::ApprovalExecutionFailed
            | EventType::ApprovalExecutionCancelled => Topic::Approvals,
            EventType::ConnectionCreated
            | EventType::ConnectionUpdated
            | EventType::ConnectionScopesUpgraded
            | EventType::ConnectionDeleted => Topic::Connections,
            EventType::SecretRequestCreated | EventType::SecretRequestFulfilled => Topic::Secrets,
            EventType::ActionCalled | EventType::ActionCompleted => Topic::Activity,
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a `?topics=` value. `None` or an empty string means "everything";
/// an unrecognised name is an error so a client typo fails loudly at connect
/// instead of silently delivering no events.
pub fn parse_topics(raw: Option<&str>) -> Result<Vec<Topic>, String> {
    let Some(raw) = raw else {
        return Ok(Topic::ALL.to_vec());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Topic::ALL.to_vec());
    }

    let mut topics = Vec::new();
    for part in trimmed.split(',') {
        let name = part.trim();
        if name.is_empty() {
            continue;
        }
        let topic = Topic::from_str(name).map_err(|_| name.to_string())?;
        if !topics.contains(&topic) {
            topics.push(topic);
        }
    }
    if topics.is_empty() {
        return Ok(Topic::ALL.to_vec());
    }
    Ok(topics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_type_round_trips_its_topic() {
        // Guards against a new variant landing in `as_str` but not `topic`.
        for (event, expected) in [
            (EventType::ApprovalCreated, Topic::Approvals),
            (EventType::ApprovalPending, Topic::Approvals),
            (EventType::ApprovalBubbled, Topic::Approvals),
            (EventType::ApprovalExecutionCancelled, Topic::Approvals),
            (EventType::ConnectionDeleted, Topic::Connections),
            (EventType::SecretRequestFulfilled, Topic::Secrets),
            (EventType::ActionCalled, Topic::Activity),
            (EventType::ActionCompleted, Topic::Activity),
        ] {
            assert_eq!(event.topic(), expected, "{event}");
        }
    }

    #[test]
    fn absent_or_blank_topics_subscribe_to_everything() {
        assert_eq!(parse_topics(None).unwrap(), Topic::ALL.to_vec());
        assert_eq!(parse_topics(Some("")).unwrap(), Topic::ALL.to_vec());
        assert_eq!(parse_topics(Some("  ")).unwrap(), Topic::ALL.to_vec());
    }

    #[test]
    fn topics_parse_dedupe_and_reject_unknown() {
        assert_eq!(
            parse_topics(Some("approvals, secrets")).unwrap(),
            vec![Topic::Approvals, Topic::Secrets]
        );
        assert_eq!(
            parse_topics(Some("approvals,approvals")).unwrap(),
            vec![Topic::Approvals]
        );
        assert_eq!(parse_topics(Some("approvals,bogus")), Err("bogus".into()));
    }

    /// `activity` parses whether or not `live_map_enabled` is set. Emission is
    /// what the flag gates; a subscription that 400s on one deployment and
    /// succeeds on another would be a worse contract than one that is quiet.
    #[test]
    fn activity_is_a_valid_topic_independent_of_the_live_map_flag() {
        assert_eq!(
            parse_topics(Some("approvals,activity")).unwrap(),
            vec![Topic::Approvals, Topic::Activity]
        );
        assert!(Topic::ALL.contains(&Topic::Activity));
    }
}
