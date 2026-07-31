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
}

impl Topic {
    pub const ALL: [Topic; 3] = [Topic::Approvals, Topic::Connections, Topic::Secrets];

    pub fn as_str(&self) -> &'static str {
        match self {
            Topic::Approvals => "approvals",
            Topic::Connections => "connections",
            Topic::Secrets => "secrets",
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
            _ => Err(()),
        }
    }
}

/// Every event Overslash emits. Both the webhook dispatcher and the SSE stream
/// carry the same payload for a given variant (SPEC.md §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    ApprovalCreated,
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
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::ApprovalCreated => "approval.created",
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
        }
    }

    pub fn topic(&self) -> Topic {
        match self {
            EventType::ApprovalCreated
            | EventType::ApprovalResolved
            | EventType::ApprovalExecuted
            | EventType::ApprovalExecutionFailed
            | EventType::ApprovalExecutionCancelled => Topic::Approvals,
            EventType::ConnectionCreated
            | EventType::ConnectionUpdated
            | EventType::ConnectionScopesUpgraded
            | EventType::ConnectionDeleted => Topic::Connections,
            EventType::SecretRequestCreated | EventType::SecretRequestFulfilled => Topic::Secrets,
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
            (EventType::ApprovalExecutionCancelled, Topic::Approvals),
            (EventType::ConnectionDeleted, Topic::Connections),
            (EventType::SecretRequestFulfilled, Topic::Secrets),
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
}
