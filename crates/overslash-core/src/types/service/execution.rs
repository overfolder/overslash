use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Whether the caller waits on its connection for the upstream.
///
/// Named `execution` on the wire rather than `async` because `async` is a Rust
/// keyword and a reserved word in JS/TS, so the field would be unnameable in
/// generated clients and awkward in every mirror type.
///
/// `Sync` is the historical behaviour: the response carries the upstream body,
/// bounded by the deployment's request cap. `Async` accepts the call, persists
/// it, and hands back an execution id to poll — the only way a call can outlive
/// the caller's connection. See DECISIONS D62.
///
/// Lives in `overslash-core` rather than beside the request struct because a
/// *template* can now name one too, as `x-overslash-wait-mode` on an action —
/// so the compiler needs the type before the API does. The two spellings are
/// deliberate and worth knowing about when grepping: the request field is
/// `execution`, the extension key is `wait-mode`, and both lower to this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    #[default]
    Sync,
    Async,
    /// Starts like `Sync` and finishes like `Async`: the job runs off the
    /// connection from the first byte, and the connection waits on it for
    /// `handoff_after_ms`. Beat the window and the caller gets the ordinary
    /// `Called` envelope; miss it and the caller gets `Accepted` and polls.
    ///
    /// Both shapes are predictable from the request alone, which is the bar
    /// D56 set when it refused to *auto*-promote an over-ceiling call: the
    /// surprise it ruled out was a response shape that changed based on a
    /// number in a template the caller never saw. See DECISIONS D68.
    Hybrid,
}

impl ExecutionMode {
    pub fn is_async(self) -> bool {
        matches!(self, ExecutionMode::Async)
    }

    pub fn is_hybrid(self) -> bool {
        matches!(self, ExecutionMode::Hybrid)
    }

    /// Runs off the caller's connection — always (`Async`) or possibly
    /// (`Hybrid`).
    ///
    /// Every refusal in the API's flag gate keys off this rather than on the
    /// variant, so the two deferred modes cannot drift into different answers
    /// for the same flag combination.
    pub fn is_deferred(self) -> bool {
        !matches!(self, ExecutionMode::Sync)
    }

    /// Wire spelling, for error text that has to name the mode the caller
    /// actually asked for.
    pub fn label(self) -> &'static str {
        match self {
            ExecutionMode::Sync => "sync",
            ExecutionMode::Async => "async",
            ExecutionMode::Hybrid => "hybrid",
        }
    }
}

impl FromStr for ExecutionMode {
    type Err = ();

    /// Parses the same lowercase spellings serde accepts. Exists so the
    /// template extractor can report an unrecognized value as a validation
    /// issue naming the three legal ones, rather than surfacing a serde error
    /// with no path.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sync" => Ok(ExecutionMode::Sync),
            "async" => Ok(ExecutionMode::Async),
            "hybrid" => Ok(ExecutionMode::Hybrid),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_spelling_round_trips() {
        for m in [
            ExecutionMode::Sync,
            ExecutionMode::Async,
            ExecutionMode::Hybrid,
        ] {
            assert_eq!(ExecutionMode::from_str(m.label()), Ok(m));
            assert_eq!(
                serde_json::to_value(m).unwrap(),
                serde_json::Value::String(m.label().to_string()),
                "serde and label() disagree on {m:?}",
            );
        }
        assert_eq!(ExecutionMode::from_str("Hybrid"), Err(()));
        assert_eq!(ExecutionMode::from_str(""), Err(()));
    }

    #[test]
    fn only_sync_runs_on_the_connection() {
        assert!(!ExecutionMode::Sync.is_deferred());
        assert!(ExecutionMode::Async.is_deferred());
        assert!(ExecutionMode::Hybrid.is_deferred());
    }
}
