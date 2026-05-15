//! Capability-shape scenarios for the upstream MCP fake.
//!
//! Each variant flips what the fake MCP server advertises in `initialize`
//! and what it returns from `tools/list` and `resources/list`. The variants
//! exist so the e2e harness can pin Overslash's MCP client (and the
//! dashboard MCP-connection UI that renders the negotiated capabilities)
//! against a known capability shape without us having to edit the fake
//! between runs.
//!
//! Selection: the `overslash-fakes` binary takes `--mcp-variant <name>`
//! (env: `OVERSLASH_FAKES_MCP_VARIANT`). Defaults to `default` — tools-only,
//! one echo tool, matching the foundation PR's behaviour for callers that
//! don't care about capability shape.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum McpVariant {
    /// Tools-only with a single `echo` tool. Matches the foundation PR.
    #[default]
    Default,
    /// Tools advertised; elicitation server-capability *not* declared.
    /// Approval gaps must reach the user via the dashboard queue alone.
    NoElicitation,
    /// Tools + elicitation server-capability declared. Every `tools/call`
    /// kicks the upstream into eliciting before returning a result.
    FullElicitation,
    /// Tools-only, but `tools/list` returns a strict subset (just `echo`,
    /// not the optional `search` tool the default offers when extended).
    /// Lets the dashboard prove it doesn't hallucinate tools the upstream
    /// hasn't advertised.
    PartialTools,
    /// Resources advertised, no tools. `tools/list` returns an empty array;
    /// `resources/list` returns one item the dashboard should surface.
    ResourcesOnly,
}

impl McpVariant {
    /// Capability map advertised in `initialize.result.capabilities`.
    pub fn capabilities(self) -> Value {
        match self {
            McpVariant::Default | McpVariant::NoElicitation | McpVariant::PartialTools => {
                json!({ "tools": {} })
            }
            McpVariant::FullElicitation => json!({ "tools": {}, "elicitation": {} }),
            McpVariant::ResourcesOnly => json!({ "resources": {} }),
        }
    }

    /// Tool list returned from `tools/list`.
    pub fn tools(self) -> Value {
        let echo = json!({
            "name": "echo",
            "description": "Echoes back its `message` argument.",
            "inputSchema": {
                "type": "object",
                "properties": { "message": { "type": "string" } },
                "required": ["message"],
            },
        });
        let search = json!({
            "name": "search",
            "description": "Returns a fixed search result (default variant only).",
            "inputSchema": {
                "type": "object",
                "properties": { "q": { "type": "string" } },
                "required": ["q"],
            },
        });
        match self {
            McpVariant::Default | McpVariant::FullElicitation | McpVariant::NoElicitation => {
                json!({ "tools": [echo, search] })
            }
            McpVariant::PartialTools => json!({ "tools": [echo] }),
            McpVariant::ResourcesOnly => json!({ "tools": [] }),
        }
    }

    /// Resource list returned from `resources/list`.
    pub fn resources(self) -> Value {
        match self {
            McpVariant::ResourcesOnly => json!({
                "resources": [{
                    "uri": "memo://greeting",
                    "name": "greeting",
                    "mimeType": "text/plain",
                }],
            }),
            _ => json!({ "resources": [] }),
        }
    }

    /// Whether `tools/call` should pretend the upstream is eliciting before
    /// returning. The fake doesn't actually open a server-initiated MCP
    /// notification stream — it just returns an `isError: false` envelope
    /// whose `content[0].text` flags that elicitation occurred, so e2e
    /// tests can assert on it without parsing SSE in JS.
    pub fn elicits_on_call(self) -> bool {
        matches!(self, McpVariant::FullElicitation)
    }
}
