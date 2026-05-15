//! `overslash-mcp-puppet` — a generic, scriptable MCP client used to drive
//! end-to-end test scenarios against Overslash's `/mcp` endpoint (or any other
//! MCP server speaking Streamable HTTP + JSON-RPC).
//!
//! This crate is a **test harness**, not a reusable MCP client SDK. It
//! deliberately diverges from official SDK conventions — official SDKs
//! (`@modelcontextprotocol/sdk`, `mcp` for Python) expose elicitation as a
//! session-global handler set once on the client; we expose elicitation
//! answers per `tools/call`, plus an explicit suspend/resume shape, so that
//! tests can either pre-script the answers (compact case) or inspect each
//! prompt before deciding (interactive case). REST parity is the load-bearing
//! constraint — closures don't cross HTTP, but suspend-tokens do.
//!
//! See `docs/design/mcp-puppet.md` (forthcoming) and the plan at
//! `.claude/plans/we-should-have-a-glistening-eich.md`.

pub mod client;
pub mod error;
pub mod server;
pub mod sse;
pub mod types;

pub use client::PuppetClient;
pub use error::{Error, Result};
pub use types::{
    Auth, CallStep, CallToolOpts, ClientCaps, ConnectOpts, ElicitationAnswer, ElicitationRequest,
    HandledElicitation, InitializeResult, JsonRpcError, SuspendedCall,
};
