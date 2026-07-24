//! Platform kernel for HTTP-OAuth connection initiation.
//!
//! Mirrors `platform_services.rs` and `platform_templates.rs`: a pure async
//! function that takes a [`PlatformCallContext`] plus typed input and returns
//! a typed response. Both the REST handler in `routes/connections.rs` and the
//! MCP platform dispatcher (via `platform_registry`) call into the same
//! kernel.
//!
//! ## Why this kernel does not return the raw provider authorize URL
//!
//! The Obsidian Security writeup *"When MCP Meets OAuth: Common Pitfalls
//! Leading to One-Click Account Takeover"* (2025) catalogues attack patterns
//! that get worse when an agent delivers a raw provider authorize URL to the
//! user over chat — the user sees `https://github.com/...` and has no
//! Overslash-branded checkpoint that says *which* agent triggered *which*
//! identity's flow on *which* org. The mitigations baked into
//! `crates/overslash-api/src/routes/oauth.rs` (PKCE-S256 mandatory, state
//! bound to session/org at the consent step, DCR-validated `redirect_uri`,
//! single-use refresh-token rotation) all hold per the table in
//! `docs/design/agent-mcp-bootstrap-story.md` §3 — those mechanisms are
//! untouched by this kernel.
//!
//! What this kernel adds on top of those is the chat-delivery hardening
//! that the upstream-MCP path already has via `mcp_upstream_flows` /
//! `/gated-authorize` (`routes/oauth_upstream.rs`). The kernel persists an
//! `oauth_connection_flows` row holding the raw authorize URL and returns
//! `auth_url` set to `{public_url}/connect-authorize?id=<flow>` instead
//! of the raw provider URL. The wire-level field name is unchanged so
//! existing REST clients keep working — only the *value* upgrades to the
//! gated URL, which fail-fasts on missing/expired/consumed/session-
//! mismatch before 302ing to the provider. The raw provider authorize URL is
//! never surfaced — white-label partners run their own OAuth dance and import
//! the resulting tokens via `/v1/connections/import` rather than wrapping an
//! Overslash-built authorize URL.
//!
//! ## URL bundle
//!
//! The kernel returns two flavors of the same authorize handle:
//!
//! - `auth_url`: the Overslash-gated URL — the default deliverable.
//! - `short`: best-effort `oversla.sh/<slug>` redirect to `auth_url`,
//!   present only when the shortener is configured. Friendlier for chat
//!   delivery where long base62 ids get mangled by line-wrapping.
//!
//! The same pair flows through the action-handler error envelopes
//! (`reauth_required`, `needs_authentication`, `missing_scopes`) via
//! [`mint_initial_auth_url`] and [`mint_upgrade_auth_url`].

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};
use uuid::Uuid;

use overslash_core::crypto;
use overslash_db::repos::connection::{ConnectionRow, CreateConnection};
use overslash_db::repos::oauth_connection_flow::{self, CreateOauthConnectionFlow};
use overslash_db::scopes::OrgScope;

use super::group_ceiling;
use super::oauth;
use super::oauth_upstream as svc;
use super::platform_caller::PlatformCallContext;
use super::short_url;
use crate::AppState;
use crate::error::AppError;

mod create;
mod import;
mod mint;
mod scopes;
mod url;

pub(crate) use self::url::{default_callback_redirect_uri, parse_return_url};
pub(crate) use create::kernel_create_connection_for_identity;
pub use create::{
    AuthRecoveryUrls, CreateConnectionInput, CreateConnectionResponse, RequestMeta,
    dispatch_create_connection, kernel_create_connection,
};
pub use import::{ImportConnectionInput, ImportConnectionResponse, kernel_import_connection};
pub use mint::{mint_initial_auth_url, mint_upgrade_auth_url};
pub use scopes::merge_scopes;
