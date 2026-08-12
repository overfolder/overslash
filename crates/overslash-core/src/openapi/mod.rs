//! OpenAPI 3.1 + `x-overslash-*` front door for service templates.
//!
//! Service templates are authored as OpenAPI 3.1 documents. Fields the gateway
//! needs that OpenAPI cannot express natively (risk class, permission-scope
//! binding, parameter resolution, symbolic OAuth provider, default secret
//! name) live under the `x-overslash-*` vendor-extension namespace.
//!
//! To keep authoring ergonomic, the same keys may also be written without the
//! prefix (`risk:` instead of `x-overslash-risk:`). The normalizer in this
//! module rewrites every known alias to its canonical form before the rest of
//! the pipeline sees the document, and rejects ambiguous documents (both
//! forms present on the same object) with a `ambiguous_alias` issue.
//!
//! This module is a facade: the public API is implemented in private siblings
//! and re-exported here.
//!
//! - [`alias`] — context-aware alias-to-canonical rewriter ([`normalize_aliases`])
//!   and its tests.
//! - [`ext`] — the extension vocabulary, the position table recording where each
//!   key is *read*, and the accessor every extractor reads through.
//! - [`lint`] — [`lint_extensions`], which reports every extension key the
//!   compiler will silently ignore.
//! - [`extract`] — compile-step helpers (hosts, auth, actions, parameters,
//!   response types, resolvers) and their tests.
//! - [`compile`] — [`compile_service`], which wires the extract helpers
//!   together, plus the end-to-end compile tests.
//! - [`yaml`] — [`parse_yaml`] / [`to_yaml_string`] and their tests.

mod alias;
mod compile;
mod ext;
mod extract;
pub mod import;
mod lint;
pub mod validate_input;
#[cfg(feature = "yaml")]
mod yaml;

// ── Public API ───────────────────────────────────────────────────────

pub use alias::normalize_aliases;
pub use compile::compile_service;
pub use extract::overlay_discovered_tools;
pub use extract::url_to_host;
pub use lint::{LINT_CODES, lint_extensions};
#[cfg(feature = "yaml")]
pub use yaml::{parse_yaml, to_yaml_string};
