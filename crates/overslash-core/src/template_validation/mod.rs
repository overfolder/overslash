//! Template validation — the parser/linter that backs `POST /v1/templates/validate`
//! and the create/update CRUD hooks. Also used by the global registry loader.
//!
//! ## Layout
//!
//! - [`core`] is the WASM-safe struct-level validator. It takes a
//!   [`ServiceDefinition`](crate::types::ServiceDefinition) and returns a
//!   [`ValidationReport`]. No YAML, no `serde_json` deserialization, no I/O.
//! - [`json`] wraps `core` for the CRUD hook path where `auth`/`actions` are
//!   stored as `serde_json::Value`.
//! - [`yaml`] wraps `core` for the HTTP endpoint path; accepts raw YAML text
//!   and surfaces YAML parse errors as regular validation errors. Gated
//!   behind the `yaml` cargo feature so WASM builds can exclude it.
//!
//! Duplicate-action-key detection is a YAML-source-level concern because
//! `serde_yaml::Mapping` and `serde_json::Map` both dedupe at the `Value`
//! level. The YAML entry point walks the `actions:` mapping before it round-trips
//! through `serde_yaml::Mapping` and passes the raw ordered key list to `core`
//! via the `raw_action_keys` side-channel.
//!
//! ## Platform templates
//!
//! `services/overslash.yaml` is a "platform namespace" template: empty `hosts`,
//! empty `auth`, and its actions have neither `method` nor `path` — they exist
//! only as permission-key anchors for platform operations. The validator
//! accommodates this by treating an action with an empty `method` as a
//! non-HTTP action and skipping HTTP-specific checks for it. Empty `hosts` and
//! empty `auth` are also allowed (the entries that ARE present still get
//! validated).

use serde::{Deserialize, Serialize};

pub mod core;
pub mod json;
#[cfg(feature = "yaml")]
pub mod yaml;

pub use core::validate_service_definition;
pub use json::validate_template_parts;
#[cfg(feature = "yaml")]
pub use yaml::validate_template_yaml;

/// The outcome of validating a template. Returned by every entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// `true` iff `errors` is empty. Warnings do not affect validity.
    pub valid: bool,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Consume this report, producing an empty one and returning whether the
    /// consumed report was valid.
    pub fn is_ok(&self) -> bool {
        self.valid
    }
}

/// A single problem found during validation. Shaped for dashboard display and
/// programmatic handling: `code` is stable (machine-readable), `message` is
/// for humans, and `path` is a dot-path into the template for precise
/// localization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Stable machine-readable identifier, e.g. `"unknown_path_param"`.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Dot-path into the template, e.g. `"actions.list_events.path"`.
    pub path: String,
}

impl ValidationIssue {
    pub(crate) fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            path: path.into(),
        }
    }
}

/// Internal accumulator used by the validation passes in `core`.
#[derive(Default)]
pub(crate) struct Issues {
    errors: Vec<ValidationIssue>,
    warnings: Vec<ValidationIssue>,
}

impl Issues {
    pub(crate) fn err(
        &mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        path: impl Into<String>,
    ) {
        self.errors.push(ValidationIssue::new(code, message, path));
    }

    pub(crate) fn warn(
        &mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        path: impl Into<String>,
    ) {
        self.warnings
            .push(ValidationIssue::new(code, message, path));
    }

    pub(crate) fn finish(self) -> ValidationReport {
        ValidationReport {
            valid: self.errors.is_empty(),
            errors: self.errors,
            warnings: self.warnings,
        }
    }
}
