//! Import options, warnings, and the preparation result.

use std::collections::HashSet;

use serde::Serialize;
use serde_json::Value;

/// User-supplied knobs for a single import call. All fields are optional; an
/// all-`None`/all-empty struct imports the source verbatim.
#[derive(Default, Debug, Clone)]
pub struct ImportOptions {
    /// If `Some`, keep only operations whose id (real or synthesized) appears
    /// in this set. Unknown ids are silently ignored (the response surfaces
    /// which were matched via `OperationInfo.included`).
    pub include_operations: Option<HashSet<String>>,
    /// Override `info.x-overslash-key` (or seed it if the source has none).
    pub key: Option<String>,
    /// Override `info.title` (used by the compiler as `display_name`).
    pub display_name: Option<String>,
}

/// Pure result of parsing + lowering an OpenAPI source. The caller decides
/// what to do with it: run the regular validator, store as a draft, render a
/// preview, etc.
#[derive(Debug, Clone)]
pub struct ImportPreparation {
    /// Lowered canonical document. Still needs `normalize_aliases` +
    /// `compile_service` (or a full [`crate::template_validation`] pass).
    pub doc: Value,
    /// Non-blocking issues: dropped OpenAPI features, unresolved refs,
    /// OpenAPI 3.0 sources that we accepted as-is, etc.
    pub warnings: Vec<ImportWarning>,
    /// Every operation from the *original* source, with an `included` flag
    /// reflecting the filter in [`ImportOptions::include_operations`].
    pub operations: Vec<OperationInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportWarning {
    pub code: String,
    pub message: String,
    /// Dotted path into the source document (e.g.
    /// `"paths./widgets.get.responses.200"`). Empty when the warning is
    /// document-wide.
    pub path: String,
}

impl ImportWarning {
    pub(super) fn new(
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

#[derive(Debug, Clone, Serialize)]
pub struct OperationInfo {
    /// Either the original `operationId` or a synthesized one
    /// (`{method}_{path_slug}`) if the source didn't have one.
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub summary: Option<String>,
    /// True when this operation survives the import filter (or no filter was
    /// set).
    pub included: bool,
    /// True when the source had an explicit `operationId`; false when it was
    /// derived from the path/method. Useful for the UI so it can flag
    /// "auto-named" ids that the user should rename before promoting.
    pub synthesized_id: bool,
}
