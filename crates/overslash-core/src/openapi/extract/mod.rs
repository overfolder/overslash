//! Extraction helpers: lower a normalized OpenAPI JSON document into the
//! fields of [`crate::types::ServiceDefinition`]. None of these helpers
//! mutate their inputs — normalization happens upstream in
//! [`super::alias`].
//!
//! The helpers are grouped by what they produce, one submodule per group:
//!
//! - [`auth`] + [`schemes`] — `components.x-overslash-secrets` /
//!   `x-overslash-config` / `securitySchemes` → `Vec<ServiceAuth>`.
//! - [`actions`] — `paths.*.*` and `x-overslash-platform_actions.*` →
//!   `ServiceAction`, plus `responses.*.content.*` → `"json"` / `"binary"`.
//! - [`mcp`] — `x-overslash-mcp` → `McpSpec` + its `ServiceAction`s.
//! - [`params`] — parameter-level helpers.
//! - this module — `servers[].url` → `hosts`, plus the `x-overslash-*`
//!   readers that more than one of the groups above needs.

use std::str::FromStr;

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::{
    DisclosureField, DownloadAuth, DownloadSpec, ExecutionMode, NextSpec, NextStyle, PageSize,
    PaginationSpec, ScopeParams, UploadMethod, UploadResultSpec, UploadSpec,
};

use super::ext::{self, Ext, Pos};

mod actions;
mod auth;
mod mcp;
mod params;
mod schemes;

pub use mcp::overlay_discovered_tools;

pub(super) use actions::{extract_http_action, extract_platform_action};
pub(super) use auth::{CompiledCredentials, extract_auth};
pub(super) use mcp::{extract_mcp_actions, extract_mcp_spec};
use params::parse_resolver;

/// Lower `x-overslash-scope_param` — a param name, a `param:label` pair, or a
/// list of either — into [`ScopeParams`].
///
/// Absent is the common case and means "unscoped" (`{service}:{action}:*`).
/// A shape that is neither a string nor a list of strings is an **error**
/// rather than a silent drop: dropping it would quietly widen the action's
/// permission key to the wildcard, which is the opposite of what the author
/// asked for.
fn parse_scope_params(raw: Option<&Value>, base: &str) -> Result<ScopeParams, ValidationIssue> {
    let invalid = |msg: String| {
        ValidationIssue::new(
            "invalid_scope_param",
            msg,
            format!("{base}.x-overslash-scope_param"),
        )
    };
    let entries: Vec<&str> = match raw {
        None | Some(Value::Null) => return Ok(ScopeParams::default()),
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str().ok_or_else(|| {
                    invalid(format!(
                        "x-overslash-scope_param list entries must be strings (got {v})"
                    ))
                })
            })
            .collect::<Result<_, _>>()?,
        Some(other) => {
            return Err(invalid(format!(
                "x-overslash-scope_param must be a param name or a list of them (got {other})"
            )));
        }
    };
    ScopeParams::parse_list(entries).map_err(invalid)
}

// ── servers → hosts ──────────────────────────────────────────────────

pub(super) fn extract_hosts(servers: Option<&Value>) -> Vec<String> {
    let Some(arr) = servers.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| s.as_object())
        .filter_map(|o| o.get("url").and_then(Value::as_str))
        .filter_map(url_to_host)
        .collect()
}

pub fn url_to_host(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let host = s.split('/').next()?.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

// ── x-overslash-disclose / x-overslash-redact ─────────────────────────

fn parse_disclose(
    v: Option<&Value>,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Vec<DisclosureField> {
    let Some(v) = v else { return Vec::new() };
    let Some(arr) = v.as_array() else {
        issues.push(ValidationIssue::new(
            "disclose_malformed",
            "x-overslash-disclose must be an array of {label, filter, max_chars?}",
            format!("{base}.x-overslash-disclose"),
        ));
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let p = format!("{base}.x-overslash-disclose[{i}]");
        let Some(obj) = item.as_object() else {
            issues.push(ValidationIssue::new(
                "disclose_malformed",
                "entry must be an object with `label` and `filter`",
                p,
            ));
            continue;
        };
        let label = match obj.get("label").and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => s.to_string(),
            _ => {
                issues.push(ValidationIssue::new(
                    "disclose_invalid_label",
                    "`label` must be a non-empty string",
                    format!("{p}.label"),
                ));
                continue;
            }
        };
        let filter = match obj.get("filter").and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => s.to_string(),
            _ => {
                issues.push(ValidationIssue::new(
                    "disclose_malformed",
                    "`filter` must be a non-empty jq expression string",
                    format!("{p}.filter"),
                ));
                continue;
            }
        };
        let max_chars = obj
            .get("max_chars")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        let primary = obj.get("primary").and_then(Value::as_bool).unwrap_or(false);
        out.push(DisclosureField {
            label,
            filter,
            max_chars,
            primary,
        });
    }
    out
}

/// Parse `x-overslash-download` — the declaration that an MCP tool's result
/// *references* a downloadable object instead of carrying it.
///
/// `url` is mandatory; a block without it is malformed rather than
/// partially-honored, because a download with no location is not a weaker
/// download, it's nothing at all. The optional metadata filters are dropped
/// individually when blank so one typo doesn't take the whole block down.
fn parse_download(
    v: Option<&Value>,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<DownloadSpec> {
    let v = v?;
    let p = format!("{base}.x-overslash-download");
    let Some(obj) = v.as_object() else {
        issues.push(ValidationIssue::new(
            "download_malformed",
            "x-overslash-download must be an object with `url` and optional {mime, size, filename, auth}",
            p,
        ));
        return None;
    };
    let url = match obj.get("url").and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => {
            issues.push(ValidationIssue::new(
                "download_malformed",
                "`url` must be a non-empty jq expression string",
                format!("{p}.url"),
            ));
            return None;
        }
    };
    // Blank/non-string metadata filters are simply absent — the descriptor
    // just carries one less field.
    let pick = |key: &str| {
        obj.get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
    };
    let auth = match obj.get("auth").and_then(Value::as_str) {
        None | Some("inherit") => DownloadAuth::Inherit,
        Some("none") => DownloadAuth::None,
        Some(other) => {
            issues.push(ValidationIssue::new(
                "download_malformed",
                format!("`auth` must be `inherit` or `none` (got {other:?})"),
                format!("{p}.auth"),
            ));
            return None;
        }
    };
    Some(DownloadSpec {
        url,
        mime: pick("mime"),
        size: pick("size"),
        filename: pick("filename"),
        sha256: pick("sha256"),
        auth,
    })
}

/// Parse `x-overslash-upload` — the declaration that an action mints a
/// capability to push bytes at a route on the MCP origin, rather than calling a
/// tool at all.
///
/// `path` and `result.media_path` are mandatory, for the same reason
/// `parse_download` insists on `url`: an upload with nowhere to put the bytes,
/// or one that cannot hand back the reference the send tools take, is not a
/// weaker upload but nothing at all. Everything else is optional metadata,
/// dropped individually when blank so one typo doesn't take the block down.
fn parse_upload(
    v: Option<&Value>,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<UploadSpec> {
    let v = v?;
    let p = format!("{base}.x-overslash-upload");
    let Some(obj) = v.as_object() else {
        issues.push(ValidationIssue::new(
            "upload_malformed",
            "x-overslash-upload must be an object with `path` and optional \
             {method, filename_param, auth, max_bytes, result}",
            p,
        ));
        return None;
    };
    let path = match obj.get("path").and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            issues.push(ValidationIssue::new(
                "upload_malformed",
                "`path` must be a non-empty path or same-origin URL",
                format!("{p}.path"),
            ));
            return None;
        }
    };
    let method = match obj.get("method").and_then(Value::as_str) {
        None => UploadMethod::default(),
        Some(m) if m.eq_ignore_ascii_case("post") => UploadMethod::Post,
        Some(m) if m.eq_ignore_ascii_case("put") => UploadMethod::Put,
        Some(other) => {
            issues.push(ValidationIssue::new(
                "upload_malformed",
                format!("`method` must be `POST` or `PUT` (got {other:?})"),
                format!("{p}.method"),
            ));
            return None;
        }
    };
    let auth = match obj.get("auth").and_then(Value::as_str) {
        None | Some("inherit") => DownloadAuth::Inherit,
        Some("none") => DownloadAuth::None,
        Some(other) => {
            issues.push(ValidationIssue::new(
                "upload_malformed",
                format!("`auth` must be `inherit` or `none` (got {other:?})"),
                format!("{p}.auth"),
            ));
            return None;
        }
    };
    // A non-positive or non-integer ceiling is refused rather than clamped: it
    // reads as a deliberate limit, and silently substituting the deployment
    // default would be the opposite of what the author wrote.
    let max_bytes = match obj.get("max_bytes") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64().filter(|n| *n > 0) {
            Some(n) => Some(n),
            None => {
                issues.push(ValidationIssue::new(
                    "upload_malformed",
                    "`max_bytes` must be a positive integer",
                    format!("{p}.max_bytes"),
                ));
                return None;
            }
        },
    };
    let result = match obj.get("result") {
        None | Some(Value::Null) => None,
        Some(r) => {
            let Some(robj) = r.as_object() else {
                issues.push(ValidationIssue::new(
                    "upload_malformed",
                    "`result` must be an object of jq expressions",
                    format!("{p}.result"),
                ));
                return None;
            };
            let rpick = |key: &str| {
                robj.get(key)
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string)
            };
            let Some(media_path) = rpick("media_path") else {
                issues.push(ValidationIssue::new(
                    "upload_malformed",
                    "`result.media_path` must be a non-empty jq expression string",
                    format!("{p}.result.media_path"),
                ));
                return None;
            };
            Some(UploadResultSpec {
                media_path,
                sha256: rpick("sha256"),
                mime: rpick("mime"),
                size: rpick("size"),
                filename: rpick("filename"),
            })
        }
    };
    let filename_param = obj
        .get("filename_param")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string);
    Some(UploadSpec {
        path,
        method,
        filename_param,
        auth,
        max_bytes,
        result,
    })
}

/// Read an `x-overslash-timeout_ms` (or `x-overslash-default_timeout_ms`) off an
/// operation, MCP tool, or `info` object.
///
/// Strict: a value that is present but not a positive integer is an authoring
/// error, not a "fall back to the default" — a template that says `timeout_ms:
/// "30s"` means to raise the ceiling, and silently ignoring it would leave the
/// author staring at timeouts they thought they had fixed.
///
/// `key` is the canonical extension name so the same parser serves the
/// per-action and per-service spellings, and the issue pointer names the field
/// the author actually wrote.
pub(in crate::openapi) fn parse_timeout_ms(
    v: Option<&Value>,
    key: &str,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<u64> {
    let v = v?;
    match v.as_u64() {
        Some(ms) if ms > 0 => Some(ms),
        _ => {
            issues.push(ValidationIssue::new(
                "invalid_timeout",
                format!("{key} must be a positive integer number of milliseconds"),
                format!("{base}.{key}"),
            ));
            None
        }
    }
}

/// `x-overslash-wait-mode` → [`ExecutionMode`].
///
/// Shaped like [`parse_timeout_ms`] deliberately: an unrecognized value is a
/// [`ValidationIssue`] and `None`, never a hard error. A template whose mode is
/// misspelled falls back to synchronous — the historical behaviour — rather
/// than removing the action, which is the same lenient direction D67 chose for
/// the extension lint and for the same reason: a stray key must not be able to
/// take a service down.
pub(in crate::openapi) fn parse_wait_mode(
    v: Option<&Value>,
    key: &str,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<ExecutionMode> {
    let v = v?;
    match v.as_str().and_then(|s| ExecutionMode::from_str(s).ok()) {
        Some(mode) => Some(mode),
        None => {
            issues.push(ValidationIssue::new(
                "invalid_wait_mode",
                format!("{key} must be one of \"sync\", \"async\", \"hybrid\""),
                format!("{base}.{key}"),
            ));
            None
        }
    }
}

/// `x-overslash-pagination` → [`PaginationSpec`].
///
/// Lenient in the same direction as [`parse_wait_mode`] and for the same
/// reason: a malformed declaration yields issues and `None`, leaving the action
/// exactly as unpaged as it was before anyone wrote the key. The alternative —
/// removing the action — turns a typo in an optional hint into a missing
/// capability, which is the failure D67 built the extension lint to avoid.
///
/// Structural shape only. Whether the named parameters actually exist on the
/// action is a cross-field question, and it lives with the rest of those in
/// `template_validation::core::action`.
pub(in crate::openapi) fn parse_pagination(
    v: Option<&Value>,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<PaginationSpec> {
    let v = v?;
    let key = Ext::Pagination.key();
    let path = format!("{base}.{key}");
    let Some(obj) = v.as_object() else {
        issues.push(ValidationIssue::new(
            "pagination_invalid",
            format!("{key} must be an object"),
            path,
        ));
        return None;
    };

    let next = parse_next_spec(obj.get("next"), key, &path, issues)?;
    let page_size = parse_page_size(obj.get("page_size"), key, &path, issues);
    let items = parse_pagination_path(obj.get("items"), "items", key, &path, issues);
    let has_more = parse_pagination_path(obj.get("has_more"), "has_more", key, &path, issues);

    Some(PaginationSpec {
        page_size,
        next,
        items,
        has_more,
    })
}

fn parse_next_spec(
    v: Option<&Value>,
    key: &str,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<NextSpec> {
    let Some(v) = v else {
        issues.push(ValidationIssue::new(
            "pagination_invalid",
            format!("{key} must declare `next` — a page size with no way to reach page two is a limit, not pagination"),
            base.to_string(),
        ));
        return None;
    };
    let Some(obj) = v.as_object() else {
        issues.push(ValidationIssue::new(
            "pagination_invalid",
            format!("{key}.next must be an object"),
            format!("{base}.next"),
        ));
        return None;
    };

    let style = match obj.get("style").and_then(Value::as_str) {
        Some(s) => match NextStyle::from_str(s) {
            Ok(style) => style,
            Err(()) => {
                issues.push(ValidationIssue::new(
                    "pagination_invalid_style",
                    format!(
                        "{key}.next.style must be one of \"cursor\", \"offset\", \"page\", \"link\""
                    ),
                    format!("{base}.next.style"),
                ));
                return None;
            }
        },
        None => {
            issues.push(ValidationIssue::new(
                "pagination_invalid_style",
                format!("{key}.next.style is required"),
                format!("{base}.next.style"),
            ));
            return None;
        }
    };

    let param = parse_pagination_path(obj.get("param"), "next.param", key, base, issues);
    let from = parse_pagination_path(obj.get("from"), "next.from", key, base, issues);

    // Per-style shape. Each arm is one sentence about what the style needs to
    // be able to name the next page at all, and a spec that cannot is dropped
    // rather than half-honoured.
    match style {
        NextStyle::Link => {
            if param.is_some() || from.is_some() {
                issues.push(ValidationIssue::new(
                    "pagination_invalid",
                    format!(
                        "{key}.next.style \"link\" takes neither `param` nor `from` — the Link header names the whole next URL"
                    ),
                    format!("{base}.next"),
                ));
                return None;
            }
        }
        NextStyle::Cursor => {
            if param.is_none() || from.is_none() {
                issues.push(ValidationIssue::new(
                    "pagination_invalid",
                    format!(
                        "{key}.next.style \"cursor\" needs both `from` (where the cursor is in the response) and `param` (where it goes on the next call)"
                    ),
                    format!("{base}.next"),
                ));
                return None;
            }
        }
        NextStyle::Offset | NextStyle::Page => {
            if param.is_none() {
                issues.push(ValidationIssue::new(
                    "pagination_invalid",
                    format!("{key}.next.style \"{}\" needs `param`", style.as_str()),
                    format!("{base}.next"),
                ));
                return None;
            }
            if from.is_some() {
                issues.push(ValidationIssue::new(
                    "pagination_invalid",
                    format!(
                        "{key}.next.style \"{}\" computes its value from the request, so `from` reads nothing",
                        style.as_str()
                    ),
                    format!("{base}.next.from"),
                ));
                return None;
            }
        }
    }

    Some(NextSpec { style, param, from })
}

fn parse_page_size(
    v: Option<&Value>,
    key: &str,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<PageSize> {
    let v = v?;
    let path = format!("{base}.page_size");
    let Some(obj) = v.as_object() else {
        issues.push(ValidationIssue::new(
            "pagination_invalid",
            format!("{key}.page_size must be an object"),
            path,
        ));
        return None;
    };
    let Some(param) = parse_pagination_path(obj.get("param"), "page_size.param", key, base, issues)
    else {
        issues.push(ValidationIssue::new(
            "pagination_invalid",
            format!("{key}.page_size.param is required"),
            format!("{path}.param"),
        ));
        return None;
    };

    let default = parse_page_size_number(obj.get("default"), "default", key, &path, issues);
    let max = parse_page_size_number(obj.get("max"), "max", key, &path, issues);
    if let (Some(d), Some(m)) = (default, max)
        && d > m
    {
        issues.push(ValidationIssue::new(
            "pagination_default_exceeds_max",
            format!("{key}.page_size.default ({d}) is above its own max ({m})"),
            format!("{path}.default"),
        ));
        return None;
    }

    Some(PageSize {
        param,
        default,
        max,
    })
}

fn parse_page_size_number(
    v: Option<&Value>,
    field: &str,
    key: &str,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<i64> {
    let v = v?;
    match v.as_i64() {
        Some(n) if n > 0 => Some(n),
        _ => {
            issues.push(ValidationIssue::new(
                "pagination_invalid",
                format!("{key}.page_size.{field} must be a positive integer"),
                format!("{base}.{field}"),
            ));
            None
        }
    }
}

/// A non-empty string field. Shared by the parameter names and the dotted
/// response paths because the failure is the same one: a key written but left
/// blank, which reads as authored and behaves as absent.
fn parse_pagination_path(
    v: Option<&Value>,
    field: &str,
    key: &str,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<String> {
    let v = v?;
    match v.as_str() {
        Some(s) if !s.trim().is_empty() => Some(s.to_string()),
        // An explicit `null` is how a template says "not this one" in YAML;
        // it is absence spelled out, not a mistake worth reporting.
        None if v.is_null() => None,
        _ => {
            issues.push(ValidationIssue::new(
                "pagination_invalid",
                format!("{key}.{field} must be a non-empty string"),
                format!("{base}.{field}"),
            ));
            None
        }
    }
}

fn parse_redact(v: Option<&Value>, base: &str, issues: &mut Vec<ValidationIssue>) -> Vec<String> {
    let Some(v) = v else { return Vec::new() };
    let Some(arr) = v.as_array() else {
        issues.push(ValidationIssue::new(
            "redact_invalid_path",
            "x-overslash-redact must be an array of dotted-path strings",
            format!("{base}.x-overslash-redact"),
        ));
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let p = format!("{base}.x-overslash-redact[{i}]");
        match item.as_str() {
            Some(s) if !s.trim().is_empty() && !s.split('.').any(str::is_empty) => {
                out.push(s.to_string());
            }
            _ => issues.push(ValidationIssue::new(
                "redact_invalid_path",
                "each entry must be a non-empty dotted path (e.g. `body.api_key`)",
                p,
            )),
        }
    }
    out
}

/// Read a parameter's `x-overslash-aliases` — a list of alternate caller-facing
/// names — off its object (a `parameters[]` entry, a schema property, or a
/// platform-action param spec). Non-string entries and blanks are dropped, and
/// an alias equal to the canonical `name` is skipped (it would be a no-op
/// rewrite). Returns an empty `Vec` when the extension is absent or malformed —
/// aliases are a convenience, never a load-time error.
/// `x-overslash-instance-config` — whether an org may pin this param per
/// service instance. Read from the same four param shapes `parse_aliases`
/// covers (operation params, body properties, platform params, lowered input
/// schemas), so the vocabulary means the same thing wherever it is authored.
fn parse_instance_config(obj: Option<&Map<String, Value>>, pos: Pos) -> bool {
    obj.and_then(|o| ext::get(o, pos, Ext::InstanceConfig))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// `x-overslash-sql-field` + `x-overslash-sql-database` (D42/D43): presence
/// of `sql-field` marks this param as the raw-SQL query field, its value is
/// the dotted body path the value nests under; `sql-database` is the jq
/// expression that resolves which database the query targets. Read from the
/// same four param shapes `parse_aliases` covers; cross-param rules (one sql
/// param per action, string type, path shape, inert sql-database) are
/// checked by template validation, not here.
fn parse_sql_policy(
    obj: Option<&Map<String, Value>>,
    pos: Pos,
) -> (Option<String>, Option<String>) {
    let sql_field = obj
        .and_then(|o| ext::get(o, pos, Ext::SqlField))
        .and_then(Value::as_str)
        .map(str::to_string);
    let sql_database = obj
        .and_then(|o| ext::get(o, pos, Ext::SqlDatabase))
        .and_then(Value::as_str)
        .map(str::to_string);
    (sql_field, sql_database)
}

fn parse_aliases(obj: Option<&Map<String, Value>>, name: &str, pos: Pos) -> Vec<String> {
    obj.and_then(|o| ext::get(o, pos, Ext::Aliases))
        .and_then(Value::as_array)
        .map(|a| {
            // Dedup within one param's list (order-preserving): `[to, to]` is
            // a single alias, not an ambiguity.
            let mut seen = std::collections::HashSet::new();
            a.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != name)
                .filter(|s| seen.insert(*s))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::compile_service;
    use serde_json::json;

    // ── parse_aliases ────────────────────────────────────────────────

    #[test]
    fn parse_aliases_dedups_within_one_param() {
        let obj = json!({ "x-overslash-aliases": ["to", "to", "dest", "to"] });
        let aliases = parse_aliases(obj.as_object(), "recipient", Pos::Parameter);
        assert_eq!(aliases, vec!["to".to_string(), "dest".to_string()]);
    }

    #[test]
    fn parse_aliases_drops_blanks_self_and_non_strings() {
        let obj = json!({
            "x-overslash-aliases": ["to", "", "  ", "recipient", 7, "dest"]
        });
        let aliases = parse_aliases(obj.as_object(), "recipient", Pos::Parameter);
        // Blank, whitespace-only, the canonical name itself, and non-strings
        // are dropped.
        assert_eq!(aliases, vec!["to".to_string(), "dest".to_string()]);
    }

    // ── url_to_host / extract_hosts ──────────────────────────────────

    #[test]
    fn url_to_host_strips_https() {
        assert_eq!(
            url_to_host("https://api.example.com/v1"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn url_to_host_strips_http() {
        assert_eq!(
            url_to_host("http://internal.svc/api"),
            Some("internal.svc".into())
        );
    }

    #[test]
    fn url_to_host_strips_port() {
        assert_eq!(
            url_to_host("https://api.example.com:8443/v1"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn url_to_host_accepts_scheme_relative() {
        assert_eq!(
            url_to_host("api.example.com/v1"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn url_to_host_empty_returns_none() {
        assert!(url_to_host("").is_none());
        assert!(url_to_host("   ").is_none());
        assert!(url_to_host("https://").is_none());
    }

    #[test]
    fn extract_hosts_missing_servers_returns_empty() {
        let (svc, _) = compile_service(&json!({
            "info": {"title": "T", "x-overslash-key": "t"}
        }))
        .unwrap();
        assert!(svc.hosts.is_empty());
    }

    #[test]
    fn extract_hosts_skips_entries_without_url() {
        let (svc, _) = compile_service(&json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "servers": [
                {"description": "no url field"},
                {"url": "https://real.example.com"},
                "not-an-object"
            ]
        }))
        .unwrap();
        assert_eq!(svc.hosts, vec!["real.example.com"]);
    }
}
