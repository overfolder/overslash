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

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::{DisclosureField, DownloadAuth, DownloadSpec, ScopeParams};

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
        auth,
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
fn parse_instance_config(obj: Option<&Map<String, Value>>) -> bool {
    obj.and_then(|o| o.get("x-overslash-instance-config"))
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
fn parse_sql_policy(obj: Option<&Map<String, Value>>) -> (Option<String>, Option<String>) {
    let sql_field = obj
        .and_then(|o| o.get("x-overslash-sql-field"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let sql_database = obj
        .and_then(|o| o.get("x-overslash-sql-database"))
        .and_then(Value::as_str)
        .map(str::to_string);
    (sql_field, sql_database)
}

fn parse_aliases(obj: Option<&Map<String, Value>>, name: &str) -> Vec<String> {
    obj.and_then(|o| o.get("x-overslash-aliases"))
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
        let aliases = parse_aliases(obj.as_object(), "recipient");
        assert_eq!(aliases, vec!["to".to_string(), "dest".to_string()]);
    }

    #[test]
    fn parse_aliases_drops_blanks_self_and_non_strings() {
        let obj = json!({
            "x-overslash-aliases": ["to", "", "  ", "recipient", 7, "dest"]
        });
        let aliases = parse_aliases(obj.as_object(), "recipient");
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
