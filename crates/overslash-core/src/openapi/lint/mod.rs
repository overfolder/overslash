//! The unknown-extension lint: report every `x-overslash-*` key, and every
//! structural key, that the compiler will silently ignore.
//!
//! ## Why
//!
//! A template document is an untyped `serde_json::Value` from `parse_yaml` all
//! the way to `compile_service`, so a key nothing reads is not an error — it is
//! nothing at all. `services/metabase.yaml` carried `response_type: binary` on
//! an operation for months: a real concept, in a position that never reads it
//! (the compiler derives the response type from `responses`), so a large export
//! was buffered instead of streamed and the only evidence was the absent
//! behaviour. D55 records the same shape from another angle — a `resolve:` block
//! beside an already-unprefixed `risk:` did nothing, and the symptom was an
//! approval still quoting a raw ID.
//!
//! `registry::load_from_dir` log-and-skips a template that fails to *load*, and
//! `shipped_services_have_no_silent_skips` keeps such a skip from hiding. This
//! is the same idea one level down, for a template that loads fine and quietly
//! does less than it says.
//!
//! ## Position, not just spelling
//!
//! Neither motivating bug is a misspelling, so a name-only check would have
//! caught neither. Every rule here is asked *where* as well as *what*, against
//! [`ext::READS`] — the map of which extension each extractor actually reads,
//! which is deliberately not the map of which alias [`alias`](super::alias)
//! normalizes. Where the two disagree the template is wrong, and this is what
//! says so.
//!
//! ## Warnings, never errors
//!
//! Every finding is a warning on every path. An error at `load_from_dir` means
//! the template is *skipped*, and a missing service is strictly worse than one
//! ignored field; an error on the update path would make an already-active
//! stored template un-saveable by its owner. The enforcement that matters lives
//! in `shipped_services_lint_clean`, where a regression is caught before it can
//! ship. See D67.
//!
//! Must run **after** [`normalize_aliases`](super::normalize_aliases): before
//! it, every legitimately unprefixed `risk:` looks like a finding. It may run
//! before `template_vars::expand`, which rewrites values and never keys.

use serde_json::Value;

use crate::template_validation::ValidationIssue;

use super::ext::Pos;

mod rules;
mod vocab;
mod walk;

use walk::{Node, walk};

/// Issue codes this module emits. `shipped_services_lint_clean` filters on this
/// set rather than on "no warnings at all", so the gate cannot be broken by an
/// unrelated warning appearing elsewhere in the validator.
pub const LINT_CODES: &[&str] = &[
    "unknown_extension",
    "misplaced_extension",
    "unprefixed_alias_ignored",
    "unknown_template_key",
];

/// Keys whose values are author-supplied *data*, not template structure. An
/// `x-overslash-*` key inside a documented example payload is content, and a
/// schema's `enum`/`default` may hold anything at all.
const STOP: &[&str] = &["example", "examples", "default", "enum", "const"];

/// D35 replaced these with [`Ext::Template`], and `extract_api_key` still
/// rejects them by name with a message quoting the jq replacement. That error is
/// strictly better than anything this module could say, so the lint steps aside
/// rather than stacking a vaguer warning on top of it.
const LEGACY_SUPPRESSED: &[&str] = &["x-overslash-prefix", "x-overslash-encode"];

/// Report every extension key the compiler will ignore, in document order.
///
/// Warnings only — see the module docs. The document must already be
/// alias-normalized.
pub fn lint_extensions(doc: &Value) -> Vec<ValidationIssue> {
    let mut out = Vec::new();
    walk(doc, Node::At(Pos::Root), "", &mut out);
    out
}

/// Join a dot-path segment, tolerating the empty root path.
fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Run the lint the way production does: normalize first, then lint.
    fn lint(mut v: Value) -> Vec<ValidationIssue> {
        let alias_issues = super::super::normalize_aliases(&mut v);
        assert!(
            alias_issues.is_empty(),
            "fixture has an alias ambiguity, which is a different (error-level) \
             finding: {alias_issues:?}"
        );
        lint_extensions(&v)
    }

    fn codes(issues: &[ValidationIssue]) -> Vec<&str> {
        issues.iter().map(|i| i.code.as_str()).collect()
    }

    fn only(issues: &[ValidationIssue]) -> &ValidationIssue {
        assert_eq!(issues.len(), 1, "expected exactly one finding: {issues:?}");
        &issues[0]
    }

    /// A document that must stay silent, for tests that add one bad key to it.
    fn clean_doc() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Svc", "key": "svc"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {"/items": {"get": {
                "operationId": "list_items",
                "summary": "List items",
                "risk": "read",
            }}},
        })
    }

    #[test]
    fn clean_document_is_silent() {
        assert!(lint(clean_doc()).is_empty());
    }

    // ── the motivating cases ─────────────────────────────────────────

    /// The bug that opened #539. `response_type` is a `ServiceAction` field the
    /// compiler *derives* from `responses`, never a key it reads off an
    /// operation, so this shipped as a no-op for months.
    #[test]
    fn response_type_on_an_operation_is_flagged() {
        let issues = lint(json!({
            "paths": {"/export": {"get": {
                "operationId": "export_query",
                "risk": "read",
                "response_type": "binary",
            }}},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "unknown_template_key");
        assert_eq!(i.path, "paths./export.get.response_type");
        assert!(
            i.message.contains("not read on an operation"),
            "message: {}",
            i.message
        );
    }

    /// D55's case, one level up: `normalize_aliases` never applies the operation
    /// table to a path item, so `risk:` hoisted out of the method is inert.
    #[test]
    fn risk_on_a_path_item_is_flagged() {
        let issues = lint(json!({
            "paths": {"/items": {
                "risk": "read",
                "get": {"operationId": "list", "risk": "read"},
            }},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "misplaced_extension");
        assert_eq!(i.path, "paths./items.risk");
        assert!(i.message.contains("an operation"), "message: {}", i.message);
    }

    // ── rule A: unknown name ─────────────────────────────────────────

    #[test]
    fn typo_in_an_extension_suggests_the_real_name() {
        let issues = lint(json!({
            "paths": {"/x": {"get": {"operationId": "x", "x-overslash-rsik": "read"}}},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "unknown_extension");
        assert!(
            i.message.contains("did you mean `x-overslash-risk`?"),
            "message: {}",
            i.message
        );
    }

    /// Names that only ever existed in a design doc. An author copying from
    /// `docs/design/` gets told, rather than getting silence.
    #[test]
    fn design_doc_only_names_are_unknown() {
        for ghost in [
            "x-overslash-transform",
            "x-overslash-execution",
            "x-overslash-fixed-params",
            "x-overslash-body-path",
            "x-overslash-sql",
            "x-overslash-default-scopes",
        ] {
            let issues = lint(json!({
                "paths": {"/x": {"get": {"operationId": "x", ghost: true}}},
            }));
            assert_eq!(
                codes(&issues),
                vec!["unknown_extension"],
                "{ghost} should be unknown, got {issues:?}"
            );
        }
    }

    /// The request-header names share the prefix but are not document keys.
    #[test]
    fn request_header_names_are_unknown_in_a_document() {
        let issues = lint(json!({
            "paths": {"/x": {"get": {"operationId": "x", "x-overslash-as": "u@example.com"}}},
        }));
        assert_eq!(codes(&issues), vec!["unknown_extension"]);
    }

    // ── rule B: known name, wrong position ───────────────────────────

    /// An HTTP action that returns bytes already is its own download, so
    /// `x-overslash-download` is MCP-only — and silently inert on an operation.
    #[test]
    fn download_on_an_http_operation_is_misplaced() {
        let issues = lint(json!({
            "paths": {"/f": {"get": {
                "operationId": "f",
                "x-overslash-download": {"url": ".url"},
            }}},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "misplaced_extension");
        assert!(
            i.message.contains("an MCP tool"),
            "should name where it IS read: {}",
            i.message
        );
        // An authored tool and a pasted snapshot share a description, so the
        // list must dedupe — "an MCP tool and an MCP tool" reads like a bug.
        assert!(
            !i.message.contains("an MCP tool and an MCP tool"),
            "duplicate position description: {}",
            i.message
        );
    }

    /// The normalizer used to rewrite these onto an `http` scheme that reads
    /// none of them. Now the tables are split and the lint says so.
    #[test]
    fn apikey_only_keys_on_an_http_scheme_are_misplaced() {
        let issues = lint(json!({
            "components": {"securitySchemes": {"bearer": {
                "type": "http",
                "scheme": "bearer",
                "x-overslash-template": {"lang": "jq", "expr": ".t"},
                "x-overslash-secret_source": "org",
                "x-overslash-optional": true,
            }}},
        }));
        assert_eq!(
            codes(&issues),
            vec![
                "misplaced_extension",
                "misplaced_extension",
                "misplaced_extension"
            ],
            "{issues:?}"
        );
        assert!(issues.iter().all(|i| i.message.contains("`apiKey`")));
    }

    /// `extract_platform_action` reads neither, though the operation alias table
    /// normalizes them here — the asymmetry documented at `actions.rs:216`.
    #[test]
    fn disclose_and_redact_on_a_platform_action_are_misplaced() {
        let issues = lint(json!({
            "x-overslash-runtime": "platform",
            "x-overslash-platform_actions": {"act": {
                "description": "x",
                "risk": "read",
                "disclose": [{"label": "L", "filter": ".x"}],
            }},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "misplaced_extension");
        assert_eq!(
            i.path,
            "x-overslash-platform_actions.act.x-overslash-disclose"
        );
    }

    /// `parse_platform_params` reads the other four param extensions but no
    /// resolver.
    #[test]
    fn resolve_on_a_platform_action_param_is_misplaced() {
        let issues = lint(json!({
            "x-overslash-platform_actions": {"act": {
                "description": "x",
                "params": {"id": {
                    "type": "string",
                    "x-overslash-resolve": {"get": "/x/{id}", "pick": "name"},
                    "x-overslash-aliases": ["ident"],
                }},
            }},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "misplaced_extension");
        assert!(i.path.ends_with("params.id.x-overslash-resolve"));
    }

    #[test]
    fn extension_buried_in_components_schemas_is_misplaced() {
        let issues = lint(json!({
            "components": {"schemas": {"Item": {
                "type": "object",
                "x-overslash-risk": "read",
            }}},
        }));
        assert_eq!(codes(&issues), vec!["misplaced_extension"]);
    }

    // ── rule C: unprefixed at a position that does not rewrite it ────

    /// The HTTP twin of D55's `input_schema` walk: the alias pass now descends
    /// into a request body's schema properties, so the bare spelling works and
    /// the lint must stay silent about it.
    #[test]
    fn bare_resolve_on_a_body_property_now_normalizes() {
        let issues = lint(json!({
            "paths": {"/send": {"post": {
                "operationId": "send",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"to": {
                        "type": "string",
                        "resolve": {"get": "/u/{to}", "pick": "name"},
                        "aliases": ["recipient"],
                    }},
                }}}},
            }}},
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// One level deeper is not a parameter, and nothing reads it there.
    #[test]
    fn extension_in_a_nested_body_property_is_misplaced() {
        let issues = lint(json!({
            "paths": {"/send": {"post": {
                "operationId": "send",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"outer": {
                        "type": "object",
                        "properties": {"inner": {
                            "type": "string",
                            "x-overslash-resolve": {"get": "/u/{inner}", "pick": "name"},
                        }},
                    }},
                }}}},
            }}},
        }));
        assert_eq!(codes(&issues), vec!["misplaced_extension"], "{issues:?}");
    }

    /// `components` has no alias table at all, so both declaration blocks are
    /// canonical-only.
    #[test]
    fn bare_secrets_and_config_under_components_are_flagged() {
        let issues = lint(json!({
            "components": {
                "secrets": {"user": {"label": "User"}},
                "config": {"host": {"label": "Host"}},
            },
        }));
        assert_eq!(
            codes(&issues),
            vec!["unprefixed_alias_ignored", "unprefixed_alias_ignored"],
            "{issues:?}"
        );
    }

    /// `x-overslash-token_injection` has no alias entry anywhere.
    #[test]
    fn bare_token_injection_on_an_oauth2_scheme_is_flagged() {
        let issues = lint(json!({
            "components": {"securitySchemes": {"o": {
                "type": "oauth2",
                "flows": {},
                "provider": "slack",
                "token_injection": {"inject_as": "header"},
            }}},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "unprefixed_alias_ignored");
        assert!(i.path.ends_with(".token_injection"), "path: {}", i.path);
    }

    /// Rule C must win over rule D: `components` is closed-world, and "write it
    /// prefixed" is a far more useful message than "unknown key".
    #[test]
    fn rule_c_beats_rule_d_at_a_closed_position() {
        let issues = lint(json!({"components": {"secrets": {}}}));
        assert_eq!(codes(&issues), vec!["unprefixed_alias_ignored"]);
    }

    /// The one case D55 fixed: the alias walk *does* descend here, so the bare
    /// spelling works and must stay silent.
    #[test]
    fn bare_resolve_inside_mcp_input_schema_stays_silent() {
        let issues = lint(json!({
            "x-overslash-runtime": "mcp",
            "x-overslash-mcp": {"url": "https://mcp.example.com", "tools": [{
                "name": "send",
                "risk": "write",
                "input_schema": {"type": "object", "properties": {"recipient": {
                    "type": "string",
                    "resolve": {"tool": "resolve_jid", "pick": "name"},
                    "aliases": ["to"],
                }}},
            }]},
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    // ── rule D: unknown bare key at a closed position ────────────────

    #[test]
    fn foreign_vendor_extensions_are_left_alone() {
        let issues = lint(json!({
            "x-amazon-apigateway-any-method": {},
            "info": {"title": "S", "key": "s", "x-ms-summary": "hi"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "x-codegen-request-body-name": "body",
                "x-google-backend": {"address": "https://b"},
            }}},
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn unknown_bare_key_on_an_operation_suggests_a_neighbour() {
        let issues = lint(json!({
            "paths": {"/x": {"get": {"operationId": "x", "operationid": "dup"}}},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "unknown_template_key");
        assert!(
            i.message.contains("did you mean `operationId`?"),
            "message: {}",
            i.message
        );
    }

    /// `lower_mcp_tool` reads `input_schema`; a faithfully pasted wire snapshot
    /// carries `inputSchema` and compiles to a tool with no parameters at all.
    #[test]
    fn camel_case_mcp_wire_fields_are_flagged() {
        let issues = lint(json!({
            "x-overslash-mcp": {"tools": [{
                "name": "t",
                "risk": "read",
                "inputSchema": {"type": "object"},
            }]},
        }));
        let i = only(&issues);
        assert_eq!(i.code, "unknown_template_key");
        assert!(i.message.contains("write `input_schema`"), "{}", i.message);
    }

    /// A pasted `discovered_tools` snapshot mirrors the MCP wire shape, so plain
    /// keys stay open-world there — but a stray extension still reports.
    #[test]
    fn discovered_tool_snapshots_keep_their_wire_fields() {
        let issues = lint(json!({
            "x-overslash-mcp": {"discovered_tools": [{
                "name": "t",
                "title": "T",
                "annotations": {"readOnlyHint": true},
                "_meta": {"v": 1},
                "risk": "read",
            }]},
        }));
        assert!(issues.is_empty(), "{issues:?}");

        let issues = lint(json!({
            "x-overslash-mcp": {"discovered_tools": [{
                "name": "t",
                "x-overslash-rsik": "read",
            }]},
        }));
        assert_eq!(codes(&issues), vec!["unknown_extension"]);
    }

    // ── the open-world guard rails ───────────────────────────────────

    /// The false positive this design must not have: a payload field genuinely
    /// named after one of our concepts. These are data, not template structure.
    #[test]
    fn data_fields_sharing_a_concept_name_are_not_flagged() {
        let issues = lint(json!({
            "components": {"schemas": {"Charge": {
                "type": "object",
                "properties": {
                    "risk": {"type": "string"},
                    "template": {"type": "string"},
                    "download": {"type": "string"},
                    "response_type": {"type": "string"},
                },
            }}},
            "paths": {"/c": {"post": {
                "operationId": "c",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"label": {"type": "string"}, "optional": {"type": "boolean"}},
                }}}},
            }}},
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// Caught by `shipped_services_lint_clean` on its first run: `provider` is a
    /// read field of the MCP auth block *and* the alias of an `oauth2` scheme's
    /// `x-overslash-provider`. A position's own fields must win.
    #[test]
    fn a_plain_field_sharing_an_extension_name_is_not_flagged() {
        let issues = lint(json!({
            "x-overslash-runtime": "mcp",
            "x-overslash-mcp": {
                "url": "https://mcp.example.com",
                "auth": {"kind": "oauth", "provider": "slack", "scopes": ["chat:write"]},
                "autodiscover": false,
                "tools": [{"name": "t", "risk": "read", "input_schema": {"type": "object"}}],
            },
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// A property may legitimately be *named* after a schema keyword, and
    /// `collect_body_parameters` reads its extensions like any other's. `STOP`
    /// stops the walk descending into author-supplied *data*, so it must not also
    /// stop it descending into a map whose keys are author-chosen names — that
    /// would blind the lint at a position the compiler does read.
    #[test]
    fn a_property_named_after_a_schema_keyword_is_still_walked() {
        let issues = lint(json!({
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {
                        "default": {"type": "string", "x-overslash-rsik": "read"},
                        "enum": {"type": "string", "x-overslash-download": {"url": ".u"}},
                        // Valid at this position: must stay silent.
                        "example": {
                            "type": "string",
                            "x-overslash-resolve": {"get": "/u/{example}", "pick": "name"},
                        },
                    },
                }}}},
            }}},
        }));
        let by_path = |p: &str| issues.iter().find(|i| i.path == p);
        assert_eq!(
            by_path("paths./x.post.requestBody.content.application/json.schema.properties.default.x-overslash-rsik")
                .map(|i| i.code.as_str()),
            Some("unknown_extension"),
            "{issues:?}"
        );
        assert_eq!(
            by_path("paths./x.post.requestBody.content.application/json.schema.properties.enum.x-overslash-download")
                .map(|i| i.code.as_str()),
            Some("misplaced_extension"),
            "{issues:?}"
        );
        assert_eq!(
            issues.len(),
            2,
            "the valid resolver must stay silent: {issues:?}"
        );
    }

    /// The other half of the same rule: `STOP` still applies where the keys *are*
    /// schema keywords, so a documented example payload is never walked.
    #[test]
    fn example_payloads_are_not_walked() {
        let issues = lint(json!({
            "paths": {"/x": {"get": {
                "operationId": "x",
                "responses": {"200": {"content": {"application/json": {
                    "example": {"x-overslash-risk": "nonsense", "response_type": "binary"},
                    "examples": {"a": {"value": {"x-overslash-transform": 1}}},
                }}}},
            }}},
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn extension_internal_shapes_are_not_walked() {
        // `{lang, expr}` and the slot declarations are extension-internal, and
        // the extractors already check their contents precisely.
        let issues = lint(json!({
            "components": {
                "x-overslash-secrets": {"user": {"label": "U", "source": "instance"}},
                "securitySchemes": {"t": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "x-overslash-template": {"lang": "jq", "expr": "\"Bearer \" + .user"},
                }},
            },
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// The legacy pair keeps its own, better error from `extract_api_key`.
    #[test]
    fn legacy_prefix_and_encode_are_not_double_reported() {
        let issues = lint(json!({
            "components": {"securitySchemes": {"t": {
                "type": "apiKey", "in": "header", "name": "Authorization",
                "x-overslash-prefix": "Bearer ",
                "x-overslash-encode": true,
            }}},
        }));
        assert!(
            issues.is_empty(),
            "compile's openapi_unsupported_construct owns these: {issues:?}"
        );
    }

    /// An unrecognized scheme `type` already fails to compile; piling warnings on
    /// top of that error would only bury it.
    #[test]
    fn unsupported_scheme_type_stays_open_world() {
        let issues = lint(json!({
            "components": {"securitySchemes": {"oidc": {
                "type": "openIdConnect",
                "openIdConnectUrl": "https://idp.example.com/.well-known",
                "provider": "should-not-rewrite",
            }}},
        }));
        assert!(issues.is_empty(), "{issues:?}");
    }

    // ── shape ────────────────────────────────────────────────────────

    #[test]
    fn every_emitted_code_is_declared() {
        // `shipped_services_lint_clean` filters on LINT_CODES, so a code missing
        // from it would be a finding the CI gate cannot see.
        let issues = lint(json!({
            "paths": {"/x": {
                "risk": "read",
                "get": {
                    "operationId": "x",
                    "x-overslash-nope": 1,
                    "x-overslash-download": {"url": ".u"},
                    "response_type": "binary",
                },
            }},
            "components": {"secrets": {}},
        }));
        assert!(!issues.is_empty());
        for i in &issues {
            assert!(
                LINT_CODES.contains(&i.code.as_str()),
                "{} is not in LINT_CODES",
                i.code
            );
        }
    }

    #[test]
    fn findings_are_stable_and_idempotent() {
        let doc = json!({
            "paths": {"/x": {"get": {"operationId": "x", "response_type": "binary"}}},
        });
        let first = lint(doc.clone());
        let second = lint(doc);
        assert_eq!(codes(&first), codes(&second));
        assert_eq!(first[0].path, second[0].path);
    }

    #[test]
    fn non_object_documents_are_tolerated() {
        assert!(lint_extensions(&json!([])).is_empty());
        assert!(lint_extensions(&json!("nope")).is_empty());
        assert!(lint_extensions(&json!(null)).is_empty());
        // A malformed path item must not stop the walk reaching its sibling.
        let issues = lint(json!({
            "paths": {"/broken": null, "/ok": {"get": {"operationId": "ok", "response_type": "x"}}},
        }));
        assert_eq!(codes(&issues), vec!["unknown_template_key"]);
    }

    /// The invariant behind `ext.rs`: every extension read goes through the
    /// accessor, so the position table cannot drift from the reader set.
    #[test]
    fn no_extension_getter_bypasses_the_accessor() {
        const READERS: &[(&str, &str)] = &[
            ("compile/mod.rs", include_str!("../compile/mod.rs")),
            ("extract/mod.rs", include_str!("../extract/mod.rs")),
            ("extract/actions.rs", include_str!("../extract/actions.rs")),
            ("extract/auth.rs", include_str!("../extract/auth.rs")),
            ("extract/mcp.rs", include_str!("../extract/mcp.rs")),
            ("extract/params.rs", include_str!("../extract/params.rs")),
            ("extract/schemes.rs", include_str!("../extract/schemes.rs")),
        ];
        // `.get("x-overslash-…")` is the one spelling that bypasses `ext::get`
        // and so escapes the READS matrix. Compound dot-paths and message text
        // are left alone deliberately — they are not reads, and routing them
        // through `Ext::key()` would only make the messages harder to read.
        //
        // Only production code is scanned: a test may legitimately assert on a
        // raw key to prove what normalization produced. `clippy::items_after_
        // test_module` keeps every test module at the end of its file, so
        // truncating at the first `#[cfg(test)]` is exact rather than a
        // heuristic.
        for (name, src) in READERS {
            let production = src.split("#[cfg(test)]").next().unwrap_or(src);
            for (n, line) in production.lines().enumerate() {
                assert!(
                    !line.contains(".get(\"x-overslash-"),
                    "{name}:{} reads an extension directly; use ext::get so the \
                     READS matrix stays authoritative:\n{line}",
                    n + 1,
                );
            }
        }
    }
}
