//! End-to-end tests for [`super::compile_service`]: public API, YAML ↔
//! compile round-trips. Split out of `mod.rs` to keep both halves
//! navigable — the file is overwhelmingly tests, and the gate that caps a
//! source file at a thousand lines does not distinguish.

use super::*;
use crate::openapi::normalize_aliases;
use crate::service_icon::ServiceIcon;
use crate::types::{ExecutionMode, McpAuth, Risk, Runtime, ServiceAuth};
use serde_json::json;

// --- icon ---------------------------------------------------------

fn compile_icon(info_extra: serde_json::Value, key: &str) -> (Option<ServiceIcon>, Vec<String>) {
    let mut info = json!({"title": "Test", "x-overslash-key": key});
    if let (Some(dst), Some(src)) = (info.as_object_mut(), info_extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    let mut v = json!({"openapi": "3.1.0", "info": info, "paths": {}});
    assert!(normalize_aliases(&mut v).is_empty());
    let (def, warnings) = compile_service(&v).unwrap();
    (def.icon, warnings.into_iter().map(|w| w.code).collect())
}

#[test]
fn icon_accepts_both_authored_forms() {
    let (icon, warnings) = compile_icon(json!({"icon": "builtin:github"}), "anything");
    assert_eq!(
        icon,
        Some(ServiceIcon::Builtin {
            slug: "github".into()
        })
    );
    assert!(warnings.is_empty());

    let (icon, _) = compile_icon(json!({"icon": "https://cdn.example.com/a.svg"}), "anything");
    assert_eq!(
        icon,
        Some(ServiceIcon::Remote {
            url: "https://cdn.example.com/a.svg".into()
        })
    );
}

#[test]
fn icon_is_implicit_when_the_key_matches_a_shipped_asset() {
    // The common case: the shipped templates declare no `icon:` at all.
    let (icon, warnings) = compile_icon(json!({}), "github");
    assert_eq!(
        icon,
        Some(ServiceIcon::Builtin {
            slug: "github".into()
        })
    );
    assert!(warnings.is_empty());
}

#[test]
fn icon_is_absent_when_nothing_matches() {
    let (icon, warnings) = compile_icon(json!({}), "no_such_service");
    assert_eq!(icon, None);
    assert!(warnings.is_empty());
}

#[test]
fn authored_icon_beats_the_implicit_one() {
    // Precedence runs the useful way round: a template keyed `github` that
    // deliberately names another icon keeps the one it named.
    let (icon, _) = compile_icon(
        json!({"icon": "https://cdn.example.com/fork.svg"}),
        "github",
    );
    assert_eq!(
        icon,
        Some(ServiceIcon::Remote {
            url: "https://cdn.example.com/fork.svg".into()
        })
    );
}

#[test]
fn malformed_icon_warns_and_still_compiles() {
    // A whole template must not fail to load over a typo'd logo — the
    // registry skips any file that fails to compile.
    let (icon, warnings) = compile_icon(json!({"icon": 42}), "no_such_service");
    assert_eq!(icon, None);
    assert_eq!(warnings, vec!["openapi_invalid"]);

    let (icon, warnings) = compile_icon(json!({"icon": "  "}), "no_such_service");
    assert_eq!(icon, None);
    assert_eq!(warnings, vec!["openapi_invalid"]);
}

#[test]
fn malformed_icon_falls_through_to_the_implicit_one() {
    let (icon, warnings) = compile_icon(json!({"icon": ""}), "github");
    assert_eq!(
        icon,
        Some(ServiceIcon::Builtin {
            slug: "github".into()
        })
    );
    assert_eq!(warnings, vec!["openapi_invalid"]);
}

#[test]
fn compile_non_object_root_errors() {
    let err = compile_service(&json!([])).unwrap_err();
    assert_eq!(err[0].code, "openapi_parse_error");
}

#[test]
fn compile_slack_fixture() {
    let mut v = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Slack",
            "x-overslash-key": "slack",
            "x-overslash-category": "chat"
        },
        "servers": [{"url": "https://slack.com"}, {"url": "https://api.slack.com"}],
        "components": {"securitySchemes": {
            "oauth": {
                "type": "oauth2",
                "x-overslash-provider": "slack",
                "flows": {"authorizationCode": {
                    "authorizationUrl": "https://slack.com/oauth/v2/authorize",
                    "tokenUrl": "https://slack.com/api/oauth.v2.access",
                    "scopes": {"chat:write": "", "channels:read": ""}
                }}
            },
            "token": {
                "type": "apiKey", "in": "header", "name": "Authorization",
                "x-overslash-template": {"lang": "jq", "expr": "\"Bearer \" + .token"},
                "x-overslash-default_secret_name": "slack_token"
            }
        }},
        "paths": {
            "/api/chat.postMessage": {"post": {
                "operationId": "send_message",
                "summary": "Send a message to Slack channel {channel}",
                "x-overslash-risk": "write",
                "x-overslash-scope_param": "channel",
                "requestBody": {"required": true, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["channel", "text"],
                    "properties": {
                        "channel": {"type": "string", "description": "Channel ID"},
                        "text": {"type": "string", "description": "Message text"}
                    }
                }}}}
            }},
            "/api/conversations.list": {"get": {
                "operationId": "list_channels", "summary": "List Slack channels"
            }}
        }
    });
    let ns_issues = normalize_aliases(&mut v);
    assert!(ns_issues.is_empty(), "{ns_issues:?}");
    let (svc, warnings) = compile_service(&v).expect("compile ok");
    assert!(warnings.is_empty());
    assert_eq!(svc.key, "slack");
    assert_eq!(svc.display_name, "Slack");
    assert_eq!(svc.category.as_deref(), Some("chat"));
    assert_eq!(svc.hosts, vec!["slack.com", "api.slack.com"]);
    assert_eq!(svc.auth.len(), 2);

    let mut has_oauth = false;
    let mut has_apikey = false;
    for a in &svc.auth {
        match a {
            ServiceAuth::OAuth {
                provider, scopes, ..
            } => {
                has_oauth = true;
                assert_eq!(provider, "slack");
                assert!(scopes.contains(&"chat:write".to_string()));
            }
            ServiceAuth::Secret {
                default_secret_name,
                ..
            } => {
                has_apikey = true;
                assert_eq!(default_secret_name, "slack_token");
            }
        }
    }
    assert!(has_oauth && has_apikey);

    let send = svc.actions.get("send_message").expect("send_message");
    assert_eq!(send.method, "POST");
    assert_eq!(send.risk, Risk::Write);
    assert_eq!(send.scope_param, "channel".into());
    assert!(send.params["channel"].required);
    assert!(!svc.hidden, "hidden defaults to false when absent");
}

/// A list-valued `scope_param`, with and without labels, lowers to one
/// entry per param — this is the syntax `services/email.yaml` ships.
#[test]
fn compile_list_scope_param() {
    let mut v = json!({
        "openapi": "3.1.0",
        "info": {"title": "Mail", "version": "1", "x-overslash-key": "mail"},
        "servers": [{"url": "https://mail.example.com"}],
        "paths": {"/send": {"post": {
            "operationId": "send",
            "summary": "Send",
            "scope_param": ["to:recipient", "cc:recipient", "bcc"],
            "requestBody": {"required": true, "content": {"application/json": {"schema": {
                "type": "object",
                "properties": {
                    "to": {"type": "array"},
                    "cc": {"type": "array"},
                    "bcc": {"type": "array"}
                }
            }}}}
        }}}
    });
    let issues = normalize_aliases(&mut v);
    assert!(issues.is_empty(), "{issues:?}");
    let (svc, _) = compile_service(&v).expect("compile ok");
    assert_eq!(
        svc.actions["send"]
            .scope_param
            .refs()
            .iter()
            .map(|r| (r.param.as_str(), r.label.as_str()))
            .collect::<Vec<_>>(),
        vec![("to", "recipient"), ("cc", "recipient"), ("bcc", "bcc")]
    );
}

/// A shape that is neither a string nor a list of strings is rejected.
/// Silently dropping it would widen the action's key to the wildcard —
/// the opposite of what an author writing `scope_param` wants.
#[test]
fn compile_rejects_a_malformed_scope_param() {
    for bad in [json!({"to": "recipient"}), json!(["to", 7]), json!("a:b:c")] {
        let mut v = json!({
            "openapi": "3.1.0",
            "info": {"title": "Mail", "version": "1", "x-overslash-key": "mail"},
            "servers": [{"url": "https://mail.example.com"}],
            "paths": {"/send": {"post": {
                "operationId": "send",
                "summary": "Send",
                "x-overslash-scope_param": bad,
            }}}
        });
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let err = compile_service(&v).expect_err("should not compile");
        assert!(
            err.iter().any(|i| i.code == "invalid_scope_param"),
            "{bad} → {err:?}"
        );
    }
}

#[test]
fn compile_hidden_flag() {
    let v = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Legacy",
            "x-overslash-key": "legacy",
            "x-overslash-hidden": true
        },
        "paths": {}
    });
    let (svc, warnings) = compile_service(&v).expect("compile ok");
    assert!(warnings.is_empty());
    assert!(svc.hidden);
}

#[test]
fn compile_hidden_non_bool_warns_and_stays_visible() {
    let v = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Legacy",
            "x-overslash-key": "legacy",
            "x-overslash-hidden": "true"
        },
        "paths": {}
    });
    let (svc, warnings) = compile_service(&v).expect("compile ok");
    assert!(!svc.hidden, "non-bool hidden must not hide the template");
    assert!(
        warnings
            .iter()
            .any(|w| w.path == "info.x-overslash-hidden" && w.code == "openapi_invalid"),
        "expected a warning for non-bool hidden, got {warnings:?}"
    );
}

// ── MCP runtime: aliases + compile + merge ──────────────────────────

#[test]
fn compile_mcp_runtime_with_aliases() {
    // Unprefixed `runtime:` and `mcp:` must normalize to the canonical
    // x-overslash-* forms. Tool-level `risk:` / `scope_param:` too.
    let mut v = json!({
        "openapi": "3.1.0",
        "info": {"title": "DeepWiki", "key": "deepwiki_mcp"},
        "runtime": "mcp",
        "paths": {},
        "mcp": {
            "url": "https://mcp.deepwiki.com/mcp",
            "auth": { "kind": "none" },
            "autodiscover": false,
            "tools": [
                {
                    "name": "ask_question",
                    "risk": "read",
                    "scope_param": "repo",
                    "description": "Ask a question about {repo}",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "repo": { "type": "string", "description": "Repo slug" },
                            "question": { "type": "string" }
                        },
                        "required": ["repo", "question"]
                    }
                }
            ]
        }
    });
    let ns = normalize_aliases(&mut v);
    assert!(ns.is_empty(), "{ns:?}");
    // aliases at root rewritten
    assert!(v.get("x-overslash-runtime").is_some());
    assert!(v.get("x-overslash-mcp").is_some());
    assert!(v.get("runtime").is_none());
    assert!(v.get("mcp").is_none());
    // tool-level aliases rewritten
    let tool = &v["x-overslash-mcp"]["tools"][0];
    assert_eq!(tool["x-overslash-risk"], "read");
    assert_eq!(tool["x-overslash-scope_param"], "repo");

    let (svc, warnings) = compile_service(&v).expect("compile ok");
    assert!(warnings.is_empty(), "warnings: {warnings:?}");
    assert_eq!(svc.runtime, Runtime::Mcp);
    let mcp = svc.mcp.expect("mcp present");
    assert_eq!(mcp.url.as_deref(), Some("https://mcp.deepwiki.com/mcp"));
    assert_eq!(mcp.auth, McpAuth::None);
    assert!(!mcp.autodiscover);

    let a = &svc.actions["ask_question"];
    assert_eq!(a.mcp_tool.as_deref(), Some("ask_question"));
    assert_eq!(a.risk, Risk::Read);
    assert_eq!(a.scope_param, "repo".into());
    assert!(a.params["repo"].required);
    assert!(a.params["question"].required);
    assert_eq!(a.params["repo"].description, "Repo slug");
}

#[test]
fn compile_mcp_merges_discovered_and_authored_tools() {
    // Discovered brings the schema; authored adds risk + scope_param + disabled.
    let mut v = json!({
        "openapi": "3.1.0",
        "info": {"title": "Linear", "x-overslash-key": "linear_mcp"},
        "x-overslash-runtime": "mcp",
        "paths": {},
        "x-overslash-mcp": {
            "url": "https://mcp.linear.app/mcp",
            "auth": { "kind": "bearer", "secret_name": "linear_api_token" },
            "discovered_tools": [
                {
                    "name": "search_issues",
                    "description": "Search Linear issues",
                    "input_schema": {
                        "type": "object",
                        "properties": {"team": {"type": "string"}},
                        "required": ["team"]
                    }
                },
                {
                    "name": "debug_internal",
                    "description": "Debug helper",
                    "input_schema": {"type": "object"}
                }
            ],
            "tools": [
                { "name": "search_issues", "risk": "read", "scope_param": "team" },
                { "name": "debug_internal", "disabled": true }
            ]
        }
    });
    assert!(normalize_aliases(&mut v).is_empty());
    let (svc, warnings) = compile_service(&v).expect("compile ok");
    assert!(warnings.is_empty(), "warnings: {warnings:?}");
    let search = &svc.actions["search_issues"];
    assert_eq!(search.risk, Risk::Read);
    assert_eq!(search.scope_param, "team".into());
    assert!(
        search.params["team"].required,
        "schema came from discovered"
    );

    let debug = &svc.actions["debug_internal"];
    assert!(debug.disabled, "YAML disabled=true wins");
}

#[test]
fn compile_mcp_yaml_only_tool_warns_when_autodiscover() {
    // autodiscover=true + a yaml-only tool not in discovered_tools → warning.
    let mut v = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t_mcp"},
        "x-overslash-runtime": "mcp",
        "paths": {},
        "x-overslash-mcp": {
            "url": "https://mcp.example.com/mcp",
            "auth": {"kind": "none"},
            "discovered_tools": [],
            "tools": [{
                "name": "pre_annotated",
                "risk": "read",
                "description": "x",
                "input_schema": {"type": "object"}
            }]
        }
    });
    assert!(normalize_aliases(&mut v).is_empty());
    let (svc, warnings) = compile_service(&v).expect("compile ok");
    assert!(svc.actions.contains_key("pre_annotated"));
    assert!(
        warnings.iter().any(|w| w.code == "mcp_tool_not_discovered"),
        "expected mcp_tool_not_discovered warning, got {warnings:?}"
    );
}

#[test]
fn compile_mcp_without_url_is_valid() {
    // url is optional — absent means the service instance must supply one.
    let v = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t_mcp"},
        "x-overslash-runtime": "mcp",
        "paths": {},
        "x-overslash-mcp": { "auth": {"kind": "none"} }
    });
    let (svc, _warnings) = compile_service(&v).expect("missing url is valid");
    assert!(svc.mcp.expect("mcp present").url.is_none());
}

#[test]
fn compile_mcp_rejects_unknown_auth_kind() {
    let v = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t_mcp"},
        "x-overslash-runtime": "mcp",
        "paths": {},
        "x-overslash-mcp": {
            "url": "https://mcp.example.com/mcp",
            "auth": { "kind": "oauth" }
        }
    });
    let err = compile_service(&v).unwrap_err();
    assert!(err.iter().any(|e| e.code == "mcp_invalid"), "{err:?}");
}

#[test]
fn compile_mcp_accepts_oauth_with_provider_and_scopes() {
    let v = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t_mcp"},
        "x-overslash-runtime": "mcp",
        "paths": {},
        "x-overslash-mcp": {
            "url": "https://mcp.example.com/mcp",
            "auth": { "kind": "oauth", "provider": "hubspot", "scopes": ["crm.objects.contacts.read"] }
        }
    });
    let (svc, _warnings) = compile_service(&v).expect("oauth mcp is valid");
    match svc.mcp.expect("mcp present").auth {
        crate::types::McpAuth::OAuth { provider, scopes } => {
            assert_eq!(provider, "hubspot");
            assert_eq!(scopes, vec!["crm.objects.contacts.read".to_string()]);
        }
        other => panic!("expected oauth auth, got {other:?}"),
    }
}

#[test]
fn compile_mcp_rejects_non_string_oauth_scope() {
    let v = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t_mcp"},
        "x-overslash-runtime": "mcp",
        "paths": {},
        "x-overslash-mcp": {
            "url": "https://mcp.example.com/mcp",
            "auth": { "kind": "oauth", "provider": "hubspot", "scopes": ["ok", 123] }
        }
    });
    let err = compile_service(&v).unwrap_err();
    assert!(
        err.iter()
            .any(|e| e.code == "mcp_invalid" && e.path.contains("scopes")),
        "non-string scope should be rejected, got: {err:?}"
    );
}

#[test]
fn compile_mcp_autodiscover_false_requires_input_schema() {
    let v = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t_mcp"},
        "x-overslash-runtime": "mcp",
        "paths": {},
        "x-overslash-mcp": {
            "url": "https://mcp.example.com/mcp",
            "auth": {"kind": "none"},
            "autodiscover": false,
            "tools": [ {"name": "t", "description": "x"} ]
        }
    });
    let err = compile_service(&v).unwrap_err();
    assert!(
        err.iter()
            .any(|e| e.code == "mcp_invalid" && e.path.contains("input_schema")),
        "{err:?}"
    );
}

#[test]
fn compile_platform_actions() {
    let doc = json!({
        "info": {"title": "Overslash", "x-overslash-key": "overslash", "x-overslash-category": "platform"},
        "x-overslash-platform_actions": {
            "manage_members": {"description": "Manage org members", "x-overslash-risk": "delete"}
        }
    });
    let (svc, _) = compile_service(&doc).unwrap();
    assert_eq!(svc.key, "overslash");
    assert!(svc.hosts.is_empty());
    let m = &svc.actions["manage_members"];
    assert!(m.method.is_empty());
    assert_eq!(m.risk, Risk::Delete);
}

/// The unprefixed authoring spellings must reach the compiled struct —
/// a template author writes `timeout_ms:`, never the canonical form, so
/// an alias that silently no-ops would leave them staring at timeouts
/// they believed they had already raised.
#[test]
fn compile_timeout_defaults_through_the_unprefixed_aliases() {
    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Slow", "key": "slow", "default_timeout_ms": 60000
        },
        "servers": [{"url": "https://slow.example"}],
        "paths": {
            "/fast": {"get": {"operationId": "fast", "description": "quick"}},
            "/slow": {"get": {
                "operationId": "slow", "description": "aggregation",
                "timeout_ms": 90000
            }}
        }
    });
    crate::openapi::normalize_aliases(&mut doc);
    let (svc, warnings) = compile_service(&doc).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(svc.default_timeout_ms, Some(60_000));
    assert_eq!(svc.actions["slow"].timeout_ms, Some(90_000));
    // Absent, not defaulted to the service value: the cascade is resolved
    // at call time, so the action rung must stay empty here or it would
    // shadow a per-call override.
    assert_eq!(svc.actions["fast"].timeout_ms, None);
}

/// The wait-mode rung has to survive the same unprefixed authoring
/// spelling `timeout_ms` does, and for a sharper reason: this one decides
/// a *response shape*, so an alias that silently no-ops leaves the author
/// believing an action defers when every call to it still rides the
/// synchronous ceiling into a 504.
#[test]
fn compile_wait_mode_through_the_unprefixed_aliases() {
    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {"title": "Slow", "key": "slow"},
        "servers": [{"url": "https://slow.example"}],
        "paths": {
            "/fast": {"get": {"operationId": "fast", "description": "quick"}},
            "/slow": {"get": {
                "operationId": "slow", "description": "aggregation",
                "wait-mode": "hybrid", "handoff_after_ms": 2000
            }},
            "/batch": {"post": {
                "operationId": "batch", "description": "long import",
                "x-overslash-wait-mode": "async"
            }}
        }
    });
    crate::openapi::normalize_aliases(&mut doc);
    let (svc, warnings) = compile_service(&doc).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(svc.actions["slow"].wait_mode, Some(ExecutionMode::Hybrid));
    assert_eq!(svc.actions["slow"].handoff_after_ms, Some(2_000));
    assert_eq!(svc.actions["batch"].wait_mode, Some(ExecutionMode::Async));
    // Absent, never defaulted to `Sync` here: the API distinguishes "this
    // template has no opinion" from "this template says sync", and only
    // the former lets a future rung land underneath it.
    assert_eq!(svc.actions["fast"].wait_mode, None);
    assert_eq!(svc.actions["fast"].handoff_after_ms, None);
}

// --- pagination ---------------------------------------------------

fn paged_doc(pagination: serde_json::Value) -> serde_json::Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Mail", "key": "mail"},
        "servers": [{"url": "https://mail.example"}],
        "paths": {"/messages": {"get": {
            "operationId": "list_messages",
            "description": "list messages",
            "pagination": pagination,
            "parameters": [
                {"name": "maxResults", "in": "query", "schema": {"type": "integer"}},
                {"name": "pageToken", "in": "query", "schema": {"type": "string"}}
            ]
        }}}
    })
}

fn compile_paged(pagination: serde_json::Value) -> ServiceDefinition {
    let mut doc = paged_doc(pagination);
    assert!(normalize_aliases(&mut doc).is_empty());
    compile_service(&doc).unwrap().0
}

/// The whole point of the page-size half: the parameter had no `default:`,
/// so an omitted `maxResults` bounded nothing. Seeding it makes
/// `apply_defaults` — the mechanism that already existed — do the work,
/// which is also what puts the number on `/v1/search` rows.
#[test]
fn a_declared_page_size_seeds_the_parameters_own_default() {
    let svc = compile_paged(json!({
        "page_size": {"param": "maxResults", "default": 100, "max": 500},
        "next": {"style": "cursor", "param": "pageToken", "from": "nextPageToken"},
        "items": "messages"
    }));
    let action = &svc.actions["list_messages"];
    assert_eq!(action.params["maxResults"].default, Some(json!(100)));
    let spec = action.pagination.as_ref().expect("pagination compiled");
    assert_eq!(spec.next.style, crate::types::NextStyle::Cursor);
    assert_eq!(spec.next.param.as_deref(), Some("pageToken"));
    assert_eq!(spec.next.from.as_deref(), Some("nextPageToken"));
    assert_eq!(spec.items.as_deref(), Some("messages"));
}

/// Seeding, not overwriting. A hand-authored `default:` is the more
/// specific statement, and it is the one an org layer patches.
#[test]
fn a_parameter_that_declares_its_own_default_keeps_it() {
    let mut doc = paged_doc(json!({
        "page_size": {"param": "maxResults", "default": 100},
        "next": {"style": "cursor", "param": "pageToken", "from": "nextPageToken"}
    }));
    doc["paths"]["/messages"]["get"]["parameters"][0]["schema"]["default"] = json!(25);
    assert!(normalize_aliases(&mut doc).is_empty());
    let svc = compile_service(&doc).unwrap().0;
    assert_eq!(
        svc.actions["list_messages"].params["maxResults"].default,
        Some(json!(25))
    );
}

/// The `x-overslash-` spelling and the bare alias have to compile to the
/// same thing, or a template author picking the documented short form gets
/// an action that silently does not page.
#[test]
fn the_prefixed_and_unprefixed_spellings_agree() {
    let bare = compile_paged(json!({
        "next": {"style": "link"}
    }));
    let mut doc = paged_doc(json!(null));
    doc["paths"]["/messages"]["get"]
        .as_object_mut()
        .unwrap()
        .remove("pagination");
    doc["paths"]["/messages"]["get"]["x-overslash-pagination"] = json!({"next": {"style": "link"}});
    assert!(normalize_aliases(&mut doc).is_empty());
    let prefixed = compile_service(&doc).unwrap().0;
    assert_eq!(
        bare.actions["list_messages"].pagination,
        prefixed.actions["list_messages"].pagination
    );
}

/// D67's leniency, one more time: a broken declaration is an authoring
/// error the author can see, not a service that quietly loses an action.
#[test]
fn a_malformed_pagination_block_is_an_authoring_error() {
    for (bad, code) in [
        (
            json!({"page_size": {"param": "maxResults"}}),
            "pagination_invalid",
        ),
        (
            json!({"next": {"style": "sideways"}}),
            "pagination_invalid_style",
        ),
        (
            json!({"next": {"style": "cursor", "param": "pageToken"}}),
            "pagination_invalid",
        ),
        (
            json!({"next": {"style": "link", "param": "pageToken"}}),
            "pagination_invalid",
        ),
        (
            json!({"next": {"style": "offset", "param": "pageToken", "from": "x"}}),
            "pagination_invalid",
        ),
        (
            json!({
                "page_size": {"param": "maxResults", "default": 900, "max": 500},
                "next": {"style": "link"}
            }),
            "pagination_default_exceeds_max",
        ),
    ] {
        let mut doc = paged_doc(bad.clone());
        normalize_aliases(&mut doc);
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.code == code),
            "expected {code} for {bad}, got {err:?}"
        );
    }
}

/// A misspelled mode falls back to synchronous — the historical behaviour
/// — and says so, rather than removing the action. D67's leniency: a stray
/// value must not be able to take a service down.
#[test]
fn an_unrecognized_wait_mode_is_an_authoring_error_not_a_dropped_action() {
    let doc = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t"},
        "servers": [{"url": "https://t.example"}],
        "paths": {"/x": {"get": {
            "operationId": "x", "description": "d",
            "x-overslash-wait-mode": "deferred"
        }}}
    });
    let err = compile_service(&doc).unwrap_err();
    assert!(err.iter().any(|i| i.code == "invalid_wait_mode"), "{err:?}");
}

#[test]
fn a_non_positive_timeout_is_an_authoring_error_not_a_silent_fallback() {
    let doc = json!({
        "openapi": "3.1.0",
        "info": {"title": "T", "x-overslash-key": "t"},
        "servers": [{"url": "https://t.example"}],
        "paths": {"/x": {"get": {
            "operationId": "x", "description": "d",
            "x-overslash-timeout_ms": "30s"
        }}}
    });
    let err = compile_service(&doc).expect_err("string timeout rejected");
    assert!(
        err.iter()
            .any(|e| e.code == "invalid_timeout"
                && e.path == "paths./x.get.x-overslash-timeout_ms"),
        "{err:?}"
    );
}
