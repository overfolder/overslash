//! Alias normalization: rewrites the friendly unprefixed forms (`risk:`,
//! `scope_param:`, `resolve:`, …) to their canonical `x-overslash-*`
//! counterparts in place. Ambiguous objects (both forms present) surface a
//! stable `ambiguous_alias` issue with a dot-path.
//!
//! The normalizer is context-aware: aliases are only rewritten in the OpenAPI
//! positions where they're meaningful (`info`, operation, parameter, security
//! scheme of the matching type, platform-action entries).

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;

/// Where an alias may appear and the canonical key it rewrites to.
#[derive(Debug, Clone, Copy)]
pub(super) struct Alias {
    pub alias: &'static str,
    pub canonical: &'static str,
}

pub(super) const ROOT_ALIASES: &[Alias] = &[Alias {
    alias: "platform_actions",
    canonical: "x-overslash-platform_actions",
}];

pub(super) const INFO_ALIASES: &[Alias] = &[
    Alias {
        alias: "key",
        canonical: "x-overslash-key",
    },
    Alias {
        alias: "category",
        canonical: "x-overslash-category",
    },
];

pub(super) const OPERATION_ALIASES: &[Alias] = &[
    Alias {
        alias: "risk",
        canonical: "x-overslash-risk",
    },
    Alias {
        alias: "scope_param",
        canonical: "x-overslash-scope_param",
    },
];

pub(super) const PARAMETER_ALIASES: &[Alias] = &[Alias {
    alias: "resolve",
    canonical: "x-overslash-resolve",
}];

pub(super) const OAUTH2_SEC_ALIASES: &[Alias] = &[Alias {
    alias: "provider",
    canonical: "x-overslash-provider",
}];

pub(super) const APIKEY_HTTP_SEC_ALIASES: &[Alias] = &[Alias {
    alias: "default_secret_name",
    canonical: "x-overslash-default_secret_name",
}];

pub(super) const HTTP_METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Walk a JSON object and rewrite every alias key listed in `table` to its
/// canonical form. When both forms are present on the same object, emits an
/// `ambiguous_alias` issue and leaves both keys in place.
pub(super) fn rewrite_aliases(
    obj: &mut Map<String, Value>,
    table: &[Alias],
    base_path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for a in table {
        let has_alias = obj.contains_key(a.alias);
        let has_canonical = obj.contains_key(a.canonical);
        match (has_alias, has_canonical) {
            (true, true) => {
                let path = if base_path.is_empty() {
                    a.alias.to_string()
                } else {
                    format!("{base_path}.{}", a.alias)
                };
                issues.push(ValidationIssue::new(
                    "ambiguous_alias",
                    format!(
                        "both `{}` and `{}` are present on the same object; remove one",
                        a.alias, a.canonical
                    ),
                    path,
                ));
            }
            (true, false) => {
                if let Some(val) = obj.remove(a.alias) {
                    obj.insert(a.canonical.to_string(), val);
                }
            }
            _ => {}
        }
    }
}

/// Normalize parameter aliases on the `parameters` array of an object. Used
/// for both path-item and operation contexts.
pub(super) fn normalize_parameters_in(
    obj: &mut Map<String, Value>,
    obj_base: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(params) = obj.get_mut("parameters").and_then(Value::as_array_mut) else {
        return;
    };
    for (i, p) in params.iter_mut().enumerate() {
        let Value::Object(pm) = p else { continue };
        let base = format!("{obj_base}.parameters[{i}]");
        rewrite_aliases(pm, PARAMETER_ALIASES, &base, issues);
    }
}

#[cfg(test)]
mod tests {
    use super::super::normalize_aliases;
    use serde_json::{Value, json};

    fn doc(v: Value) -> Value {
        v
    }

    #[test]
    fn rewrites_alias_on_info() {
        let mut v = doc(json!({
            "info": {"key": "slack", "category": "chat", "title": "Slack"}
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let info = v["info"].as_object().unwrap();
        assert_eq!(info["x-overslash-key"], "slack");
        assert_eq!(info["x-overslash-category"], "chat");
        assert!(!info.contains_key("key"));
    }

    #[test]
    fn idempotent_on_canonical_form() {
        let mut v = doc(json!({
            "info": {"x-overslash-key": "slack", "title": "Slack"}
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty());
        assert_eq!(v["info"]["x-overslash-key"], "slack");
    }

    #[test]
    fn rewrites_operation_risk_and_scope_param() {
        let mut v = doc(json!({
            "paths": {"/repos/{repo}/pulls": {"post": {
                "operationId": "createPull",
                "risk": "write",
                "scope_param": "repo"
            }}}
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let op = v["paths"]["/repos/{repo}/pulls"]["post"]
            .as_object()
            .unwrap();
        assert_eq!(op["x-overslash-risk"], "write");
        assert_eq!(op["x-overslash-scope_param"], "repo");
        assert!(!op.contains_key("risk"));
    }

    #[test]
    fn rewrites_operation_parameter_resolve() {
        let mut v = doc(json!({
            "paths": {"/x/{id}": {"get": {
                "operationId": "getX",
                "parameters": [{"name": "id", "in": "path", "required": true,
                 "resolve": {"get": "/x/{id}", "pick": "name"}}]
            }}}
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let p0 = &v["paths"]["/x/{id}"]["get"]["parameters"][0];
        assert!(p0.get("x-overslash-resolve").is_some());
        assert!(p0.get("resolve").is_none());
    }

    #[test]
    fn rewrites_path_level_parameter_resolve() {
        let mut v = doc(json!({
            "paths": {"/x/{id}": {
                "parameters": [{"name": "id", "in": "path", "required": true,
                 "resolve": {"get": "/x/{id}", "pick": "name"}}],
                "get": {"operationId": "getX"}
            }}
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let p0 = &v["paths"]["/x/{id}"]["parameters"][0];
        assert!(p0.get("x-overslash-resolve").is_some());
    }

    #[test]
    fn rewrites_oauth2_provider() {
        let mut v = doc(json!({
            "components": {"securitySchemes": {
                "slack_oauth": {"type": "oauth2", "provider": "slack", "flows": {}}
            }}
        }));
        assert!(normalize_aliases(&mut v).is_empty());
        assert_eq!(
            v["components"]["securitySchemes"]["slack_oauth"]["x-overslash-provider"],
            "slack"
        );
    }

    #[test]
    fn rewrites_api_key_default_secret() {
        let mut v = doc(json!({
            "components": {"securitySchemes": {
                "slack_token": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "default_secret_name": "slack_token"
                }
            }}
        }));
        assert!(normalize_aliases(&mut v).is_empty());
        assert_eq!(
            v["components"]["securitySchemes"]["slack_token"]["x-overslash-default_secret_name"],
            "slack_token"
        );
    }

    #[test]
    fn rewrites_top_level_platform_actions() {
        let mut v = doc(json!({
            "platform_actions": {
                "manage_members": {"description": "x", "risk": "delete"}
            }
        }));
        assert!(normalize_aliases(&mut v).is_empty());
        assert_eq!(
            v["x-overslash-platform_actions"]["manage_members"]["x-overslash-risk"],
            "delete"
        );
    }

    // ── Non-object tolerance / early returns ─────────────────────────

    #[test]
    fn non_object_root_is_noop() {
        let mut arr = json!([]);
        assert!(normalize_aliases(&mut arr).is_empty());
        let mut scalar = json!("not an object");
        assert!(normalize_aliases(&mut scalar).is_empty());
    }

    #[test]
    fn skips_non_object_path_item() {
        let mut v = json!({
            "paths": {
                "/broken": null,
                "/ok": {"get": {"operationId": "ok", "risk": "read"}}
            }
        });
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(v["paths"]["/ok"]["get"]["x-overslash-risk"], "read");
    }

    #[test]
    fn skips_non_object_security_scheme() {
        let mut v = json!({
            "components": {"securitySchemes": {
                "bogus": "not-an-object",
                "real": {"type": "oauth2", "provider": "slack", "flows": {}}
            }}
        });
        assert!(normalize_aliases(&mut v).is_empty());
        assert_eq!(
            v["components"]["securitySchemes"]["real"]["x-overslash-provider"],
            "slack"
        );
    }

    #[test]
    fn skips_non_object_platform_action() {
        let mut v = json!({
            "x-overslash-platform_actions": {
                "bogus": "not-an-object",
                "real": {"description": "x", "risk": "delete"}
            }
        });
        assert!(normalize_aliases(&mut v).is_empty());
        assert_eq!(
            v["x-overslash-platform_actions"]["real"]["x-overslash-risk"],
            "delete"
        );
    }

    #[test]
    fn unknown_security_scheme_type_left_alone() {
        let mut v = json!({
            "components": {"securitySchemes": {
                "oidc": {"type": "openIdConnect", "provider": "should-not-rewrite"}
            }}
        });
        assert!(normalize_aliases(&mut v).is_empty());
        let scheme = &v["components"]["securitySchemes"]["oidc"];
        assert_eq!(scheme["provider"], "should-not-rewrite");
        assert!(scheme.get("x-overslash-provider").is_none());
    }

    // ── Ambiguity on every alias site ────────────────────────────────

    #[test]
    fn rejects_ambiguous_info_key() {
        let mut v = doc(json!({
            "info": {"key": "slack", "x-overslash-key": "slack", "title": "Slack"}
        }));
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
        assert_eq!(issues[0].path, "info.key");
    }

    #[test]
    fn rejects_ambiguous_operation_risk() {
        let mut v = json!({
            "paths": {"/x": {"post": {
                "operationId": "x",
                "risk": "write",
                "x-overslash-risk": "write"
            }}}
        });
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
        assert_eq!(issues[0].path, "paths./x.post.risk");
    }

    #[test]
    fn rejects_ambiguous_parameter_resolve() {
        let mut v = json!({
            "paths": {"/x/{id}": {"get": {
                "operationId": "x",
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "resolve": {"get": "/x/{id}", "pick": "name"},
                    "x-overslash-resolve": {"get": "/x/{id}", "pick": "name"}
                }]
            }}}
        });
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
        assert!(issues[0].path.ends_with(".parameters[0].resolve"));
    }

    #[test]
    fn rejects_ambiguous_path_level_parameter_resolve() {
        let mut v = json!({
            "paths": {"/x/{id}": {
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "resolve": {"get": "/x/{id}", "pick": "name"},
                    "x-overslash-resolve": {"get": "/x/{id}", "pick": "name"}
                }],
                "get": {"operationId": "x"}
            }}
        });
        let issues = normalize_aliases(&mut v);
        assert!(issues.iter().any(
            |i| i.code == "ambiguous_alias" && i.path == "paths./x/{id}.parameters[0].resolve"
        ));
    }

    #[test]
    fn rejects_ambiguous_security_scheme_provider() {
        let mut v = json!({
            "components": {"securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "provider": "slack",
                    "x-overslash-provider": "slack",
                    "flows": {}
                }
            }}
        });
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
        assert_eq!(issues[0].path, "components.securitySchemes.oauth.provider");
    }

    #[test]
    fn rejects_ambiguous_security_scheme_default_secret_name() {
        let mut v = json!({
            "components": {"securitySchemes": {
                "token": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "default_secret_name": "svc_token",
                    "x-overslash-default_secret_name": "svc_token"
                }
            }}
        });
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
    }

    #[test]
    fn rejects_ambiguous_platform_action_risk() {
        let mut v = json!({
            "x-overslash-platform_actions": {
                "act": {
                    "description": "x",
                    "risk": "delete",
                    "x-overslash-risk": "delete"
                }
            }
        });
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
        assert!(
            issues[0]
                .path
                .starts_with("x-overslash-platform_actions.act")
        );
    }

    #[test]
    fn rejects_ambiguous_top_level_platform_actions() {
        let mut v = json!({
            "platform_actions": {"x": {"description": "x"}},
            "x-overslash-platform_actions": {"x": {"description": "x"}}
        });
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
        assert_eq!(issues[0].path, "platform_actions");
    }
}
