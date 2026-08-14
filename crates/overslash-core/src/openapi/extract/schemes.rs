//! One lowering per `securitySchemes` type: `oauth2`, `apiKey`, `http`.

use serde_json::{Map, Value};

use crate::credential_template::TemplateReads;
use crate::template_validation::ValidationIssue;
use crate::types::{CredentialTemplate, ServiceAuth, TokenInjection};

use super::super::ext::{self, Ext, Pos, SchemeKind};
use super::auth::extract_template;

pub(super) fn extract_oauth2(
    obj: &Map<String, Value>,
    _base: &str,
) -> Result<ServiceAuth, Vec<ValidationIssue>> {
    let provider = ext::get(obj, Pos::SecurityScheme(SchemeKind::Oauth2), Ext::Provider)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Collect scopes from all declared OAuth flows (authorizationCode is the
    // common one). A scope declared in any flow counts as supported.
    let mut scopes: Vec<String> = Vec::new();
    if let Some(flows) = obj.get("flows").and_then(Value::as_object) {
        for flow in flows.values() {
            if let Some(f) = flow.as_object()
                && let Some(s) = f.get("scopes").and_then(Value::as_object)
            {
                for k in s.keys() {
                    if !scopes.contains(k) {
                        scopes.push(k.clone());
                    }
                }
            }
        }
    }

    // OAuth tokens are standardly injected as `Authorization: Bearer <token>`.
    // Allow an explicit override via x-overslash-token_injection; otherwise
    // use the bearer default.
    let token_injection = parse_token_injection(ext::get(
        obj,
        Pos::SecurityScheme(SchemeKind::Oauth2),
        Ext::TokenInjection,
    ))
    .unwrap_or(TokenInjection {
        inject_as: "header".into(),
        header_name: Some("Authorization".into()),
        query_param: None,
        prefix: Some("Bearer ".into()),
    });

    Ok(ServiceAuth::OAuth {
        provider,
        scopes,
        token_injection,
    })
}

pub(super) fn extract_api_key(
    obj: &Map<String, Value>,
    base: &str,
    // The securitySchemes map key (`gateway`, `mailbox`, …) — NOT the scheme
    // object's `name` field, which is the HTTP header/query-param name.
    scheme_key: &str,
    // Slot keys declared under `components.x-overslash-secrets`.
    declared_slots: &[String],
    // Config keys declared under `components.x-overslash-config`.
    declared_config: &[String],
) -> Result<ServiceAuth, Vec<ValidationIssue>> {
    let default_secret_name = ext::get(
        obj,
        Pos::SecurityScheme(SchemeKind::ApiKey),
        Ext::DefaultSecretName,
    )
    .and_then(Value::as_str)
    .unwrap_or("")
    .to_string();

    let inject_as = obj.get("in").and_then(Value::as_str).unwrap_or("header");
    let name = obj.get("name").and_then(Value::as_str).map(str::to_string);

    // Predecessors of `x-overslash-template`. A live template in the wild
    // still carrying them would silently lose its transform, so name the
    // replacement rather than ignoring the key.
    for (legacy, replacement) in [
        ("x-overslash-prefix", r#""Bearer " + .SLOT"#),
        ("x-overslash-encode", r#"(.SLOT | @base64)"#),
    ] {
        if obj.contains_key(legacy) {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "{legacy} was replaced by x-overslash-template; express it as \
                     `{{lang: jq, expr: '{replacement}'}}`"
                ),
                format!("{base}.{legacy}"),
            )]);
        }
    }

    let (template, reads) =
        extract_template(obj, base, scheme_key, declared_slots, declared_config)?;
    let TemplateReads {
        slots,
        config: config_keys,
    } = reads;

    let secret_source = match ext::get(
        obj,
        Pos::SecurityScheme(SchemeKind::ApiKey),
        Ext::SecretSource,
    )
    .and_then(Value::as_str)
    {
        Some("org") => crate::types::SecretSource::Org,
        Some("instance") | None => crate::types::SecretSource::Instance,
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "{} must be `instance` or `org` (got {other:?})",
                    Ext::SecretSource.key()
                ),
                format!("{base}.{}", Ext::SecretSource.key()),
            )]);
        }
    };

    let optional = match ext::get(obj, Pos::SecurityScheme(SchemeKind::ApiKey), Ext::Optional) {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("{} must be a boolean (got {other})", Ext::Optional.key()),
                format!("{base}.{}", Ext::Optional.key()),
            )]);
        }
    };

    let injection = match inject_as {
        "header" => TokenInjection {
            inject_as: "header".into(),
            header_name: name,
            query_param: None,
            prefix: None,
        },
        "query" => TokenInjection {
            inject_as: "query".into(),
            header_name: None,
            query_param: name,
            prefix: None,
        },
        other => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("apiKey `in` must be `header` or `query` (got {other:?})"),
                format!("{base}.in"),
            )]);
        }
    };

    let label = match ext::get(obj, Pos::SecurityScheme(SchemeKind::ApiKey), Ext::Label) {
        None => String::new(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("{} must be a string (got {other})", Ext::Label.key()),
                format!("{base}.{}", Ext::Label.key()),
            )]);
        }
    };

    Ok(ServiceAuth::Secret {
        scheme: scheme_key.to_string(),
        label,
        description: scheme_description(obj),
        default_secret_name,
        injection,
        template,
        slots,
        config_keys,
        secret_source,
        optional,
    })
}

pub(super) fn extract_http_auth(
    obj: &Map<String, Value>,
    base: &str,
    // The securitySchemes map key — NOT the `scheme` field below, which is
    // the HTTP auth scheme (`bearer`).
    scheme_key: &str,
) -> Result<ServiceAuth, Vec<ValidationIssue>> {
    let scheme = obj.get("scheme").and_then(Value::as_str).unwrap_or("");
    if scheme != "bearer" {
        return Err(vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            format!("http auth scheme {scheme:?} is not supported (only `bearer`)"),
            format!("{base}.scheme"),
        )]);
    }
    let default_secret_name = ext::get(
        obj,
        Pos::SecurityScheme(SchemeKind::Http),
        Ext::DefaultSecretName,
    )
    .and_then(Value::as_str)
    .unwrap_or("")
    .to_string();
    Ok(ServiceAuth::Secret {
        scheme: scheme_key.to_string(),
        label: ext::get(obj, Pos::SecurityScheme(SchemeKind::Http), Ext::Label)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string(),
        description: scheme_description(obj),
        default_secret_name,
        injection: TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: None,
        },
        // `http`+`bearer` is exactly "prepend `Bearer ` to the one secret",
        // so it compiles to the template that says so rather than to a
        // special case the injector has to know about.
        template: Some(CredentialTemplate::Jq {
            expr: format!(r#""Bearer " + .{scheme_key}"#),
        }),
        slots: vec![scheme_key.to_string()],
        // A bearer scheme composes nothing: its template is generated, not
        // authored, so there is no place for a config read.
        config_keys: Vec::new(),
        secret_source: crate::types::SecretSource::Instance,
        optional: false,
    })
}

/// The standard OpenAPI securityScheme `description`, verbatim (empty when
/// absent). Surfaces as help text for the credential's dashboard row.
fn scheme_description(obj: &Map<String, Value>) -> String {
    obj.get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn parse_token_injection(v: Option<&Value>) -> Option<TokenInjection> {
    let obj = v?.as_object()?;
    Some(TokenInjection {
        inject_as: obj
            .get("as")
            .and_then(Value::as_str)
            .unwrap_or("header")
            .to_string(),
        header_name: obj
            .get("header_name")
            .and_then(Value::as_str)
            .map(str::to_string),
        query_param: obj
            .get("query_param")
            .and_then(Value::as_str)
            .map(str::to_string),
        prefix: obj
            .get("prefix")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::compile_service;
    use serde_json::json;

    // ── extract_api_key ──────────────────────────────────────────────

    #[test]
    fn api_key_in_query() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "token": {
                    "type": "apiKey",
                    "in": "query",
                    "name": "api_key",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match svc.auth.into_iter().next().unwrap() {
            ServiceAuth::Secret {
                default_secret_name,
                injection,
                ..
            } => {
                assert_eq!(default_secret_name, "t_token");
                assert_eq!(injection.inject_as, "query");
                assert_eq!(injection.query_param.as_deref(), Some("api_key"));
                assert!(injection.header_name.is_none());
                assert!(injection.prefix.is_none());
            }
            _ => panic!("expected Secret"),
        }
    }

    #[test]
    fn api_key_rejects_in_cookie() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "c": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "session",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.path.ends_with(".in")),
            "got: {err:?}"
        );
    }

    #[test]
    fn api_key_defaults_in_to_header() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "token": {
                    "type": "apiKey",
                    "name": "Authorization",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::Secret { injection, .. } => {
                assert_eq!(injection.inject_as, "header");
                assert_eq!(injection.header_name.as_deref(), Some("Authorization"));
            }
            _ => panic!("expected Secret"),
        }
    }

    // ── extract_http_auth: full coverage ──────────────────────────────

    #[test]
    fn http_bearer_success() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::Secret {
                default_secret_name,
                injection,
                template,
                slots,
                ..
            } => {
                assert_eq!(default_secret_name, "t_token");
                assert_eq!(injection.inject_as, "header");
                assert_eq!(injection.header_name.as_deref(), Some("Authorization"));
                assert!(injection.query_param.is_none());
                // `http`+`bearer` is "prepend Bearer to the one secret", which
                // compiles to the template that says so rather than to a
                // special case the injector would have to know about.
                assert_eq!(
                    template.as_ref().map(CredentialTemplate::expr),
                    Some(r#""Bearer " + .bearer"#)
                );
                assert_eq!(slots, &["bearer"]);
            }
            _ => panic!("expected Secret for http/bearer"),
        }
        // The implicit self-named slot carries the scheme's own metadata, so a
        // single-secret template declares no x-overslash-secrets block.
        let all = svc.all_slots();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].key, "bearer");
        assert_eq!(all[0].default_secret_name, "t_token");
    }

    #[test]
    fn http_bearer_allows_missing_default_secret_name() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"}
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::Secret {
                default_secret_name,
                ..
            } => assert!(default_secret_name.is_empty()),
            _ => panic!("expected Secret for http/bearer"),
        }
    }

    #[test]
    fn http_rejects_basic_scheme() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "basic": {"type": "http", "scheme": "basic"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.code == "openapi_unsupported_construct"
                && i.message.contains("basic")
                && i.path.ends_with(".scheme")),
            "got: {err:?}"
        );
    }

    #[test]
    fn http_rejects_digest_scheme() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "digest": {"type": "http", "scheme": "digest"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.message.contains("digest")),
            "got: {err:?}"
        );
    }

    #[test]
    fn http_rejects_missing_scheme() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "nope": {"type": "http"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.path.ends_with(".scheme")),
            "got: {err:?}"
        );
    }

    // ── extract_oauth2 ────────────────────────────────────────────────

    #[test]
    fn oauth2_with_explicit_token_injection_override() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "x-overslash-provider": "custom",
                    "flows": {},
                    "x-overslash-token_injection": {
                        "as": "query",
                        "query_param": "access_token"
                    }
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::OAuth {
                token_injection, ..
            } => {
                assert_eq!(token_injection.inject_as, "query");
                assert_eq!(token_injection.query_param.as_deref(), Some("access_token"));
                assert!(token_injection.header_name.is_none());
            }
            _ => panic!("expected OAuth"),
        }
    }

    #[test]
    fn oauth2_empty_provider_allowed() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oauth": {"type": "oauth2", "flows": {}}
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::OAuth { provider, .. } => assert!(provider.is_empty()),
            _ => panic!("expected OAuth"),
        }
    }

    #[test]
    fn oauth2_dedups_scopes_across_flows() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "x-overslash-provider": "p",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://x", "tokenUrl": "https://y",
                            "scopes": {"read": "", "write": ""}
                        },
                        "clientCredentials": {
                            "tokenUrl": "https://y",
                            "scopes": {"read": "", "admin": ""}
                        }
                    }
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::OAuth { scopes, .. } => {
                assert!(scopes.contains(&"read".to_string()));
                assert!(scopes.contains(&"write".to_string()));
                assert!(scopes.contains(&"admin".to_string()));
                let reads = scopes.iter().filter(|s| *s == "read").count();
                assert_eq!(reads, 1);
            }
            _ => panic!("expected OAuth"),
        }
    }
}
