//! The credential model: the slots an operator binds, the non-secret values
//! they set, and the templates that read both.

use serde_json::{Map, Value};

use crate::credential_template::TemplateReads;
use crate::template_validation::ValidationIssue;
use crate::types::{ConfigVar, CredentialTemplate, SecretSlot, ServiceAuth};

use super::super::ext::{self, Ext, Pos, SchemeKind};
use super::schemes::{extract_api_key, extract_http_auth, extract_oauth2};

// ── securitySchemes → Vec<ServiceAuth> ───────────────────────────────

/// A template's whole credential model: what an operator fills in, and the
/// injections that read it.
pub(crate) struct CompiledCredentials {
    /// The injections — one per securityScheme.
    pub auth: Vec<ServiceAuth>,
    /// Vault secrets an instance binds.
    pub secrets: Vec<SecretSlot>,
    /// Non-secret values an instance sets.
    pub config: Vec<ConfigVar>,
}

/// Compile `components.x-overslash-secrets` + `components.x-overslash-config` +
/// `components.securitySchemes` into the credential model: the slots an
/// operator binds, the non-secret values they set, and the injections that read
/// both.
pub(crate) fn extract_auth(
    components: Option<&Value>,
) -> Result<CompiledCredentials, Vec<ValidationIssue>> {
    let mut out = Vec::new();
    let mut errors = Vec::new();

    let mut slots = match extract_secret_slots(components) {
        Ok(s) => s,
        Err(mut es) => {
            errors.append(&mut es);
            Vec::new()
        }
    };
    let config = match extract_config_vars(components) {
        Ok(c) => c,
        Err(mut es) => {
            errors.append(&mut es);
            Vec::new()
        }
    };
    let declared: Vec<String> = slots.iter().map(|s| s.key.clone()).collect();
    let declared_config: Vec<String> = config.iter().map(|c| c.key.clone()).collect();

    // One key, one meaning. Declared in both blocks there is no answer to "is
    // this value vaulted?", and the partition would silently pick config.
    for key in &declared_config {
        if declared.contains(key) {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "`{key}` is declared as both a secret and a config value; \
                     a template input is either vaulted or it is not"
                ),
                format!("components.x-overslash-config.{key}"),
            ));
        }
    }

    let Some(schemes) = components
        .and_then(Value::as_object)
        .and_then(|c| c.get("securitySchemes"))
        .and_then(Value::as_object)
    else {
        if !errors.is_empty() {
            return Err(errors);
        }
        return Ok(CompiledCredentials {
            auth: out,
            secrets: slots,
            config,
        });
    };

    // Deterministic order so tests/snapshots are stable.
    let mut keys: Vec<&String> = schemes.keys().collect();
    keys.sort();
    for name in keys {
        let scheme = &schemes[name];
        let Some(obj) = scheme.as_object() else {
            continue;
        };
        let base = format!("components.securitySchemes.{name}");
        let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "oauth2" => match extract_oauth2(obj, &base) {
                Ok(a) => out.push(a),
                Err(mut es) => errors.append(&mut es),
            },
            "apiKey" => match extract_api_key(obj, &base, name, &declared, &declared_config) {
                Ok(a) => out.push(a),
                Err(mut es) => errors.append(&mut es),
            },
            "http" => match extract_http_auth(obj, &base, name) {
                Ok(a) => out.push(a),
                Err(mut es) => errors.append(&mut es),
            },
            other => errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("security scheme type {other:?} is not supported"),
                format!("{base}.type"),
            )),
        }
    }

    // Every scheme implicitly declares a slot named after itself, carrying the
    // scheme's own label/source/optional. That is the shape of a credential
    // that needs just one secret, so those templates declare no secrets block.
    for auth in &out {
        if let ServiceAuth::Secret {
            scheme,
            label,
            description,
            default_secret_name,
            slots: read,
            secret_source,
            optional,
            ..
        } = auth
            && read.iter().any(|s| s == scheme)
            && !slots.iter().any(|s| &s.key == scheme)
        {
            slots.push(SecretSlot {
                key: scheme.clone(),
                label: label.clone(),
                description: description.clone(),
                default_secret_name: default_secret_name.clone(),
                source: *secret_source,
                optional: *optional,
            });
        }
    }

    // A slot nothing reads is dead config: the dashboard would ask for a
    // secret that can never reach a request.
    let read: Vec<&str> = out
        .iter()
        .filter_map(|a| match a {
            ServiceAuth::Secret { slots, .. } => Some(slots.iter().map(String::as_str)),
            _ => None,
        })
        .flatten()
        .collect();
    for slot in &slots {
        if !read.contains(&slot.key.as_str()) {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "secret `{}` is declared but no security scheme reads it",
                    slot.key
                ),
                format!("components.x-overslash-secrets.{}", slot.key),
            ));
        }
    }

    // Same reasoning for config: a var nothing reads is a field on the instance
    // form whose value can never reach a request.
    let read_config: Vec<&str> = out
        .iter()
        .filter_map(|a| match a {
            ServiceAuth::Secret { config_keys, .. } => Some(config_keys.iter().map(String::as_str)),
            _ => None,
        })
        .flatten()
        .collect();
    for var in &config {
        // `sql_databases` is consumed by the D42 SQL policy at call time
        // (dialect + audit-label lookup), not by a credential template, so
        // it is exempt from the scheme-reads check.
        if var.key == crate::sql_policy::SQL_DATABASES_CONFIG_KEY {
            continue;
        }
        if !read_config.contains(&var.key.as_str()) {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "config `{}` is declared but no security scheme reads it",
                    var.key
                ),
                format!("components.x-overslash-config.{}", var.key),
            ));
        }
    }

    slots.sort_by(|a, b| a.key.cmp(&b.key));

    if errors.is_empty() {
        Ok(CompiledCredentials {
            auth: out,
            secrets: slots,
            config,
        })
    } else {
        Err(errors)
    }
}

/// Parse `components.x-overslash-config` — the non-secret per-instance values
/// this template's credential expressions may read. Same declaration shape as
/// the secrets block minus everything vault-specific (no source, no default
/// secret name), because there is no vault entry behind one.
fn extract_config_vars(components: Option<&Value>) -> Result<Vec<ConfigVar>, Vec<ValidationIssue>> {
    let Some(map) = components
        .and_then(Value::as_object)
        .and_then(|c| ext::get(c, Pos::Components, Ext::Config))
    else {
        return Ok(Vec::new());
    };
    let Some(map) = map.as_object() else {
        return Err(vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            "x-overslash-config must be a map of config key to declaration",
            "components.x-overslash-config",
        )]);
    };

    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let base = format!("components.x-overslash-config.{key}");
        let Some(obj) = map[key].as_object() else {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("config `{key}` must be an object"),
                base,
            ));
            continue;
        };
        let required = match obj.get("required") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(other) => {
                errors.push(ValidationIssue::new(
                    "openapi_unsupported_construct",
                    format!("config `required` must be a boolean (got {other})"),
                    format!("{base}.required"),
                ));
                continue;
            }
        };
        let identity = match obj.get("identity") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(other) => {
                errors.push(ValidationIssue::new(
                    "openapi_unsupported_construct",
                    format!("config `identity` must be a boolean (got {other})"),
                    format!("{base}.identity"),
                ));
                continue;
            }
        };
        out.push(ConfigVar {
            key: key.clone(),
            label: str_field(obj, "label"),
            description: str_field(obj, "description"),
            required,
            identity,
        });
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Parse `components.x-overslash-secrets` — the credential slots this template
/// needs, declared once and referenced by name from the schemes' templates.
fn extract_secret_slots(
    components: Option<&Value>,
) -> Result<Vec<SecretSlot>, Vec<ValidationIssue>> {
    let Some(map) = components
        .and_then(Value::as_object)
        .and_then(|c| ext::get(c, Pos::Components, Ext::Secrets))
    else {
        return Ok(Vec::new());
    };
    let Some(map) = map.as_object() else {
        return Err(vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            "x-overslash-secrets must be a map of slot key to declaration",
            "components.x-overslash-secrets",
        )]);
    };

    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let base = format!("components.x-overslash-secrets.{key}");
        let Some(obj) = map[key].as_object() else {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("secret `{key}` must be an object"),
                base,
            ));
            continue;
        };
        let source = match obj.get("source").and_then(Value::as_str) {
            Some("org") => crate::types::SecretSource::Org,
            Some("instance") | None => crate::types::SecretSource::Instance,
            Some(other) => {
                errors.push(ValidationIssue::new(
                    "openapi_unsupported_construct",
                    format!("secret source must be `instance` or `org` (got {other:?})"),
                    format!("{base}.source"),
                ));
                continue;
            }
        };
        out.push(SecretSlot {
            key: key.clone(),
            label: str_field(obj, "label"),
            description: str_field(obj, "description"),
            default_secret_name: str_field(obj, "default_secret_name"),
            source,
            optional: obj
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn str_field(obj: &Map<String, Value>, key: &str) -> String {
    obj.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Parse `x-overslash-template` and resolve the inputs it reads, split into
/// vault slots and non-secret config keys.
///
/// Returns `(None, {slots: [scheme_key], config: []})` when absent: the
/// credential is one secret injected verbatim, from the slot named after the
/// scheme.
pub(super) fn extract_template(
    obj: &Map<String, Value>,
    base: &str,
    scheme_key: &str,
    declared_slots: &[String],
    declared_config: &[String],
) -> Result<(Option<CredentialTemplate>, TemplateReads), Vec<ValidationIssue>> {
    let issue = |msg: String, path: String| {
        vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            msg,
            path,
        )]
    };
    let path = format!("{base}.{}", Ext::Template.key());

    // `extract_api_key` is the only caller: on an `http` scheme the injection
    // template is generated rather than authored, which is why
    // `Pos::SecurityScheme(Http)` does not read this key.
    let Some(raw) = ext::get(obj, Pos::SecurityScheme(SchemeKind::ApiKey), Ext::Template) else {
        return Ok((
            None,
            TemplateReads {
                slots: vec![scheme_key.to_string()],
                config: Vec::new(),
            },
        ));
    };
    let Some(raw) = raw.as_object() else {
        return Err(issue(
            "x-overslash-template must be an object with `lang` and `expr`".into(),
            path,
        ));
    };

    match raw.get("lang").and_then(Value::as_str) {
        Some("jq") => {}
        Some(other) => {
            return Err(issue(
                format!("credential template lang must be `jq` (got {other:?})"),
                format!("{path}.lang"),
            ));
        }
        None => {
            return Err(issue(
                "credential template needs a `lang` (only `jq` today)".into(),
                format!("{path}.lang"),
            ));
        }
    }
    let Some(expr) = raw.get("expr").and_then(Value::as_str) else {
        return Err(issue(
            "credential template needs an `expr` string".into(),
            format!("{path}.expr"),
        ));
    };

    let template = CredentialTemplate::Jq {
        expr: expr.to_string(),
    };
    // Resolved once here so nothing on the request path parses jq to decide
    // which secrets to decrypt.
    let reads = crate::credential_template::partition_reads(&template, declared_config)
        .map_err(|e| issue(e.to_string(), format!("{path}.expr")))?;

    if reads.slots.is_empty() {
        // Config values alone are not a credential — they are public by
        // declaration, so a header built only from them authenticates nothing
        // and belongs in `parameters` (where `x-overslash-instance-config`
        // already pins per-instance values) rather than securitySchemes.
        return Err(issue(
            "credential template reads no secret; a credential that needs no \
             secret should not be a security scheme"
                .into(),
            format!("{path}.expr"),
        ));
    }
    for slot in &reads.slots {
        // A scheme always implicitly declares a slot named after itself, so a
        // single-secret credential needs no x-overslash-secrets entry at all.
        if slot != scheme_key && !declared_slots.iter().any(|d| d == slot) {
            return Err(issue(
                format!(
                    "credential template reads undeclared input `{slot}`; \
                     components.x-overslash-secrets declares: {}; \
                     components.x-overslash-config declares: {}",
                    join_or_none(declared_slots),
                    join_or_none(declared_config),
                ),
                format!("{path}.expr"),
            ));
        }
    }

    Ok((Some(template), reads))
}

fn join_or_none(keys: &[String]) -> String {
    if keys.is_empty() {
        "none".to_string()
    } else {
        keys.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::compile_service;
    use serde_json::json;

    // ── extract_auth ─────────────────────────────────────────────────

    #[test]
    fn auth_missing_components_yields_no_auth() {
        let doc = json!({"info": {"title": "T", "x-overslash-key": "t"}});
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.auth.is_empty());
    }

    #[test]
    fn auth_rejects_openid_connect() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://x/.well-known"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.path.ends_with(".type")),
            "got: {err:?}"
        );
    }

    #[test]
    fn auth_carries_scheme_keys_and_descriptions_in_sorted_order() {
        // Two apiKey schemes à la services/email.yaml: the securitySchemes map
        // KEY (`gateway`/`mailbox`) — not the header `name` — must ride into
        // `ServiceAuth::Secret.scheme`, in the deterministic sorted order the
        // dashboard's per-scheme credential rows key off.
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "mailbox": {
                    "type": "apiKey", "in": "header", "name": "X-Mailbox-Auth",
                    "description": "Per-mailbox IMAP/SMTP login.",
                    "x-overslash-default_secret_name": "mailbox_credential"
                },
                "gateway": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "x-overslash-label": "Overfwd API Token",
                    "x-overslash-template": {"lang": "jq", "expr": "\"Bearer \" + .gateway"},
                    "x-overslash-secret_source": "org",
                    "x-overslash-optional": true,
                    "x-overslash-default_secret_name": "overfwd_gateway_key"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.auth.len(), 2);
        match &svc.auth[0] {
            ServiceAuth::Secret {
                scheme,
                label,
                description,
                secret_source,
                optional,
                ..
            } => {
                assert_eq!(scheme, "gateway");
                assert_eq!(label, "Overfwd API Token");
                assert!(description.is_empty());
                assert_eq!(*secret_source, crate::types::SecretSource::Org);
                assert!(optional);
            }
            other => panic!("expected Secret, got {other:?}"),
        }
        match &svc.auth[1] {
            ServiceAuth::Secret {
                scheme,
                label,
                description,
                secret_source,
                injection,
                ..
            } => {
                assert_eq!(scheme, "mailbox");
                assert!(label.is_empty());
                assert_eq!(description, "Per-mailbox IMAP/SMTP login.");
                assert_eq!(*secret_source, crate::types::SecretSource::Instance);
                // The header name stays injection config — proves the scheme
                // key wasn't confused with the scheme object's `name` field.
                assert_eq!(injection.header_name.as_deref(), Some("X-Mailbox-Auth"));
            }
            other => panic!("expected Secret, got {other:?}"),
        }
    }

    #[test]
    fn auth_skips_non_object_scheme_value() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "junk": "string-value",
                "real": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "x-overslash-template": {"lang": "jq", "expr": "\"Bearer \" + .real"},
                    "x-overslash-default_secret_name": "svc_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.auth.len(), 1);
        assert!(matches!(svc.auth[0], ServiceAuth::Secret { .. }));
    }

    // ── credential slots + templates ─────────────────────────────────

    /// The services/email.yaml shape: two declared secrets joined into one
    /// header by a jq template.
    fn composed_mailbox_doc() -> serde_json::Value {
        json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {
                    "mailbox_user": {"label": "Mailbox username", "source": "instance"},
                    "mailbox_pass": {"label": "Mailbox password", "source": "instance"}
                },
                "securitySchemes": {"mailbox": {
                    "type": "apiKey", "in": "header", "name": "X-Mailbox-Auth",
                    "x-overslash-template": {
                        "lang": "jq",
                        "expr": "\"Basic \" + (.mailbox_user + \":\" + .mailbox_pass | @base64)"
                    }
                }}
            }
        })
    }

    #[test]
    fn composed_scheme_declares_its_slots() {
        let (svc, _) = compile_service(&composed_mailbox_doc()).unwrap();
        let ServiceAuth::Secret {
            slots,
            template,
            injection,
            ..
        } = &svc.auth[0]
        else {
            panic!("expected Secret");
        };
        // Slot order follows the expression, so the send path decrypts in the
        // order the header reads.
        assert_eq!(slots, &["mailbox_user", "mailbox_pass"]);
        assert!(template.is_some());
        assert_eq!(injection.header_name.as_deref(), Some("X-Mailbox-Auth"));

        // Declared slots keep their own labels; the scheme key is NOT a slot
        // here, because nothing reads it.
        let all = svc.all_slots();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].key, "mailbox_user");
        assert_eq!(all[0].label, "Mailbox username");
        assert!(!all.iter().any(|s| s.key == "mailbox"));
    }

    #[test]
    fn slots_are_sorted_for_determinism() {
        let (svc, _) = compile_service(&composed_mailbox_doc()).unwrap();
        let keys: Vec<&str> = svc.secrets.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(keys, ["mailbox_pass", "mailbox_user"]);
    }

    /// The property that makes static analysis worth having: a template with
    /// four declared secrets whose header names two reads exactly two.
    #[test]
    fn scheme_reads_only_the_slots_its_template_names() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {
                    "a": {}, "b": {}, "c": {}, "d": {}
                },
                "securitySchemes": {
                    "one": {
                        "type": "apiKey", "in": "header", "name": "X-One",
                        "x-overslash-template": {"lang": "jq", "expr": ".a + \":\" + .b"}
                    },
                    "two": {
                        "type": "apiKey", "in": "header", "name": "X-Two",
                        "x-overslash-template": {"lang": "jq", "expr": ".c + .d"}
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.slots_for(&svc.auth[0]).len(), 2);
        assert_eq!(
            svc.slots_for(&svc.auth[0])
                .iter()
                .map(|s| s.key.clone())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(svc.all_slots().len(), 4);
    }

    #[test]
    fn template_reading_undeclared_slot_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {"user": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": ".user + \":\" + .pass"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("undeclared input `pass`")),
            "got: {err:?}"
        );
    }

    #[test]
    fn declared_but_unread_slot_is_rejected() {
        // Dead config: the dashboard would ask for a secret that can never
        // reach a request.
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {"user": {}, "unused": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": ".user"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("`unused` is declared")),
            "got: {err:?}"
        );
    }

    /// The `services/email.yaml` shape: a non-secret username joined with a
    /// vaulted password. The username must NOT become a credential slot — that
    /// is the whole point — and must land on the definition as a config var.
    #[test]
    fn config_var_is_read_by_a_template_without_becoming_a_slot() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-config": {"mailbox_user": {
                    "label": "Mailbox username", "required": true
                }},
                "x-overslash-secrets": {"mailbox_pass": {"source": "instance"}},
                "securitySchemes": {"mailbox": {
                    "type": "apiKey", "in": "header", "name": "X-Mailbox-Auth",
                    "x-overslash-template": {
                        "lang": "jq",
                        "expr": "\"Basic \" + (.mailbox_user + \":\" + .mailbox_pass | @base64)"
                    }
                }}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();

        assert_eq!(
            svc.all_slots().iter().map(|s| &s.key).collect::<Vec<_>>(),
            ["mailbox_pass"],
            "the username must not be a vault slot"
        );
        assert_eq!(svc.config.len(), 1);
        assert_eq!(svc.config[0].key, "mailbox_user");
        assert_eq!(svc.config[0].label, "Mailbox username");
        assert!(svc.config[0].required);
        assert_eq!(
            svc.config_for(&svc.auth[0])
                .iter()
                .map(|c| c.key.clone())
                .collect::<Vec<_>>(),
            ["mailbox_user"]
        );
    }

    #[test]
    fn key_declared_as_both_secret_and_config_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-config": {"user": {}},
                "x-overslash-secrets": {"user": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": ".user + .cred"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("both a secret and a config value")),
            "got: {err:?}"
        );
    }

    #[test]
    fn declared_but_unread_config_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-config": {"unused": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred"
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("config `unused` is declared")),
            "got: {err:?}"
        );
    }

    /// A header built only from public values authenticates nobody; it belongs
    /// in `parameters` with `x-overslash-instance-config`, not in a scheme.
    #[test]
    fn template_reading_only_config_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-config": {"region": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": "\"r=\" + .region"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.message.contains("reads no secret")),
            "got: {err:?}"
        );
    }

    /// One `config` map on the instance, so one namespace: a config var and an
    /// instance-config param of the same name would be one form field feeding
    /// two unrelated consumers.
    #[test]
    fn config_var_colliding_with_an_instance_config_param_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "servers": [{"url": "https://api.example.com"}],
            "components": {
                "x-overslash-config": {"tenant": {}},
                "x-overslash-secrets": {"pass": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": ".tenant + .pass"}
                }}
            },
            "paths": {"/thing": {"get": {
                "operationId": "thing",
                "parameters": [{
                    "name": "tenant", "in": "header",
                    "x-overslash-instance-config": true,
                    "schema": {"type": "string"}
                }]
            }}}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("instance config is one namespace")),
            "got: {err:?}"
        );
    }

    #[test]
    fn template_with_dynamic_key_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {"user": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": "to_entries"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.message.contains("computed key")),
            "got: {err:?}"
        );
    }

    #[test]
    fn template_syntax_error_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {"cred": {
                "type": "apiKey", "in": "header", "name": "X-Cred",
                "x-overslash-template": {"lang": "jq", "expr": "\"unterminated"}
            }}}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.message.contains("invalid jq")),
            "got: {err:?}"
        );
    }

    #[test]
    fn unknown_template_lang_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {"cred": {
                "type": "apiKey", "in": "header", "name": "X-Cred",
                "x-overslash-template": {"lang": "handlebars", "expr": "{{user}}"}
            }}}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.message.contains("must be `jq`")),
            "got: {err:?}"
        );
    }

    #[test]
    fn removed_extensions_name_their_replacement() {
        // A template in the wild still carrying these would silently lose its
        // transform, so the error is the migration guide.
        for legacy in ["x-overslash-prefix", "x-overslash-encode"] {
            let doc = json!({
                "info": {"title": "T", "x-overslash-key": "t"},
                "components": {"securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    legacy: "Bearer ",
                    "x-overslash-default_secret_name": "k"
                }}}
            });
            let err = compile_service(&doc).unwrap_err();
            assert!(
                err.iter()
                    .any(|i| i.message.contains("x-overslash-template")),
                "{legacy} -> got: {err:?}"
            );
        }
    }

    #[test]
    fn template_less_scheme_keeps_its_implicit_slot() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {"token": {
                "type": "apiKey", "in": "header", "name": "X-Key",
                "x-overslash-label": "API key",
                "x-overslash-default_secret_name": "svc_key"
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let ServiceAuth::Secret {
            template, slots, ..
        } = &svc.auth[0]
        else {
            panic!("expected Secret");
        };
        assert!(template.is_none(), "no template means inject verbatim");
        assert_eq!(slots, &["token"]);
        let all = svc.all_slots();
        assert_eq!(all[0].key, "token");
        assert_eq!(all[0].label, "API key");
        assert_eq!(all[0].default_secret_name, "svc_key");
    }
}
