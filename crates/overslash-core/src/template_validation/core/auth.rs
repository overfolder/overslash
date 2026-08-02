use crate::template_validation::Issues;
use crate::types::{ServiceAuth, ServiceDefinition, TokenInjection};

// --- auth ------------------------------------------------------------------

pub(super) fn check_auth(def: &ServiceDefinition, issues: &mut Issues) {
    let mut seen_schemes: Vec<&str> = Vec::new();
    for (i, entry) in def.auth.iter().enumerate() {
        match entry {
            ServiceAuth::OAuth {
                provider,
                token_injection,
                ..
            } => {
                if provider.trim().is_empty() {
                    issues.err(
                        "missing_field",
                        "oauth provider is required",
                        format!("auth[{i}].provider"),
                    );
                }
                check_token_injection(
                    token_injection,
                    &format!("auth[{i}].token_injection"),
                    issues,
                );
            }
            ServiceAuth::Secret {
                scheme, injection, ..
            } => {
                // An org-source slot resolves ONLY through its default secret
                // name — with none, the credential can never be found. An
                // instance-source slot resolves from the instance's binding,
                // so it needs no default.
                for slot in def.slots_for(entry) {
                    if slot.source == crate::types::SecretSource::Org
                        && slot.default_secret_name.trim().is_empty()
                    {
                        issues.err(
                            "missing_field",
                            format!(
                                "secret `{}` is org-sourced and needs a default_secret_name \
                                 to resolve against the org vault",
                                slot.key
                            ),
                            format!("auth[{i}].default_secret_name"),
                        );
                    }
                }
                // Instances bind secrets per scheme key (`credentials[scheme]`),
                // so any number of secret schemes is fine — but the keys must be
                // unambiguous. Unique by construction when compiled from a
                // securitySchemes map; guard the programmatic construction paths.
                if !scheme.is_empty() {
                    if seen_schemes.contains(&scheme.as_str()) {
                        issues.err(
                            "duplicate_scheme_key",
                            format!(
                                "security scheme key {scheme:?} appears more than once; \
                                 per-instance credential bindings are keyed by scheme"
                            ),
                            format!("auth[{i}].scheme"),
                        );
                    }
                    seen_schemes.push(scheme.as_str());
                }
                check_token_injection(injection, &format!("auth[{i}].injection"), issues);
            }
        }
    }
}

fn check_token_injection(inj: &TokenInjection, base_path: &str, issues: &mut Issues) {
    match inj.inject_as.as_str() {
        "header" => {
            if inj.header_name.as_deref().unwrap_or("").trim().is_empty() {
                issues.err(
                    "incomplete_token_injection",
                    "token_injection with as=\"header\" requires header_name",
                    base_path.to_string(),
                );
            }
        }
        "query" => {
            if inj.query_param.as_deref().unwrap_or("").trim().is_empty() {
                issues.err(
                    "incomplete_token_injection",
                    "token_injection with as=\"query\" requires query_param",
                    base_path.to_string(),
                );
            }
        }
        other => {
            issues.err(
                "invalid_token_injection",
                format!("token_injection `as` must be \"header\" or \"query\" (got {other:?})"),
                format!("{base_path}.as"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::template_validation::core::tests::{minimal_valid, run};
    use crate::types::{SecretSource, ServiceAuth, TokenInjection};

    #[test]
    fn incomplete_token_injection_header() {
        let mut d = minimal_valid();
        d.auth = vec![ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            config_keys: Vec::new(),
            scheme: String::new(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: None,
                query_param: None,
                prefix: None,
            },
            secret_source: SecretSource::Instance,
            optional: false,
        }];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "incomplete_token_injection")
        );
    }

    #[test]
    fn incomplete_token_injection_query() {
        let mut d = minimal_valid();
        d.auth = vec![ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            config_keys: Vec::new(),
            scheme: String::new(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "query".into(),
                header_name: None,
                query_param: None,
                prefix: None,
            },
            secret_source: SecretSource::Instance,
            optional: false,
        }];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "incomplete_token_injection")
        );
    }

    fn secret(scheme: &str, source: SecretSource) -> ServiceAuth {
        ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            config_keys: Vec::new(),
            scheme: scheme.into(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: None,
            },
            secret_source: source,
            optional: false,
        }
    }

    #[test]
    fn several_instance_source_schemes_are_valid() {
        // Instances bind secrets per scheme key (`credentials[scheme]`), so a
        // template may declare any number of instance-source secret schemes —
        // the old `multiple_instance_secrets` scalar-storage rule is gone.
        let mut d = minimal_valid();
        d.auth = vec![
            secret("first", SecretSource::Instance),
            secret("second", SecretSource::Instance),
        ];
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn duplicate_scheme_keys_are_rejected() {
        let mut d = minimal_valid();
        d.auth = vec![
            secret("token", SecretSource::Instance),
            secret("token", SecretSource::Org),
        ];
        let r = run(&d);
        assert!(
            r.errors.iter().any(|e| e.code == "duplicate_scheme_key"),
            "errors: {:?}",
            r.errors
        );
    }
}
