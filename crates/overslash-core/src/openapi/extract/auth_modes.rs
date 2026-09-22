//! `components.x-overslash-auth-modes` — the alternative credential kinds a
//! template accepts, of which an instance picks exactly one at creation.
//!
//! Prefixed spelling only, matching its `components` siblings
//! `x-overslash-secrets` and `x-overslash-config`: `alias.rs` rewrites
//! unprefixed forms at the root, `info`, operation, parameter and
//! security-scheme positions, and deliberately not here.

use serde_json::Value;

use crate::template_validation::ValidationIssue;
use crate::types::{AuthMode, ServiceAuth};

use super::super::ext::{self, Ext, Pos};

/// Parse `components.x-overslash-auth-modes` — the alternative credential
/// kinds an instance picks between at creation.
///
/// Absent is the overwhelmingly common case and means "no alternation": every
/// declared scheme applies at once, which is what `services/email.yaml`'s
/// gateway-plus-mailbox pair has always meant. The empty vec says that, and
/// `ServiceDefinition::auth_modes` synthesizes the single implicit mode rather
/// than making every caller special-case it.
pub(super) fn extract_auth_modes(
    components: Option<&Value>,
    auth: &[ServiceAuth],
) -> Result<Vec<AuthMode>, Vec<ValidationIssue>> {
    const BASE: &str = "components.x-overslash-auth-modes";

    let Some(raw) = components
        .and_then(Value::as_object)
        .and_then(|c| ext::get(c, Pos::Components, Ext::AuthModes))
    else {
        return Ok(Vec::new());
    };
    let Some(map) = raw.as_object() else {
        return Err(vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            "x-overslash-auth-modes must be a map of mode key to declaration",
            BASE,
        )]);
    };
    if map.is_empty() {
        return Err(vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            "x-overslash-auth-modes declares no modes; omit the block instead",
            BASE,
        )]);
    }

    let declared: Vec<&str> = auth.iter().map(scheme_key).collect();
    let mut out: Vec<AuthMode> = Vec::new();
    let mut errors = Vec::new();

    // Deterministic order so the dashboard's picker and our snapshots agree;
    // `default` decides which one is preselected, never position.
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let at = format!("{BASE}.{key}");
        let Some(obj) = map[key].as_object() else {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("auth mode `{key}` must be an object"),
                at,
            ));
            continue;
        };
        if key.trim().is_empty() {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                "an auth mode key must not be empty",
                at,
            ));
            continue;
        }

        let schemes: Vec<String> = match obj.get("schemes") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(_) => {
                errors.push(ValidationIssue::new(
                    "openapi_unsupported_construct",
                    format!("auth mode `{key}`'s `schemes` must be an array of scheme keys"),
                    format!("{at}.schemes"),
                ));
                continue;
            }
            // A mode that names no schemes selects no credential, so a call
            // under it would authenticate as nobody.
            None => {
                errors.push(ValidationIssue::new(
                    "openapi_unsupported_construct",
                    format!("auth mode `{key}` must name at least one scheme in `schemes`"),
                    format!("{at}.schemes"),
                ));
                continue;
            }
        };
        if schemes.is_empty() {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("auth mode `{key}` must name at least one scheme in `schemes`"),
                format!("{at}.schemes"),
            ));
            continue;
        }
        for scheme in &schemes {
            if !declared.contains(&scheme.as_str()) {
                errors.push(ValidationIssue::new(
                    "openapi_unsupported_construct",
                    format!(
                        "auth mode `{key}` names security scheme `{scheme}`, \
                         which the template does not declare"
                    ),
                    format!("{at}.schemes"),
                ));
            }
        }
        // Two OAuth schemes in one mode is two providers for one request, and
        // nothing downstream chooses between them.
        let oauth_count = auth
            .iter()
            .filter(|a| {
                matches!(a, ServiceAuth::OAuth { .. }) && schemes.iter().any(|s| s == scheme_key(a))
            })
            .count();
        if oauth_count > 1 {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("auth mode `{key}` names {oauth_count} OAuth schemes; a mode resolves at most one"),
                format!("{at}.schemes"),
            ));
        }

        out.push(AuthMode {
            key: key.clone(),
            label: obj
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            description: obj
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            schemes,
            default: obj.get("default").and_then(Value::as_bool).unwrap_or(false),
        });
    }

    // A scheme in no mode is a credential the dashboard can collect and no
    // request will ever carry.
    for scheme in &declared {
        if !out.iter().any(|m| m.schemes.iter().any(|s| s == scheme)) {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("security scheme `{scheme}` belongs to no auth mode, so nothing can ever inject it"),
                format!("components.securitySchemes.{scheme}"),
            ));
        }
    }

    // With alternatives on the table, which one a create resolves to cannot be
    // left to map order.
    let defaults = out.iter().filter(|m| m.default).count();
    if out.len() > 1 && defaults != 1 {
        errors.push(ValidationIssue::new(
            "openapi_unsupported_construct",
            format!(
                "a template declaring several auth modes must mark exactly one `default: true` (found {defaults})"
            ),
            BASE,
        ));
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// The `securitySchemes` key an entry was compiled from, for both variants.
pub(crate) fn scheme_key(auth: &ServiceAuth) -> &str {
    match auth {
        ServiceAuth::OAuth { scheme, .. } | ServiceAuth::Secret { scheme, .. } => scheme,
    }
}

#[cfg(test)]
mod tests {
    use super::super::auth::extract_auth;
    use serde_json::json;

    /// Two schemes, two modes — the shape `services/figma.yaml` ships.
    fn dual_mode() -> serde_json::Value {
        json!({
            "x-overslash-auth-modes": {
                "oauth": {"label": "Sign in", "default": true, "schemes": ["oauth"]},
                "token": {"label": "API token", "schemes": ["token"]},
            },
            "securitySchemes": {
                "oauth": {"type": "oauth2", "x-overslash-provider": "figma", "flows": {}},
                "token": {
                    "type": "apiKey", "in": "header", "name": "X-Figma-Token",
                    "x-overslash-default_secret_name": "figma_pat",
                },
            },
        })
    }

    #[test]
    fn modes_compile_and_name_their_schemes() {
        let creds = extract_auth(Some(&dual_mode())).expect("should compile");
        let modes = &creds.auth_modes;
        assert_eq!(
            modes.iter().map(|m| m.key.as_str()).collect::<Vec<_>>(),
            ["oauth", "token"]
        );
        assert!(modes[0].default);
        assert!(!modes[1].default);
        assert_eq!(modes[1].schemes, ["token"]);
        assert_eq!(modes[0].label, "Sign in");
    }

    /// The OAuth entry has to carry the `securitySchemes` key it came from, or
    /// a mode could never select it — `Secret` always did, `OAuth` did not.
    #[test]
    fn the_oauth_entry_remembers_its_scheme_key() {
        let creds = extract_auth(Some(&dual_mode())).expect("should compile");
        let oauth = creds
            .auth
            .iter()
            .find(|a| matches!(a, crate::types::ServiceAuth::OAuth { .. }))
            .expect("oauth entry missing");
        assert_eq!(super::scheme_key(oauth), "oauth");
    }

    /// Absent means "no alternation" — every scheme, together. This is the
    /// reading `services/email.yaml` depends on, so it must survive untouched.
    #[test]
    fn a_template_without_the_block_declares_no_modes() {
        let mut doc = dual_mode();
        doc.as_object_mut()
            .unwrap()
            .remove("x-overslash-auth-modes");
        let creds = extract_auth(Some(&doc)).expect("should compile");
        assert!(
            creds.auth_modes.is_empty(),
            "no block must mean no alternation, not an invented one"
        );
    }

    #[test]
    fn a_mode_naming_an_undeclared_scheme_is_an_error() {
        let mut doc = dual_mode();
        doc["x-overslash-auth-modes"]["token"]["schemes"] = json!(["nope"]);
        let errs = extract_auth(Some(&doc)).expect_err("should not compile");
        assert!(
            errs.iter().any(|e| e.message.contains("does not declare")),
            "{errs:?}"
        );
    }

    /// A scheme in no mode is a credential the dashboard collects and no
    /// request ever carries.
    #[test]
    fn a_scheme_in_no_mode_is_an_error() {
        let mut doc = dual_mode();
        doc["x-overslash-auth-modes"]
            .as_object_mut()
            .unwrap()
            .remove("token");
        doc["x-overslash-auth-modes"]["oauth"]["default"] = json!(true);
        let errs = extract_auth(Some(&doc)).expect_err("should not compile");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("belongs to no auth mode")),
            "{errs:?}"
        );
    }

    /// Map order is not an ordering, so "which mode does a bare create get"
    /// cannot be left to it.
    #[test]
    fn several_modes_need_exactly_one_default() {
        let mut doc = dual_mode();
        doc["x-overslash-auth-modes"]["token"]["default"] = json!(true);
        let errs = extract_auth(Some(&doc)).expect_err("two defaults should not compile");
        assert!(
            errs.iter().any(|e| e.message.contains("exactly one")),
            "{errs:?}"
        );

        let mut doc = dual_mode();
        doc["x-overslash-auth-modes"]["oauth"]["default"] = json!(false);
        let errs = extract_auth(Some(&doc)).expect_err("no default should not compile");
        assert!(
            errs.iter().any(|e| e.message.contains("exactly one")),
            "{errs:?}"
        );
    }

    #[test]
    fn a_mode_naming_no_schemes_is_an_error() {
        let mut doc = dual_mode();
        doc["x-overslash-auth-modes"]["token"]["schemes"] = json!([]);
        let errs = extract_auth(Some(&doc)).expect_err("should not compile");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("at least one scheme")),
            "{errs:?}"
        );
    }

    /// Two OAuth schemes in one mode is two providers for one request, and
    /// nothing downstream chooses between them.
    #[test]
    fn a_mode_with_two_oauth_schemes_is_an_error() {
        let doc = json!({
            "x-overslash-auth-modes": {
                "both": {"schemes": ["a", "b"]},
            },
            "securitySchemes": {
                "a": {"type": "oauth2", "x-overslash-provider": "one", "flows": {}},
                "b": {"type": "oauth2", "x-overslash-provider": "two", "flows": {}},
            },
        });
        let errs = extract_auth(Some(&doc)).expect_err("should not compile");
        assert!(
            errs.iter().any(|e| e.message.contains("OAuth schemes")),
            "{errs:?}"
        );
    }
}
