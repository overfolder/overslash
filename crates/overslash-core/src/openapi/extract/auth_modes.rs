//! `components.x-overslash-auth-modes` — the alternative credential kinds a
//! template accepts, of which an instance picks exactly one at creation.

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
