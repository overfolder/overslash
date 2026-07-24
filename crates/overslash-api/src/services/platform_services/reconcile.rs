//! Credential-slot reconciliation and per-instance config validation, shared
//! by the create and update kernels.

use super::*;

// ── Helpers ───────────────────────────────────────────────────────────────

/// The template's credential slot keys whose fallback is the instance's legacy
/// scalar `secret_name` (i.e. `source: instance`). Empty keys
/// (programmatically-built templates) are skipped — they can't key a binding.
pub(super) fn instance_slot_keys(template: &ServiceDefinition) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for slot in template.all_slots() {
        if slot.source == SecretSource::Instance && !slot.key.is_empty() && !out.contains(&slot.key)
        {
            out.push(slot.key);
        }
    }
    out
}

/// Every credential slot key the template declares, in `auth` order.
fn all_slot_keys(template: &ServiceDefinition) -> Vec<String> {
    template
        .all_slots()
        .into_iter()
        .map(|s| s.key)
        .filter(|k| !k.is_empty())
        .collect()
}

/// Validate a per-instance `config` map against the template.
///
/// The rules themselves live in `overslash_core::instance_config`, shared with
/// the layer write path — an org layer supplying `instance_defaults.config`
/// must accept exactly the same keys an instance may pin. This wrapper only
/// renders the outcome as an `AppError`.
pub(super) fn validate_instance_config(
    template: &ServiceDefinition,
    explicit: Option<&ConfigMap>,
) -> Result<ConfigMap, AppError> {
    let Some(explicit) = explicit else {
        return Ok(ConfigMap::new());
    };
    overslash_core::instance_config::validate_config(template, explicit)
        .map_err(|e| AppError::BadRequest(e.message(&template.key)))
}

/// Reconcile explicit per-slot `credentials` with the legacy scalar
/// `secret_name` alias into the map to store, validating both against the
/// template.
///
/// - Every explicit key must name one of the template's credential slots, and
///   every value must be non-empty (whole-map replace: omit a key to unbind).
/// - A non-empty `secret_name` folds into the sole instance-source slot.
///   With several instance-source slots the alias is ambiguous → 400. With
///   none (MCP bearer) it stays scalar-only and the map is untouched.
/// - Both provided with different values for the same slot → 400.
///
/// Returns `(credentials_to_store, secret_name_to_store)`. The scalar is kept
/// mirrored (dual-write) so binaries from the previous release keep resolving
/// during a rolling deploy; it is dropped once the column goes.
pub(super) fn reconcile_credentials(
    template: &ServiceDefinition,
    explicit: Option<&CredentialsMap>,
    legacy_secret_name: Option<&str>,
) -> Result<(CredentialsMap, Option<String>), AppError> {
    let slot_keys = all_slot_keys(template);
    let instance_slots = instance_slot_keys(template);

    let mut map = CredentialsMap::new();
    if let Some(explicit) = explicit {
        for (key, value) in explicit {
            if !slot_keys.contains(key) {
                // A key that is now a config var is the shape of a template
                // that stopped vaulting a value (the `email` mailbox username).
                // Saying only "unknown credential" would leave the operator
                // hunting; this is the one message they get.
                if template.config.iter().any(|c| &c.key == key) {
                    return Err(AppError::BadRequest(format!(
                        "'{key}' is no longer a credential on template '{}'; it is a \
                         plain config value — move it from `credentials` to `config`",
                        template.key
                    )));
                }
                return Err(AppError::BadRequest(format!(
                    "unknown credential '{key}'; template '{}' declares: {}",
                    template.key,
                    if slot_keys.is_empty() {
                        "none".to_string()
                    } else {
                        slot_keys.join(", ")
                    }
                )));
            }
            if value.trim().is_empty() {
                return Err(AppError::BadRequest(format!(
                    "credential '{key}' must name a secret; omit the key to unbind it"
                )));
            }
            map.insert(key.clone(), value.clone());
        }
    }

    let legacy = legacy_secret_name.filter(|s| !s.is_empty());
    if let Some(legacy) = legacy {
        match instance_slots.as_slice() {
            [] => {} // MCP bearer / legacy scalar-only template: stays scalar.
            [sole] => match map.get(sole) {
                Some(bound) if bound != legacy => {
                    return Err(AppError::BadRequest(format!(
                        "secret_name '{legacy}' conflicts with credentials['{sole}'] = '{bound}'; \
                         pass one or the other"
                    )));
                }
                _ => {
                    map.insert(sole.clone(), legacy.to_string());
                }
            },
            _ => {
                return Err(AppError::BadRequest(format!(
                    "template '{}' declares several instance credentials ({}); \
                     bind them via `credentials` instead of `secret_name`",
                    template.key,
                    instance_slots.join(", ")
                )));
            }
        }
    }

    // Dual-write the scalar: mirror the sole instance-source slot's binding
    // (whatever provided it), else preserve a scalar-only legacy value.
    let secret_name = match instance_slots.as_slice() {
        [sole] => map.get(sole).cloned(),
        _ => legacy.map(str::to_string),
    };
    Ok((map, secret_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::platform_services::test_fixtures::*;

    // ── reconcile_credentials ────────────────────────────────────────

    #[test]
    fn reconcile_rejects_unknown_scheme_and_empty_value() {
        let tpl = dual_scheme_template();
        let unknown = CredentialsMap::from([("gatway".to_string(), "x".to_string())]);
        assert!(reconcile_credentials(&tpl, Some(&unknown), None).is_err());
        let blank = CredentialsMap::from([("mailbox".to_string(), "  ".to_string())]);
        assert!(reconcile_credentials(&tpl, Some(&blank), None).is_err());
    }

    #[test]
    fn reconcile_folds_legacy_scalar_into_sole_instance_slot_and_mirrors_it() {
        let tpl = dual_scheme_template();
        let (map, scalar) = reconcile_credentials(&tpl, None, Some("my_login")).unwrap();
        assert_eq!(map.get("mailbox").map(String::as_str), Some("my_login"));
        assert_eq!(scalar.as_deref(), Some("my_login"));
        // Map binding wins the mirror when both agree; a disagreement is a 400.
        let explicit = CredentialsMap::from([("mailbox".to_string(), "my_login".to_string())]);
        assert!(reconcile_credentials(&tpl, Some(&explicit), Some("my_login")).is_ok());
        assert!(reconcile_credentials(&tpl, Some(&explicit), Some("other")).is_err());
    }

    #[test]
    fn reconcile_rejects_scalar_alias_when_several_instance_slots_exist() {
        let mut tpl = dual_scheme_template();
        if let ServiceAuth::Secret {
            secret_source,
            optional,
            ..
        } = &mut tpl.auth[0]
        {
            *secret_source = overslash_core::types::SecretSource::Instance;
            *optional = false;
        }
        assert!(reconcile_credentials(&tpl, None, Some("ambiguous")).is_err());
        // …but per-scheme bindings work, and no scalar is mirrored (it would
        // be ambiguous for old readers).
        let both = CredentialsMap::from([
            ("gateway".to_string(), "gw".to_string()),
            ("mailbox".to_string(), "mb".to_string()),
        ]);
        let (map, scalar) = reconcile_credentials(&tpl, Some(&both), None).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(scalar, None);
    }
}
