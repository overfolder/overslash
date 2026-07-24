use crate::template_validation::Issues;
use crate::types::{ParamLocation, ServiceAction};

/// D42/D43 SQL-policy annotation rules. `x-overslash-sql-field` marks the
/// param carrying raw SQL, and its value is the dotted path of the SQL
/// string *within the assembled JSON body*. Two modes fall out of the
/// param's type:
/// - **string param** (placement mode): the assembler moves the value to
///   that body path (`native.query`); a path equal to the param name means
///   flat placement. Non-body-located params can only use their own name —
///   there is no body to nest into.
/// - **object param** (extraction mode): assembly is unchanged (the object
///   is placed flat at its name); the path points *inside* the param, so it
///   must have ≥2 segments and start with the param's own name
///   (`native.query` on param `native`).
///
/// Cross-param rules: at most one sql-field param per action; `risk:
/// dynamic` requires one (nothing to classify otherwise);
/// `x-overslash-sql-database` with no sql-field param on the action is inert
/// and almost certainly a mistake.
pub(super) fn check_sql_policy(action: &ServiceAction, action_path: &str, issues: &mut Issues) {
    let is_ident = |s: &str| {
        let mut chars = s.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };

    let sql_params: Vec<String> = {
        let mut v: Vec<String> = action
            .params
            .iter()
            .filter(|(_, p)| p.sql_field.is_some())
            .map(|(name, _)| name.clone())
            .collect();
        v.sort();
        v
    };

    if sql_params.len() > 1 {
        issues.err(
            "sql_param_ambiguous",
            format!(
                "only one param per action may set x-overslash-sql-field (got {sql_params:?}); \
                 the handler needs a single nominated query field"
            ),
            format!("{action_path}.params"),
        );
    }

    for name in &sql_params {
        let param = &action.params[name.as_str()];
        let param_path = format!("{action_path}.params.{name}");

        // Empty `param_type` is the "type unspecified" sentinel, treated as
        // a string param (placement mode).
        let is_object = param.param_type == "object";
        if !param.param_type.is_empty() && param.param_type != "string" && !is_object {
            issues.err(
                "sql_param_not_string",
                format!(
                    "x-overslash-sql-field param {name:?} must be a string (or an object the \
                     path points into) — got type {:?}",
                    param.param_type
                ),
                param_path.clone(),
            );
            continue;
        }

        let path = param.sql_field.as_deref().unwrap_or_default();
        if path.is_empty() || !path.split('.').all(is_ident) {
            issues.err(
                "invalid_sql_field",
                format!(
                    "x-overslash-sql-field {path:?} must be dotted identifier segments naming \
                     the SQL string's location in the JSON body (e.g. \"native.query\", or \
                     the param's own name for a flat string param)"
                ),
                param_path.clone(),
            );
            continue;
        }
        let segments: Vec<&str> = path.split('.').collect();
        let first = segments[0];

        if is_object {
            // Extraction mode: the path descends into the caller-supplied
            // object, so it must anchor at the param's flat body position.
            if first != name.as_str() || segments.len() < 2 {
                issues.err(
                    "invalid_sql_field",
                    format!(
                        "x-overslash-sql-field on object param {name:?} must point inside it: \
                         the path starts with the param name and names a nested field \
                         (e.g. \"{name}.query\") — got {path:?}"
                    ),
                    param_path.clone(),
                );
            }
            if param.location != ParamLocation::Body {
                issues.err(
                    "sql_field_not_body",
                    format!(
                        "object param {name:?} with x-overslash-sql-field must be body-located \
                         (got {:?})",
                        param.location
                    ),
                    param_path.clone(),
                );
            }
            continue;
        }

        // Placement mode (string param).
        if param.location != ParamLocation::Body && path != name.as_str() {
            issues.err(
                "sql_field_not_body",
                format!(
                    "param {name:?} is located {:?}, so x-overslash-sql-field cannot nest it \
                     into the body — use the param's own name",
                    param.location
                ),
                param_path.clone(),
            );
            continue;
        }

        // The nested insert and another param's flat insert must not fight
        // over one top-level key in the assembled body.
        let collides = action.params.iter().any(|(other_name, other)| {
            other_name.as_str() != name.as_str()
                && other.location == ParamLocation::Body
                && other.sql_field.is_none()
                && other_name == first
        });
        if collides {
            issues.err(
                "sql_field_collision",
                format!(
                    "x-overslash-sql-field {path:?} on param {name:?} collides with the \
                     declared body param {first:?}"
                ),
                param_path,
            );
        }
    }

    if action.risk.is_dynamic() && sql_params.is_empty() {
        issues.err(
            "dynamic_risk_without_sql",
            "risk: dynamic requires an x-overslash-sql-field param — without a nominated \
             query field there is nothing to classify per call",
            format!("{action_path}.risk"),
        );
    }

    if sql_params.is_empty() {
        for (name, param) in &action.params {
            if param.sql_database.is_some() {
                issues.warn(
                    "sql_database_without_sql",
                    format!(
                        "param {name:?} sets x-overslash-sql-database but no param on this \
                         action sets x-overslash-sql-field — the expression is never evaluated"
                    ),
                    format!("{action_path}.params.{name}"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::template_validation::core::tests::{minimal_valid, param, run};
    use crate::types::{ActionParam, DeclaredRisk, ServiceDefinition};

    // ── D42/D43 sql-field / dynamic-risk rules ──────────────────────────

    fn sql_param(ty: &str, sql_field: &str) -> ActionParam {
        let mut p = param(ty, true);
        p.sql_field = Some(sql_field.into());
        p
    }

    fn def_with_sql_action(
        risk: DeclaredRisk,
        params: Vec<(&str, ActionParam)>,
    ) -> ServiceDefinition {
        let mut d = minimal_valid();
        let action = d.actions.get_mut("list").unwrap();
        action.method = "POST".into();
        action.risk = risk;
        action.params = params
            .into_iter()
            .map(|(n, p)| (n.to_string(), p))
            .collect();
        d
    }

    #[test]
    fn sql_field_happy_paths_validate_clean() {
        // Placement mode: flat string param nested into the body.
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![("query", sql_param("string", "native.query"))],
        );
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);

        // Placement mode: path == own name (flat body).
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![("query", sql_param("string", "query"))],
        );
        assert!(run(&d).valid);

        // Extraction mode: object param, path points inside it.
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![("native", sql_param("object", "native.query"))],
        );
        assert!(run(&d).valid);
    }

    #[test]
    fn dynamic_risk_requires_a_sql_param() {
        let d = def_with_sql_action(DeclaredRisk::Dynamic, vec![("q", param("string", false))]);
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "dynamic_risk_without_sql")
        );
    }

    #[test]
    fn two_sql_params_are_ambiguous() {
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![
                ("a", sql_param("string", "a")),
                ("b", sql_param("string", "b")),
            ],
        );
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "sql_param_ambiguous"));
    }

    #[test]
    fn sql_param_must_be_string_or_object() {
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![("n", sql_param("integer", "n"))],
        );
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "sql_param_not_string"));
    }

    #[test]
    fn sql_field_path_shape_is_checked() {
        for bad in ["", "a..b", "native.qu ery", "1x.y"] {
            let d = def_with_sql_action(
                DeclaredRisk::Dynamic,
                vec![("query", sql_param("string", bad))],
            );
            let r = run(&d);
            assert!(
                r.errors.iter().any(|e| e.code == "invalid_sql_field"),
                "path {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn object_mode_path_must_anchor_at_the_param() {
        // Path not starting with the param name.
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![("native", sql_param("object", "other.query"))],
        );
        assert!(run(&d).errors.iter().any(|e| e.code == "invalid_sql_field"));
        // Path with no nested segment.
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![("native", sql_param("object", "native"))],
        );
        assert!(run(&d).errors.iter().any(|e| e.code == "invalid_sql_field"));
    }

    #[test]
    fn sql_field_nesting_collision_is_rejected() {
        // `query` nests under `native.…` while a flat `native` body param
        // also exists — the two would fight over one body key.
        let d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![
                ("query", sql_param("string", "native.query")),
                ("native", param("object", false)),
            ],
        );
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "sql_field_collision"));
    }

    #[test]
    fn non_body_sql_param_cannot_nest() {
        let mut p = sql_param("string", "native.query");
        p.location = crate::types::ParamLocation::Query;
        let d = def_with_sql_action(DeclaredRisk::Dynamic, vec![("q", p)]);
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "sql_field_not_body"));

        // …but its own name is fine.
        let mut p = sql_param("string", "q");
        p.location = crate::types::ParamLocation::Query;
        let d = def_with_sql_action(DeclaredRisk::Dynamic, vec![("q", p)]);
        assert!(run(&d).valid);
    }

    #[test]
    fn sql_database_without_sql_field_warns() {
        let mut p = param("integer", true);
        p.sql_database = Some(".database | tostring".into());
        let d = def_with_sql_action(DeclaredRisk::Read, vec![("database", p)]);
        let r = run(&d);
        assert!(r.valid, "warning, not error: {:?}", r.errors);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "sql_database_without_sql")
        );
    }

    #[test]
    fn dynamic_risk_skips_method_plausibility() {
        // GET + dynamic must not trip the read-only-method warning.
        let mut d = def_with_sql_action(
            DeclaredRisk::Dynamic,
            vec![("q", {
                let mut p = sql_param("string", "q");
                p.location = crate::types::ParamLocation::Query;
                p
            })],
        );
        d.actions.get_mut("list").unwrap().method = "GET".into();
        let r = run(&d);
        assert!(
            !r.warnings.iter().any(|w| w.code == "risk_method_mismatch"),
            "{:?}",
            r.warnings
        );
    }
}
