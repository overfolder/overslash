//! YAML entry point — backs `POST /v1/templates/validate`.
//!
//! Accepts OpenAPI 3.1 YAML text with `x-overslash-*` vendor extensions (plus
//! their convenience aliases — see `crate::openapi`). Parses, normalizes, and
//! compiles into a `ServiceDefinition`, then runs the struct-level validator.
//!
//! The endpoint never returns a transport-level error for malformed YAML: all
//! parse errors, alias ambiguities, and compile-time rejections surface as
//! structured `ValidationIssue`s so the dashboard editor can render them
//! inline on every keystroke.

use crate::openapi;
use crate::template_vars::{self, Vars};
use crate::types::ServiceDefinition;

use super::{Issues, ValidationIssue, ValidationReport, core::validate_service_definition};

/// Expand `${VAR}` references into a **copy** of the document, for compiling.
///
/// The copy matters: the persisted document must keep its references intact.
/// Storing an expanded doc would bake whichever host the *authoring*
/// deployment happened to have into the row forever, which is the drift this
/// mechanism removes rather than relocates.
fn expanded_for_compile(
    doc: &serde_json::Value,
    vars: &Vars,
) -> Result<serde_json::Value, Vec<crate::template_validation::ValidationIssue>> {
    let mut copy = doc.clone();
    template_vars::expand(&mut copy, vars)?;
    Ok(copy)
}

/// Alias-normalize `doc` in place, then run every check that operates on the raw
/// *document* rather than the compiled definition: duplicate `operationId`s
/// (errors) and the extension lint (warnings).
///
/// One function rather than three copies, because the last source-level check to
/// arrive — `check_duplicate_operation_ids` — had to be added to each entry point
/// by hand, and a fourth landing in two of the three would be invisible.
///
/// Returns `(errors, warnings)`. The lint deliberately produces only warnings:
/// see [`crate::openapi::lint`].
fn normalize_and_lint_source(
    doc: &mut serde_json::Value,
) -> (Vec<ValidationIssue>, Vec<ValidationIssue>) {
    let mut errors = openapi::normalize_aliases(doc);

    // An ambiguous or unparseable document makes the lint's position map
    // unreliable, and its findings would only bury the real error.
    if !errors.is_empty() {
        return (errors, Vec::new());
    }

    let mut dup = Issues::default();
    check_duplicate_operation_ids(doc, &mut dup);
    errors.extend(dup.finish().errors);

    (errors, openapi::lint_extensions(doc))
}

/// Parse OpenAPI YAML source and validate the resulting service definition.
///
/// Always returns a `ValidationReport`. A parse error becomes a single
/// issue in the report (`openapi_parse_error`, `ambiguous_alias`,
/// `duplicate_operation_id`, or whatever the compiler surfaces) rather than
/// a transport error.
pub fn validate_template_yaml(source: &str, vars: &Vars) -> ValidationReport {
    // Pass 1: detect duplicate YAML mapping keys (shipped serde_yaml rejects
    // them at parse time and we surface them as structured issues).
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(source) {
        let msg = e.to_string();
        let mut issues = Issues::default();
        issues.err("yaml_parse", format!("could not parse YAML: {msg}"), "");
        return issues.finish();
    }

    // Pass 2: parse → normalize → compile through the openapi pipeline.
    let mut doc = match openapi::parse_yaml(source) {
        Ok(d) => d,
        Err(issue) => {
            let mut issues = Issues::default();
            issues.err(issue.code, issue.message, issue.path);
            return issues.finish();
        }
    };

    // Source-level checks: alias ambiguity and duplicate operationIds (errors),
    // and the extension lint (warnings). OpenAPI allows the same operationId in
    // different operations, but that is a collision for our action-key model.
    let (src_errors, lint_warnings) = normalize_and_lint_source(&mut doc);
    if !src_errors.is_empty() {
        let mut issues = Issues::default();
        for i in src_errors {
            issues.err(i.code, i.message, i.path);
        }
        return issues.finish();
    }

    let compile_doc = match expanded_for_compile(&doc, vars) {
        Ok(d) => d,
        Err(errors) => {
            let mut issues = Issues::default();
            for i in errors {
                issues.err(i.code, i.message, i.path);
            }
            return issues.finish();
        }
    };

    let def = match openapi::compile_service(&compile_doc) {
        Ok((def, _warnings)) => def,
        Err(errors) => {
            let mut issues = Issues::default();
            for i in errors {
                issues.err(i.code, i.message, i.path);
            }
            return issues.finish();
        }
    };

    let mut report = validate_service_definition(&def, &[]);
    report.warnings.extend(lint_warnings);
    report
}

/// Parse + alias-normalize + compile + validate an OpenAPI YAML source for
/// persistence. On success returns the normalized canonical `serde_json::Value`
/// (alias-free — suitable for storing in the DB) and the compiled
/// [`ServiceDefinition`]. On failure returns a structured `ValidationReport`
/// so the caller can surface it back to the client as-is.
///
/// The returned document keeps its `${VAR}` references **unexpanded**; only
/// the definition compiled alongside it sees resolved values.
pub fn parse_normalize_compile_yaml(
    source: &str,
    vars: &Vars,
) -> std::result::Result<(serde_json::Value, ServiceDefinition), ValidationReport> {
    let mut issues = Issues::default();

    // Raw YAML syntax pass first (serde_yaml catches duplicate mapping keys).
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(source) {
        issues.err("yaml_parse", format!("could not parse YAML: {e}"), "");
        return Err(issues.finish());
    }

    let mut doc = match openapi::parse_yaml(source) {
        Ok(d) => d,
        Err(i) => {
            issues.err(i.code, i.message, i.path);
            return Err(issues.finish());
        }
    };

    // Lint findings are deliberately dropped on this path: it returns only the
    // compiled pair on success, and its callers (template create/update) have
    // nowhere to put a warning — `TemplateDetail` carries no warnings field. The
    // author has already seen them, because the editor polls
    // `validate_template_yaml` on every keystroke, and `template_resolve`
    // re-reports them against the stored row. A decision, not an oversight.
    let (src_errors, _lint_warnings) = normalize_and_lint_source(&mut doc);
    if !src_errors.is_empty() {
        for i in src_errors {
            issues.err(i.code, i.message, i.path);
        }
        return Err(issues.finish());
    }

    let compile_doc = match expanded_for_compile(&doc, vars) {
        Ok(d) => d,
        Err(errors) => {
            for i in errors {
                issues.err(i.code, i.message, i.path);
            }
            return Err(issues.finish());
        }
    };

    let def = match openapi::compile_service(&compile_doc) {
        Ok((def, _warnings)) => def,
        Err(errors) => {
            for i in errors {
                issues.err(i.code, i.message, i.path);
            }
            return Err(issues.finish());
        }
    };

    let report = validate_service_definition(&def, &[]);
    if !report.valid {
        return Err(report);
    }

    Ok((doc, def))
}

/// Lenient variant of [`parse_normalize_compile_yaml`] that operates on an
/// already-parsed `serde_json::Value` (the output of the import pipeline) and
/// never returns a transport-level error. The caller gets back:
///  - the canonical document (alias-normalized, with any available compile
///    fix-ups applied; stored as-is to the DB for drafts),
///  - the compiled [`ServiceDefinition`] if the document was well-formed
///    enough to compile, or `None` if it wasn't,
///  - a [`ValidationReport`] describing what's still wrong.
///
/// This is the entry point used by `POST /v1/templates/import`: drafts can
/// legitimately persist with validation errors because the user intends to
/// fix them in the editor before promoting. `POST
/// /v1/templates/drafts/{id}/promote` re-runs `parse_normalize_compile_yaml`
/// against the edited source and rejects promotion if it still has errors.
pub fn prepare_draft_from_value(
    mut doc: serde_json::Value,
    vars: &Vars,
) -> (
    serde_json::Value,
    Option<ServiceDefinition>,
    ValidationReport,
) {
    let mut issues = Issues::default();

    let (src_errors, lint_warnings) = normalize_and_lint_source(&mut doc);
    for i in src_errors {
        issues.err(i.code, i.message, i.path);
    }
    for w in lint_warnings {
        issues.warn(w.code, w.message, w.path);
    }

    // A draft may legitimately reference a variable this deployment has not
    // set — the author is mid-edit. Report it like any other error and skip
    // compiling, rather than compiling against a half-expanded document.
    let compiled = match expanded_for_compile(&doc, vars) {
        Err(errors) => {
            for i in errors {
                issues.err(i.code, i.message, i.path);
            }
            None
        }
        Ok(compile_doc) => match crate::openapi::compile_service(&compile_doc) {
            Ok((def, _warnings)) => Some(def),
            Err(errors) => {
                for i in errors {
                    issues.err(i.code, i.message, i.path);
                }
                None
            }
        },
    };

    // Struct-level linting: only meaningful when compile succeeded.
    if let Some(ref def) = compiled {
        let struct_report = validate_service_definition(def, &[]);
        for e in struct_report.errors {
            issues.err(e.code, e.message, e.path);
        }
        for w in struct_report.warnings {
            issues.warn(w.code, w.message, w.path);
        }
    }

    (doc, compiled, issues.finish())
}

fn check_duplicate_operation_ids(doc: &serde_json::Value, issues: &mut Issues) {
    let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) else {
        return;
    };
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    const METHODS: &[&str] = &[
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ];
    for (path_key, path_item) in paths {
        let Some(obj) = path_item.as_object() else {
            continue;
        };
        for m in METHODS {
            let Some(op) = obj.get(*m).and_then(|v| v.as_object()) else {
                continue;
            };
            let Some(op_id) = op.get("operationId").and_then(|v| v.as_str()) else {
                continue;
            };
            let here = format!("paths.{path_key}.{m}.operationId");
            if let Some(first) = seen.get(op_id) {
                issues.err(
                    "duplicate_operation_id",
                    format!(
                        "operationId {op_id:?} is used in multiple operations ({first} and {here})"
                    ),
                    here,
                );
            } else {
                seen.insert(op_id.to_string(), here);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
openapi: 3.1.0
info:
  title: Service
  key: svc
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    token:
      type: apiKey
      in: header
      name: Authorization
      template:
        lang: jq
        expr: '"Bearer " + .token'
      default_secret_name: svc_token
paths:
  /items:
    get:
      operationId: list
      summary: List items
      risk: read
"#;

    #[test]
    fn valid_yaml_parses_clean() {
        let report = validate_template_yaml(VALID_YAML, &crate::template_vars::Vars::for_tests());
        assert!(report.valid, "errors: {:?}", report.errors);
    }

    #[test]
    fn yaml_parse_error_surfaces_as_issue() {
        let report = validate_template_yaml(
            "key: svc\n  bad_indent: :::",
            &crate::template_vars::Vars::for_tests(),
        );
        assert!(!report.valid);
        assert_eq!(report.errors[0].code, "yaml_parse");
    }

    #[test]
    fn ambiguous_alias_reported() {
        let src = r#"
openapi: 3.1.0
info:
  title: Svc
  key: svc
  x-overslash-key: svc
servers:
  - url: https://api.example.com
"#;
        let report = validate_template_yaml(src, &crate::template_vars::Vars::for_tests());
        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|e| e.code == "ambiguous_alias"),
            "expected ambiguous_alias error; got {:?}",
            report.errors
        );
    }

    #[test]
    fn duplicate_operation_id_reported() {
        let src = r#"
openapi: 3.1.0
info:
  title: Svc
  key: svc
servers:
  - url: https://api.example.com
paths:
  /a:
    get:
      operationId: same
      summary: a
  /b:
    get:
      operationId: same
      summary: b
"#;
        let report = validate_template_yaml(src, &crate::template_vars::Vars::for_tests());
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "duplicate_operation_id"),
            "expected duplicate_operation_id; got {:?}",
            report.errors
        );
    }

    #[test]
    fn missing_operation_id_reported() {
        let src = r#"
openapi: 3.1.0
info:
  title: Svc
  key: svc
servers:
  - url: https://api.example.com
paths:
  /a:
    get:
      summary: no id
"#;
        let report = validate_template_yaml(src, &crate::template_vars::Vars::for_tests());
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.code == "missing_field"));
    }

    #[test]
    fn shipped_services_validate_clean() {
        // Smoke test: every shipped services/*.yaml must validate through
        // the full openapi pipeline.
        let services_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let entries = std::fs::read_dir(&services_dir).unwrap();
        let mut checked = 0;
        for entry in entries {
            let path = entry.unwrap().path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            let report = validate_template_yaml(&content, &crate::template_vars::Vars::for_tests());
            assert!(
                report.valid,
                "shipped template {path:?} failed validation: errors {:?}, warnings {:?}",
                report.errors, report.warnings
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "no shipped templates found in {services_dir:?}"
        );
    }

    /// Every shipped template must declare nothing the compiler ignores.
    ///
    /// This is where the extension lint's leniency is paid for. Findings are
    /// warnings everywhere at runtime — an error at `registry::load_from_dir`
    /// would *skip* the template, and a missing service is worse than an ignored
    /// field — so `report.valid` cannot hold this line and a test has to. It is
    /// the one-level-down analogue of `shipped_services_have_no_silent_skips`:
    /// that test catches a template that vanishes, this one catches a template
    /// that loads and quietly does less than it says.
    ///
    /// Filtered by `LINT_CODES` rather than asserting `warnings.is_empty()`, so an
    /// unrelated warning appearing elsewhere in the validator cannot silently
    /// disarm the gate — or noisily break it.
    #[test]
    fn shipped_services_lint_clean() {
        let services_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let mut checked = 0;
        let mut findings: Vec<(String, String, String, String)> = Vec::new();
        for entry in std::fs::read_dir(&services_dir).unwrap() {
            let path = entry.unwrap().path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            let report = validate_template_yaml(&content, &crate::template_vars::Vars::for_tests());
            let file = path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("?")
                .to_string();
            for w in report
                .warnings
                .iter()
                .filter(|w| crate::openapi::LINT_CODES.contains(&w.code.as_str()))
            {
                findings.push((
                    file.clone(),
                    w.code.clone(),
                    w.path.clone(),
                    w.message.clone(),
                ));
            }
            checked += 1;
        }
        assert!(
            checked > 0,
            "no shipped templates found in {services_dir:?}"
        );
        assert!(
            findings.is_empty(),
            "shipped templates declare {} key(s) nothing reads:\n{}",
            findings.len(),
            findings
                .iter()
                .map(|(f, c, p, m)| format!("  {f}: [{c}] {p} — {m}"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    /// The dashboard's seed skeleton for a new template, read out of the Svelte
    /// source so the two cannot drift.
    ///
    /// It shipped `x-overslash-prefix` — removed by D35 and rejected outright by
    /// `extract_api_key` — which means the default scaffold could not be saved at
    /// all. Nothing tested it, because it lived in a string literal in a
    /// component.
    #[test]
    fn scaffold_skeleton_is_valid_and_lint_clean() {
        let page = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("dashboard/src/routes/services/templates/new/+page.svelte");
        let src =
            std::fs::read_to_string(&page).unwrap_or_else(|e| panic!("cannot read {page:?}: {e}"));
        let body = src
            .split_once("// SCAFFOLD-SKELETON-START")
            .and_then(|(_, rest)| rest.split_once("// SCAFFOLD-SKELETON-END"))
            .map(|(inner, _)| inner)
            .unwrap_or_else(|| {
                panic!("scaffold markers missing from {page:?}; keep them around the skeleton")
            });
        let yaml = body
            .split_once('`')
            .and_then(|(_, rest)| rest.rsplit_once('`'))
            .map(|(inner, _)| inner)
            .expect("skeleton is a backtick template literal");
        assert!(
            yaml.contains("openapi: 3.1.0"),
            "extracted the wrong slice: {yaml:?}"
        );

        let report = validate_template_yaml(yaml, &crate::template_vars::Vars::for_tests());
        assert!(
            report.valid,
            "the new-template scaffold does not validate: {:?}",
            report.errors
        );
        let lint: Vec<_> = report
            .warnings
            .iter()
            .filter(|w| crate::openapi::LINT_CODES.contains(&w.code.as_str()))
            .collect();
        assert!(
            lint.is_empty(),
            "the new-template scaffold hands the author keys nothing reads: {lint:?}"
        );
    }
}
