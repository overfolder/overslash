//! `x-overslash-staged-upload` and the `multipart/form-data` parts around it.

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::StagedInline;

/// Lower an `x-overslash-staged-upload` block.
///
/// Strict where [`parse_resolver`](super::params::parse_resolver) is lenient,
/// and for the reason `cache_ttl` is strict there: a malformed block here does not degrade a
/// display string, it decides whether a body carries descriptors or bytes. A
/// typo that dropped the block would send `{upload_id}` stubs upstream and
/// look like a working send with no attachments, so every malformed shape is
/// named rather than ignored — and names nothing onto the action.
///
/// The encoding must match the body it sits in: `base64` writes into a JSON
/// document and `multipart` writes a form-data part, so either one in the
/// other's body would put something on the wire the upstream cannot read.
pub(super) fn parse_staged_upload(
    v: &Value,
    param_type: &str,
    multipart_body: bool,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<StagedInline> {
    let path = format!("{base}.x-overslash-staged-upload");
    let Some(obj) = v.as_object() else {
        issues.push(ValidationIssue::new(
            "invalid_staged_upload",
            "x-overslash-staged-upload must be an object, e.g. {inline_as: base64}".to_string(),
            path,
        ));
        return None;
    };
    let inline_as = match obj.get("inline_as") {
        None if multipart_body => StagedInline::Multipart,
        None => StagedInline::Base64,
        Some(v) => match serde_json::from_value::<StagedInline>(v.clone()) {
            Ok(i) => i,
            Err(_) => {
                issues.push(ValidationIssue::new(
                    "invalid_staged_upload",
                    format!(
                        "unsupported inline_as {v}; the encodings are `base64` (JSON bodies) \
                         and `multipart` (multipart/form-data bodies)"
                    ),
                    format!("{path}.inline_as"),
                ));
                return None;
            }
        },
    };
    if param_type != "array" {
        issues.push(ValidationIssue::new(
            "invalid_staged_upload",
            "x-overslash-staged-upload marks a list of {upload_id} references, so the \
             property must be `type: array`"
                .to_string(),
            path,
        ));
        return None;
    }
    if (inline_as == StagedInline::Multipart) != multipart_body {
        issues.push(ValidationIssue::new(
            "invalid_staged_upload",
            format!(
                "inline_as {} does not fit a {} body; use `{}`",
                if multipart_body {
                    "base64"
                } else {
                    "multipart"
                },
                if multipart_body {
                    "multipart/form-data"
                } else {
                    "JSON"
                },
                if multipart_body {
                    "multipart"
                } else {
                    "base64"
                },
            ),
            format!("{path}.inline_as"),
        ));
        return None;
    }
    Some(inline_as)
}

/// A `multipart/form-data` property that is *not* a staged upload goes out as
/// a text part, so it must be a scalar. A raw `format: binary` field is the
/// case worth naming: the gateway never takes bytes inline, so the only way to
/// fill it is to mark it as a staged upload.
pub(super) fn check_unstaged_part(
    name: &str,
    prop: Option<&Map<String, Value>>,
    path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let get = |k: &str| prop.and_then(|o| o.get(k)).and_then(Value::as_str);
    if get("format") == Some("binary") {
        issues.push(ValidationIssue::new(
            "multipart_binary_needs_staged_upload",
            format!(
                "multipart field '{name}' carries bytes; mark it \
                 `x-overslash-staged-upload: {{inline_as: multipart}}` as a list of \
                 {{upload_id}} references, since a caller cannot send bytes inline"
            ),
            path.to_string(),
        ));
    } else if matches!(get("type"), Some("array" | "object")) {
        issues.push(ValidationIssue::new(
            "multipart_field_not_scalar",
            format!(
                "multipart field '{name}' is a {}; only staged uploads and scalars \
                 can be sent as form-data parts",
                get("type").unwrap_or_default()
            ),
            path.to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::openapi::compile_service;
    use crate::types::StagedInline;

    fn doc(media: &str, props: Value) -> Value {
        json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {"required": true, "content": {media: {
                    "schema": {"type": "object", "properties": props}
                }}}
            }}}
        })
    }

    fn codes(doc: &Value) -> Vec<String> {
        let issues = match compile_service(doc) {
            Ok((_, warnings)) => warnings,
            Err(errors) => errors,
        };
        issues.into_iter().map(|i| i.code.to_string()).collect()
    }

    fn file_field(inline_as: Option<&str>) -> Value {
        let mut marker = json!({});
        if let Some(i) = inline_as {
            marker["inline_as"] = json!(i);
        }
        json!({
            "type": "array",
            "x-overslash-staged-upload": marker,
            "items": {"type": "object", "properties": {"upload_id": {"type": "string"}}}
        })
    }

    /// A form-data body's fields are extracted like a JSON body's, and an
    /// unannotated marker there defaults to the encoding that fits it.
    #[test]
    fn multipart_body_extracts_fields_and_defaults_to_multipart() {
        let d = doc(
            "multipart/form-data",
            json!({"file": file_field(None), "note": {"type": "string"}}),
        );
        let (svc, _) = compile_service(&d).unwrap();
        let action = &svc.actions["x"];
        assert!(action.request_body.as_ref().unwrap().is_multipart());
        assert_eq!(
            action.params["file"].staged_upload,
            Some(StagedInline::Multipart)
        );
        assert!(action.params.contains_key("note"));
    }

    #[test]
    fn encoding_must_fit_the_body() {
        let wrong_on_form = doc(
            "multipart/form-data",
            json!({"file": file_field(Some("base64"))}),
        );
        assert!(codes(&wrong_on_form).contains(&"invalid_staged_upload".to_string()));

        let wrong_on_json = doc(
            "application/json",
            json!({"file": file_field(Some("multipart"))}),
        );
        assert!(codes(&wrong_on_json).contains(&"invalid_staged_upload".to_string()));
    }

    /// Bytes never travel inline, so a raw binary part is a template that can
    /// never be filled — and a nested value has no form-data spelling.
    #[test]
    fn unstaged_multipart_fields_must_be_scalars() {
        let binary = doc(
            "multipart/form-data",
            json!({"file": {"type": "string", "format": "binary"}}),
        );
        assert!(codes(&binary).contains(&"multipart_binary_needs_staged_upload".to_string()));

        let nested = doc(
            "multipart/form-data",
            json!({"file": file_field(None), "tags": {"type": "array"}}),
        );
        assert!(codes(&nested).contains(&"multipart_field_not_scalar".to_string()));
    }
}
