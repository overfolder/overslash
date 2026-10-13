//! The `multipart/form-data` encoding of a staged-upload body.
//!
//! Built by hand rather than with `reqwest::multipart::Form`: a `Form` is a
//! one-shot stream, and the transport replays a buffered body across 307/308
//! redirects (`http_caller::send_following_redirects`). A byte buffer replays;
//! a consumed stream does not.

use serde_json::{Map, Value};

use crate::error::AppError;

/// One file part: a staged upload, decrypted, about to go on the wire.
pub(super) struct FilePart {
    pub field: String,
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// Encode `fields` as text parts and `files` as file parts. Returns the body
/// and the `Content-Type` that names its boundary.
///
/// Every non-file field must be a scalar — validation already holds templates
/// to that, so a nested value here is a caller-supplied one for an
/// `additional-properties`-free action that slipped past it, and is refused
/// rather than flattened into something the upstream never asked for.
pub(super) fn encode(
    fields: &Map<String, Value>,
    files: &[FilePart],
) -> Result<(Vec<u8>, String), AppError> {
    // 128 random bits: the chance of it occurring inside a part is the same
    // bound every multipart encoder relies on.
    let boundary = format!("overslash-{}", uuid::Uuid::new_v4().simple());
    let mut out = Vec::with_capacity(files.iter().map(|f| f.bytes.len() + 256).sum::<usize>());

    for (name, value) in fields {
        let text = match value {
            Value::Null => continue,
            Value::Array(items) if items.is_empty() => continue,
            Value::String(s) => s.clone(),
            Value::Bool(_) | Value::Number(_) => value.to_string(),
            Value::Array(_) | Value::Object(_) => {
                return Err(AppError::BadRequest(format!(
                    "'{name}' is not a scalar and cannot be sent as a form-data part"
                )));
            }
        };
        open_part(&mut out, &boundary, name, None);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for file in files {
        open_part(&mut out, &boundary, &file.field, Some(&file.filename));
        out.extend_from_slice(
            format!("Content-Type: {}\r\n\r\n", header_safe(&file.content_type)).as_bytes(),
        );
        out.extend_from_slice(&file.bytes);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Ok((out, format!("multipart/form-data; boundary={boundary}")))
}

fn open_part(out: &mut Vec<u8>, boundary: &str, name: &str, filename: Option<&str>) {
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    let mut disposition = format!("Content-Disposition: form-data; name=\"{}\"", quoted(name));
    if let Some(f) = filename {
        disposition.push_str(&format!("; filename=\"{}\"", quoted(f)));
    }
    disposition.push_str("\r\n");
    out.extend_from_slice(disposition.as_bytes());
}

/// The WHATWG form-data escape for a quoted header value: `"`, CR and LF are
/// percent-encoded, so no name or filename can close the quote or start a
/// header of its own. Filenames are already sanitised at mint; this holds even
/// for a row written before that existed.
fn quoted(s: &str) -> String {
    s.replace('"', "%22")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn header_safe(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file(name: &str, bytes: &[u8]) -> FilePart {
        FilePart {
            field: "file".into(),
            filename: name.into(),
            content_type: "application/pdf".into(),
            bytes: bytes.to_vec(),
        }
    }

    fn boundary_of(ct: &str) -> &str {
        ct.strip_prefix("multipart/form-data; boundary=").unwrap()
    }

    #[test]
    fn file_and_text_parts_are_framed_by_one_boundary() {
        // One text field: a JSON object's key order is the map's, not ours.
        let fields = json!({"note": "Q3", "skip": null, "empty": []});
        let bytes = b"%PDF-1.7\x00\xff raw";
        let (body, ct) = encode(fields.as_object().unwrap(), &[file("q3.pdf", bytes)]).unwrap();
        let b = boundary_of(&ct);

        let mut expected = Vec::new();
        expected.extend_from_slice(
            format!(
                "--{b}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nQ3\r\n\
                 --{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"q3.pdf\"\r\n\
                 Content-Type: application/pdf\r\n\r\n"
            )
            .as_bytes(),
        );
        expected.extend_from_slice(bytes);
        expected.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
        assert_eq!(body, expected);
    }

    #[test]
    fn filenames_cannot_break_out_of_their_quote() {
        let (body, _) =
            encode(&Map::new(), &[file("a\"; name=\"x\r\nX-Evil: 1.pdf", b"")]).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(
            text.contains("filename=\"a%22; name=%22x%0D%0AX-Evil: 1.pdf\""),
            "{text}"
        );
        assert!(!text.contains("\r\nX-Evil"), "{text}");
    }

    #[test]
    fn non_ascii_filenames_go_out_as_utf8() {
        let (body, _) = encode(&Map::new(), &[file("résumé-ñ.pdf", b"x")]).unwrap();
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("filename=\"résumé-ñ.pdf\"")
        );
    }

    #[test]
    fn nested_text_fields_are_refused() {
        let fields = json!({"tags": ["a"]});
        assert!(encode(fields.as_object().unwrap(), &[]).is_err());
    }
}
