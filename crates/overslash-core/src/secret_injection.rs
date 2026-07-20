use std::collections::HashMap;

use crate::types::{ActionRequest, InjectAs};

/// Place resolved credential values into an action request's headers and
/// query string. Returns the modified URL (with query params if any) and
/// modified headers.
///
/// `values` is keyed by [`crate::types::SecretRef::name`] and holds *finished*
/// values: a single secret injected verbatim, or the output of the ref's
/// [`crate::types::CredentialTemplate`]. Composition happens in the caller,
/// which is the only place that holds plaintext — see
/// `overslash-api`'s `action_caller::resolve_credential_values`.
pub fn inject_secrets(
    request: &ActionRequest,
    values: &HashMap<String, String>,
) -> Result<(String, HashMap<String, String>), InjectionError> {
    let mut headers = request.headers.clone();
    let mut url = request.url.clone();

    for secret_ref in &request.secrets {
        let value = values
            .get(&secret_ref.name)
            .ok_or_else(|| InjectionError::SecretNotFound(secret_ref.name.clone()))?;

        // `prefix` is the raw-HTTP caller's own field; a template-compiled ref
        // already carries any prefix inside its rendered value and leaves this
        // `None`, so the two never both apply.
        let value = match &secret_ref.prefix {
            Some(p) => format!("{p}{value}"),
            None => value.clone(),
        };

        match secret_ref.inject_as {
            InjectAs::Header => {
                let header_name = secret_ref
                    .header_name
                    .as_deref()
                    .ok_or_else(|| InjectionError::MissingField("header_name".into()))?;
                headers.insert(header_name.to_string(), value);
            }
            InjectAs::Query => {
                let param = secret_ref
                    .query_param
                    .as_deref()
                    .ok_or_else(|| InjectionError::MissingField("query_param".into()))?;
                let separator = if url.contains('?') { "&" } else { "?" };
                url = format!("{url}{separator}{param}={value}");
            }
        }
    }

    Ok((url, headers))
}

#[derive(Debug, thiserror::Error)]
pub enum InjectionError {
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    #[error("missing required field: {0}")]
    MissingField(String),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::types::SecretRef;

    fn request(secret: SecretRef) -> ActionRequest {
        ActionRequest {
            method: "GET".into(),
            url: "https://api.example.com/data".into(),
            headers: HashMap::new(),
            body: None,
            secrets: vec![secret],
        }
    }

    #[test]
    fn inject_header() {
        let req = request(SecretRef {
            name: "auth".into(),
            inject_as: InjectAs::Header,
            header_name: Some("Authorization".into()),
            ..Default::default()
        });
        let values = HashMap::from([("auth".to_string(), "Bearer abc123".to_string())]);

        let (url, headers) = inject_secrets(&req, &values).unwrap();
        assert_eq!(url, "https://api.example.com/data");
        assert_eq!(headers["Authorization"], "Bearer abc123");
    }

    #[test]
    fn inject_query_param() {
        let req = request(SecretRef {
            name: "key".into(),
            inject_as: InjectAs::Query,
            query_param: Some("api_key".into()),
            ..Default::default()
        });
        let values = HashMap::from([("key".to_string(), "secret123".to_string())]);

        let (url, _) = inject_secrets(&req, &values).unwrap();
        assert_eq!(url, "https://api.example.com/data?api_key=secret123");
    }

    #[test]
    fn composed_value_is_injected_verbatim() {
        // The `X-Mailbox-Auth` shape: the caller composed
        // `Basic base64(user:pass)` from two secrets, and the injector must
        // place it untouched — it applies no transforms of its own.
        let req = request(SecretRef {
            name: "mailbox".into(),
            inject_as: InjectAs::Header,
            header_name: Some("X-Mailbox-Auth".into()),
            ..Default::default()
        });
        let values = HashMap::from([(
            "mailbox".to_string(),
            "Basic dXNlckBleGFtcGxlLmNvbTphcHAtcGFzc3dvcmQ=".to_string(),
        )]);

        let (_url, headers) = inject_secrets(&req, &values).unwrap();
        assert_eq!(
            headers["X-Mailbox-Auth"],
            "Basic dXNlckBleGFtcGxlLmNvbTphcHAtcGFzc3dvcmQ="
        );
    }

    /// Raw HTTP (Mode A): the caller names a vault secret inline, with no
    /// bindings and no template. `name` must still be recognised as the
    /// secret to fetch — a regression here silently drops every per-call
    /// secret on the raw-HTTP path.
    #[test]
    fn bindingless_ref_fetches_the_secret_named_by_name() {
        let secret = SecretRef {
            name: "test_token".into(),
            inject_as: InjectAs::Header,
            header_name: Some("X-Token".into()),
            ..Default::default()
        };
        assert_eq!(secret.vault_names(), ["test_token"]);
    }

    /// The documented raw-HTTP request shape lets a caller pass `prefix`
    /// alongside an inline secret — they have no service template to express
    /// it in. See docs/design/overslash.md's `secrets[]` schema.
    #[test]
    fn mode_a_prefix_is_applied() {
        let req = request(SecretRef {
            name: "gcal_token".into(),
            inject_as: InjectAs::Header,
            header_name: Some("Authorization".into()),
            prefix: Some("Bearer ".into()),
            ..Default::default()
        });
        let values = HashMap::from([("gcal_token".to_string(), "manual-token-xyz".to_string())]);

        let (_url, headers) = inject_secrets(&req, &values).unwrap();
        assert_eq!(headers["Authorization"], "Bearer manual-token-xyz");
    }

    #[test]
    fn bound_ref_fetches_only_its_bound_secrets() {
        let secret = SecretRef {
            name: "mailbox".into(),
            inject_as: InjectAs::Header,
            header_name: Some("X-Mailbox-Auth".into()),
            bindings: BTreeMap::from([
                ("mailbox_user".to_string(), "angel_login".to_string()),
                ("mailbox_pass".to_string(), "angel_password".to_string()),
            ]),
            ..Default::default()
        };
        let mut names = secret.vault_names();
        names.sort();
        assert_eq!(names, ["angel_login", "angel_password"]);
        // Never the scheme key itself — that names the injection, not a secret.
        assert!(!names.contains(&"mailbox"));
    }

    #[test]
    fn missing_value_fails() {
        let req = request(SecretRef {
            name: "nonexistent".into(),
            inject_as: InjectAs::Header,
            header_name: Some("X-Key".into()),
            ..Default::default()
        });
        assert!(inject_secrets(&req, &HashMap::new()).is_err());
    }
}
