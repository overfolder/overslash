use std::collections::HashMap;

use crate::types::{ActionRequest, InjectAs};

/// Resolve secret refs in an action request, injecting decrypted values into headers or query params.
/// Returns the modified URL (with query params if any) and modified headers.
pub fn inject_secrets(
    request: &ActionRequest,
    secret_values: &HashMap<String, String>,
) -> Result<(String, HashMap<String, String>), InjectionError> {
    let mut headers = request.headers.clone();
    let mut url = request.url.clone();

    for secret_ref in &request.secrets {
        let value = secret_values
            .get(&secret_ref.name)
            .ok_or_else(|| InjectionError::SecretNotFound(secret_ref.name.clone()))?;

        let prefixed = match &secret_ref.prefix {
            Some(p) => format!("{p}{value}"),
            None => value.clone(),
        };

        match secret_ref.inject_as {
            InjectAs::Header => {
                let header_name = secret_ref
                    .header_name
                    .as_deref()
                    .ok_or_else(|| InjectionError::MissingField("header_name".into()))?;
                headers.insert(header_name.to_string(), prefixed);
            }
            InjectAs::Query => {
                let param = secret_ref
                    .query_param
                    .as_deref()
                    .ok_or_else(|| InjectionError::MissingField("query_param".into()))?;
                let separator = if url.contains('?') { "&" } else { "?" };
                url = format!("{url}{separator}{param}={prefixed}");
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
    use super::*;
    use crate::types::SecretRef;

    #[test]
    fn inject_header_with_prefix() {
        let request = ActionRequest {
            method: "GET".into(),
            url: "https://api.example.com/data".into(),
            headers: HashMap::new(),
            body: None,
            secrets: vec![SecretRef {
                name: "token".into(),
                inject_as: InjectAs::Header,
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: Some("Bearer ".into()),
            }],
        };
        let mut values = HashMap::new();
        values.insert("token".into(), "abc123".into());

        let (url, headers) = inject_secrets(&request, &values).unwrap();
        assert_eq!(url, "https://api.example.com/data");
        assert_eq!(headers["Authorization"], "Bearer abc123");
    }

    #[test]
    fn inject_query_param() {
        let request = ActionRequest {
            method: "GET".into(),
            url: "https://api.example.com/data".into(),
            headers: HashMap::new(),
            body: None,
            secrets: vec![SecretRef {
                name: "key".into(),
                inject_as: InjectAs::Query,
                header_name: None,
                query_param: Some("api_key".into()),
                prefix: None,
            }],
        };
        let mut values = HashMap::new();
        values.insert("key".into(), "secret123".into());

        let (url, _) = inject_secrets(&request, &values).unwrap();
        assert_eq!(url, "https://api.example.com/data?api_key=secret123");
    }

    #[test]
    fn missing_secret_fails() {
        let request = ActionRequest {
            method: "GET".into(),
            url: "https://example.com".into(),
            headers: HashMap::new(),
            body: None,
            secrets: vec![SecretRef {
                name: "nonexistent".into(),
                inject_as: InjectAs::Header,
                header_name: Some("X-Key".into()),
                query_param: None,
                prefix: None,
            }],
        };
        let result = inject_secrets(&request, &HashMap::new());
        assert!(result.is_err());
    }
}
