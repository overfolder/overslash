use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Canonical `aud` value for the dashboard session JWT (set via cookie).
pub const AUD_SESSION: &str = "session";

/// Canonical `aud` value for MCP/OAuth access tokens presented as Bearer.
/// Distinct from `AUD_SESSION` so a cookie JWT cannot be replayed against
/// `/mcp` and vice versa.
pub const AUD_MCP: &str = "mcp";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub org: Uuid,
    pub email: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token error: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),
}

/// Mint a JWT signed with HMAC-SHA256.
pub fn mint(secret: &[u8], claims: &Claims) -> Result<String, JwtError> {
    let key = EncodingKey::from_secret(secret);
    let token = jsonwebtoken::encode(&Header::default(), claims, &key)?;
    Ok(token)
}

/// Verify and decode a JWT, asserting the `aud` matches `expected_aud`.
/// Callers must pass the audience they expect — session handlers pass
/// `AUD_SESSION`, MCP bearer acceptance passes `AUD_MCP`.
///
/// Legacy tokens minted before the `aud` field was introduced lack it
/// entirely. For `AUD_SESSION` only, we fall back to a second decode
/// that skips the audience check so that active sessions survive a
/// rolling deployment. `AUD_MCP` tokens are always newly minted and
/// must carry `aud`.
pub fn verify(secret: &[u8], token: &str, expected_aud: &str) -> Result<Claims, JwtError> {
    let key = DecodingKey::from_secret(secret);
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    validation.set_audience(&[expected_aud]);
    match jsonwebtoken::decode::<Claims>(token, &key, &validation) {
        Ok(data) => Ok(data.claims),
        Err(e) if expected_aud == AUD_SESSION => {
            // Retry without aud requirement for legacy session tokens.
            let mut legacy = Validation::new(Algorithm::HS256);
            legacy.set_required_spec_claims(&["exp", "sub"]);
            legacy.validate_aud = false;
            let data =
                jsonwebtoken::decode::<Claims>(token, &key, &legacy).map_err(|_| e.clone())?;
            // Guard: if the token explicitly carries a *different* known
            // audience it's not a legacy session — it's a mis-routed MCP
            // token. Reject it rather than silently promoting it.
            if data.claims.aud == AUD_MCP {
                return Err(e.into());
            }
            Ok(Claims {
                aud: AUD_SESSION.into(),
                ..data.claims
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// Convenience: mint an MCP access token (aud=mcp, HS256 with the configured
/// signing key). Intentionally minimal — callers populate `sub`/`org`/`email`
/// themselves from the resolved identity.
pub fn mint_mcp(
    secret: &[u8],
    sub: Uuid,
    org: Uuid,
    email: String,
    ttl_secs: i64,
) -> Result<String, JwtError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = Claims {
        sub,
        org,
        email,
        aud: AUD_MCP.into(),
        iat: now,
        exp: now + ttl_secs,
    };
    mint(secret, &claims)
}

/// Claims for the standalone "Provide Secret" page. Distinct from `Claims`
/// (user session) so a leaked session cookie cannot be used to satisfy a
/// secret-request URL — and vice versa. The `kind` field is asserted on
/// verify as a defense-in-depth check against future claim-shape collisions.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretRequestClaims {
    pub req: String, // "req_<uuid>"
    pub org: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub kind: String, // always "secret_request"
}

pub const SECRET_REQUEST_KIND: &str = "secret_request";

pub fn mint_secret_request(
    secret: &[u8],
    claims: &SecretRequestClaims,
) -> Result<String, JwtError> {
    let key = EncodingKey::from_secret(secret);
    Ok(jsonwebtoken::encode(&Header::default(), claims, &key)?)
}

pub fn verify_secret_request(secret: &[u8], token: &str) -> Result<SecretRequestClaims, JwtError> {
    let key = DecodingKey::from_secret(secret);
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp"]);
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<SecretRequestClaims>(token, &key, &validation)?;
    if data.claims.kind != SECRET_REQUEST_KIND {
        // Map "wrong kind" into the same error type as a bad signature so
        // callers don't have to special-case it.
        return Err(JwtError::Token(
            jsonwebtoken::errors::ErrorKind::InvalidToken.into(),
        ));
    }
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> Vec<u8> {
        vec![0u8; 32]
    }

    fn test_claims() -> Claims {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Claims {
            sub: Uuid::new_v4(),
            org: Uuid::new_v4(),
            email: "test@example.com".into(),
            aud: AUD_SESSION.into(),
            iat: now,
            exp: now + 3600,
        }
    }

    #[test]
    fn roundtrip() {
        let secret = test_secret();
        let claims = test_claims();
        let token = mint(&secret, &claims).unwrap();
        let decoded = verify(&secret, &token, AUD_SESSION).unwrap();
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.org, claims.org);
        assert_eq!(decoded.email, claims.email);
    }

    #[test]
    fn expired_token_rejected() {
        let secret = test_secret();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            sub: Uuid::new_v4(),
            org: Uuid::new_v4(),
            email: "test@example.com".into(),
            aud: AUD_SESSION.into(),
            iat: now - 7200,
            exp: now - 3600,
        };
        let token = mint(&secret, &claims).unwrap();
        assert!(verify(&secret, &token, AUD_SESSION).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let secret = test_secret();
        let claims = test_claims();
        let token = mint(&secret, &claims).unwrap();
        let wrong_secret = vec![1u8; 32];
        assert!(verify(&wrong_secret, &token, AUD_SESSION).is_err());
    }

    #[test]
    fn session_token_not_accepted_as_mcp() {
        let secret = test_secret();
        let claims = test_claims(); // aud=session
        let token = mint(&secret, &claims).unwrap();
        assert!(verify(&secret, &token, AUD_MCP).is_err());
    }

    #[test]
    fn mcp_token_not_accepted_as_session() {
        let secret = test_secret();
        let token = mint_mcp(
            &secret,
            Uuid::new_v4(),
            Uuid::new_v4(),
            "u@example.com".into(),
            3600,
        )
        .unwrap();
        assert!(verify(&secret, &token, AUD_SESSION).is_err());
        assert!(verify(&secret, &token, AUD_MCP).is_ok());
    }
}
