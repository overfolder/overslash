use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub org: Uuid,
    pub email: String,
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

/// Verify and decode a JWT.
pub fn verify(secret: &[u8], token: &str) -> Result<Claims, JwtError> {
    let key = DecodingKey::from_secret(secret);
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "sub"]);
    let data = jsonwebtoken::decode::<Claims>(token, &key, &validation)?;
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
            iat: now,
            exp: now + 3600,
        }
    }

    #[test]
    fn roundtrip() {
        let secret = test_secret();
        let claims = test_claims();
        let token = mint(&secret, &claims).unwrap();
        let decoded = verify(&secret, &token).unwrap();
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
            iat: now - 7200,
            exp: now - 3600,
        };
        let token = mint(&secret, &claims).unwrap();
        assert!(verify(&secret, &token).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let secret = test_secret();
        let claims = test_claims();
        let token = mint(&secret, &claims).unwrap();
        let wrong_secret = vec![1u8; 32];
        assert!(verify(&wrong_secret, &token).is_err());
    }
}
