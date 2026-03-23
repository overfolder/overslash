use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::OsRng, aead::rand_core::RngCore};

/// Encrypt plaintext with AES-256-GCM. Returns nonce (12 bytes) prepended to ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data produced by [`encrypt`]. Expects 12-byte nonce prefix.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::InvalidData);
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Parse a 64-char hex string into a 32-byte key.
pub fn parse_hex_key(hex_str: &str) -> Result<[u8; 32], CryptoError> {
    if hex_str.len() != 64 {
        return Err(CryptoError::InvalidKeyLength);
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| CryptoError::InvalidKeyLength)?;
        key[i] = u8::from_str_radix(s, 16).map_err(|_| CryptoError::InvalidKeyLength)?;
    }
    Ok(key)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid encrypted data")]
    InvalidData,
    #[error("invalid key length (expected 64 hex chars)")]
    InvalidKeyLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"super secret api key";
        let encrypted = encrypt(&key, plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [0xAB; 32];
        let key2 = [0xCD; 32];
        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn decrypt_truncated_data_fails() {
        let key = test_key();
        assert!(decrypt(&key, &[0u8; 5]).is_err());
    }

    #[test]
    fn parse_hex_key_valid() {
        let hex = "ab".repeat(32);
        let key = parse_hex_key(&hex).unwrap();
        assert_eq!(key, [0xAB; 32]);
    }

    #[test]
    fn parse_hex_key_wrong_length() {
        assert!(parse_hex_key("abcd").is_err());
    }
}
