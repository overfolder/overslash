use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::OsRng, aead::rand_core::RngCore};

/// AES-256-GCM blob layout:
///
/// ```text
/// byte 0       : key_version (u8, 1..=255; 0 reserved/invalid)
/// bytes 1..13  : nonce (12 bytes)
/// bytes 13..N  : ciphertext + 16-byte GCM tag
/// ```
///
/// The version byte is what lets us rotate the master key with zero
/// downtime: a blob is decrypted with the keyring entry whose id matches
/// byte 0, so `Active` and `Previous` blobs coexist in the database during
/// a rotation. See [`Keyring`].
const NONCE_LEN: usize = 12;
const VERSION_OFFSET: usize = 0;
const NONCE_OFFSET: usize = 1;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;
/// Minimum valid blob: 1 (version) + 12 (nonce) + 16 (GCM tag).
const MIN_BLOB_LEN: usize = CIPHERTEXT_OFFSET + 16;

/// Two-slot keyring: an `active` key (used for encrypt + decrypt) and an
/// optional `previous` key (decrypt-only).
///
/// During a master-key rotation the operator deploys with `previous = old`
/// and `active = new`; reads succeed on both new and legacy blobs, and
/// every new write is tagged with the new key id. The `overslash admin
/// reencrypt` CLI then walks every encrypted row and rewrites it under the
/// active key. Once the loop is done the operator redeploys with
/// `previous = None` and the keyring is back to one key.
#[derive(Clone)]
pub struct Keyring {
    active_id: u8,
    active_key: [u8; 32],
    previous_id: Option<u8>,
    previous_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("Keyring")
            .field("active_id", &self.active_id)
            .field("previous_id", &self.previous_id)
            .finish()
    }
}

impl Keyring {
    /// Build a single-key keyring. `active_id` must be non-zero.
    pub fn single(active_id: u8, active_key: [u8; 32]) -> Result<Self, CryptoError> {
        if active_id == 0 {
            return Err(CryptoError::InvalidKeyId);
        }
        Ok(Self {
            active_id,
            active_key,
            previous_id: None,
            previous_key: None,
        })
    }

    /// Build a dual-key keyring. `previous_id` must differ from `active_id`
    /// and both must be non-zero.
    pub fn dual(
        active_id: u8,
        active_key: [u8; 32],
        previous_id: u8,
        previous_key: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if active_id == 0 || previous_id == 0 || active_id == previous_id {
            return Err(CryptoError::InvalidKeyId);
        }
        Ok(Self {
            active_id,
            active_key,
            previous_id: Some(previous_id),
            previous_key: Some(previous_key),
        })
    }

    /// Build a [`Keyring`] from raw hex strings. Shared by
    /// [`Keyring::from_env`] and `Config::keyring` so the active/previous
    /// dispatch lives in one place.
    pub fn from_hex(
        active_hex: &str,
        active_id: u8,
        previous_hex: Option<&str>,
        previous_id: u8,
    ) -> Result<Self, CryptoError> {
        let active_key = parse_hex_key(active_hex)?;
        match previous_hex.filter(|s| !s.is_empty()) {
            Some(prev) => {
                let previous_key = parse_hex_key(prev)?;
                Self::dual(active_id, active_key, previous_id, previous_key)
            }
            None => Self::single(active_id, active_key),
        }
    }

    /// Read a [`Keyring`] from environment variables.
    ///
    /// - `SECRETS_ENCRYPTION_KEY` (required, 64 hex chars): the active key.
    /// - `SECRETS_ENCRYPTION_KEY_PREVIOUS` (optional): the prior key,
    ///   decrypt-only. Set during rotation.
    /// - `SECRETS_ENCRYPTION_KEY_ACTIVE_ID` / `_PREVIOUS_ID` (optional,
    ///   `u8`): override the default ids. Default to `1` for active and
    ///   `2` for previous.
    pub fn from_env() -> Result<Self, CryptoError> {
        let active_hex = std::env::var("SECRETS_ENCRYPTION_KEY")
            .map_err(|_| CryptoError::MissingEnv("SECRETS_ENCRYPTION_KEY"))?;
        let active_id = parse_id_env("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", 1)?;
        let previous_id = parse_id_env("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID", 2)?;
        let previous_hex = std::env::var("SECRETS_ENCRYPTION_KEY_PREVIOUS").ok();
        Self::from_hex(&active_hex, active_id, previous_hex.as_deref(), previous_id)
    }

    /// Fixed test keyring (active id = 1, key = `[0xAB; 32]`). Mirrors the
    /// historical `"ab".repeat(32)` value that test fixtures across the
    /// workspace expect.
    pub fn test() -> Self {
        Self {
            active_id: 1,
            active_key: [0xAB; 32],
            previous_id: None,
            previous_key: None,
        }
    }

    pub fn active_id(&self) -> u8 {
        self.active_id
    }

    pub fn previous_id(&self) -> Option<u8> {
        self.previous_id
    }

    fn key_for(&self, id: u8) -> Option<&[u8; 32]> {
        if id == self.active_id {
            Some(&self.active_key)
        } else if Some(id) == self.previous_id {
            self.previous_key.as_ref()
        } else {
            None
        }
    }
}

fn parse_id_env(var: &'static str, default: u8) -> Result<u8, CryptoError> {
    match std::env::var(var).ok() {
        Some(s) if !s.is_empty() => s.parse::<u8>().map_err(|_| CryptoError::InvalidKeyId),
        _ => Ok(default),
    }
}

/// Encrypt `plaintext` with the keyring's active key and return a
/// version-tagged blob (see module docs for layout).
pub fn encrypt(keyring: &Keyring, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new((&keyring.active_key).into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(keyring.active_id);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt`]. Reads the version byte, looks
/// up the matching key in the keyring, and decrypts. Returns
/// `UnknownKeyVersion` if the blob is tagged with a key id the keyring
/// doesn't know about (e.g. a third historical key, or `0`).
pub fn decrypt(keyring: &Keyring, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < MIN_BLOB_LEN {
        return Err(CryptoError::InvalidData);
    }
    let version = data[VERSION_OFFSET];
    if version == 0 {
        return Err(CryptoError::UnknownKeyVersion(0));
    }
    let key = keyring
        .key_for(version)
        .ok_or(CryptoError::UnknownKeyVersion(version))?;
    let nonce = Nonce::from_slice(&data[NONCE_OFFSET..CIPHERTEXT_OFFSET]);
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(nonce, &data[CIPHERTEXT_OFFSET..])
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
    #[error("invalid key id (must be 1..=255, active and previous must differ)")]
    InvalidKeyId,
    #[error("blob tagged with unknown key version {0}; rotate previous key in")]
    UnknownKeyVersion(u8),
    #[error("missing environment variable {0}")]
    MissingEnv(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_a() -> [u8; 32] {
        [0xAB; 32]
    }

    fn key_b() -> [u8; 32] {
        [0xCD; 32]
    }

    #[test]
    fn keyring_roundtrip_active_only() {
        let kr = Keyring::single(1, key_a()).unwrap();
        let plaintext = b"super secret api key";
        let blob = encrypt(&kr, plaintext).unwrap();
        assert_eq!(blob[0], 1, "blob must start with active key id");
        assert_ne!(&blob[CIPHERTEXT_OFFSET..], plaintext);
        let recovered = decrypt(&kr, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn keyring_decrypts_previous() {
        // Pre-rotation: only key id 1 exists. Encrypt with it.
        let pre = Keyring::single(1, key_a()).unwrap();
        let blob_v1 = encrypt(&pre, b"old data").unwrap();
        assert_eq!(blob_v1[0], 1);

        // Mid-rotation: id 2 active, id 1 previous. Both old and new blobs
        // must decrypt; new writes must carry id 2.
        let rotated = Keyring::dual(2, key_b(), 1, key_a()).unwrap();
        let recovered_old = decrypt(&rotated, &blob_v1).unwrap();
        assert_eq!(recovered_old, b"old data");

        let blob_v2 = encrypt(&rotated, b"new data").unwrap();
        assert_eq!(blob_v2[0], 2);
        let recovered_new = decrypt(&rotated, &blob_v2).unwrap();
        assert_eq!(recovered_new, b"new data");
    }

    #[test]
    fn decrypt_rejects_unknown_version() {
        let kr = Keyring::single(2, key_b()).unwrap();
        // Forge a blob tagged with id 9 (not in the keyring).
        let mut forged = vec![9u8];
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 16]); // bogus tag-sized ct
        match decrypt(&kr, &forged) {
            Err(CryptoError::UnknownKeyVersion(9)) => {}
            other => panic!("expected UnknownKeyVersion(9), got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_version_zero() {
        let kr = Keyring::single(1, key_a()).unwrap();
        let mut forged = vec![0u8];
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 16]);
        match decrypt(&kr, &forged) {
            Err(CryptoError::UnknownKeyVersion(0)) => {}
            other => panic!("expected UnknownKeyVersion(0), got {other:?}"),
        }
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        // Two single-key keyrings with the same id but different bytes: a
        // blob from one must fail (AEAD tag check) when decrypted by the
        // other. This catches the "operator deployed the wrong hex" case.
        let kr1 = Keyring::single(1, key_a()).unwrap();
        let kr2 = Keyring::single(1, key_b()).unwrap();
        let blob = encrypt(&kr1, b"secret").unwrap();
        assert!(matches!(
            decrypt(&kr2, &blob),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_truncated_data_fails() {
        let kr = Keyring::single(1, key_a()).unwrap();
        assert!(matches!(
            decrypt(&kr, &[0u8; 5]),
            Err(CryptoError::InvalidData)
        ));
    }

    #[test]
    fn keyring_rejects_zero_id() {
        assert!(matches!(
            Keyring::single(0, key_a()),
            Err(CryptoError::InvalidKeyId)
        ));
        assert!(matches!(
            Keyring::dual(1, key_a(), 0, key_b()),
            Err(CryptoError::InvalidKeyId)
        ));
        assert!(matches!(
            Keyring::dual(1, key_a(), 1, key_b()),
            Err(CryptoError::InvalidKeyId)
        ));
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
