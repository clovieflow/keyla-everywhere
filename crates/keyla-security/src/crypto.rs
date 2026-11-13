//! Credential encryption (AES-256-GCM) and secret hashing.
//! Port of `src/security/crypto.ts`.
//!
//! Stored envelope layout is `iv(12) || authTag(16) || ciphertext`, keyed by
//! the 32-byte `KEYLA_ENCRYPTION_KEY`. Postgres never sees plaintext.

use std::sync::RwLock;

use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

const IV_LENGTH: usize = 12;
const AUTH_TAG_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("credential encryption key is not configured")]
    KeyMissing,
    #[error("invalid credential encryption key: {0}")]
    KeyInvalid(String),
    #[error("malformed credential ciphertext: too short")]
    TooShort,
    #[error("credential decryption failed")]
    DecryptFailed,
}

static KEY: RwLock<Option<[u8; KEY_LENGTH]>> = RwLock::new(None);

fn key_cell() -> &'static RwLock<Option<[u8; KEY_LENGTH]>> {
    &KEY
}

/// Installs a key for a test or an explicit composition point.
pub fn set_credential_encryption_key_for_testing(key: Option<[u8; KEY_LENGTH]>) {
    *key_cell()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = key;
}

fn encryption_key() -> Result<[u8; KEY_LENGTH], CryptoError> {
    if let Some(key) = *key_cell()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
    {
        return Ok(key);
    }
    let env = keyla_config::ProcessEnv;
    let raw = keyla_config::require_encryption_key_env(&env)
        .map_err(|error| CryptoError::KeyInvalid(error.to_string()))?;
    let key = keyla_config::decode_encryption_key(&raw)
        .map_err(|error| CryptoError::KeyInvalid(error.to_string()))?;
    let mut cell = key_cell()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = *cell {
        return Ok(existing);
    }
    *cell = Some(key);
    Ok(key)
}

/// Encrypts plaintext credential material for storage.
pub fn encrypt_credential(plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::KeyMissing)?;
    let mut iv = [0u8; IV_LENGTH];
    OsRng.fill_bytes(&mut iv);
    let sealed = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .map_err(|_| CryptoError::DecryptFailed)?;
    if sealed.len() < AUTH_TAG_LENGTH {
        return Err(CryptoError::DecryptFailed);
    }
    let split = sealed.len() - AUTH_TAG_LENGTH;
    let (ciphertext, auth_tag) = sealed.split_at(split);
    let mut out = Vec::with_capacity(IV_LENGTH + AUTH_TAG_LENGTH + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(auth_tag);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Decrypts a buffer produced by [`encrypt_credential`].
pub fn decrypt_credential(encoded: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encoded.len() < IV_LENGTH + AUTH_TAG_LENGTH {
        return Err(CryptoError::TooShort);
    }
    let key = encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CryptoError::KeyMissing)?;
    let iv = &encoded[..IV_LENGTH];
    let auth_tag = &encoded[IV_LENGTH..IV_LENGTH + AUTH_TAG_LENGTH];
    let ciphertext = &encoded[IV_LENGTH + AUTH_TAG_LENGTH..];
    let mut sealed = Vec::with_capacity(ciphertext.len() + AUTH_TAG_LENGTH);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(auth_tag);
    cipher
        .decrypt(Nonce::from_slice(iv), sealed.as_ref())
        .map_err(|_| CryptoError::DecryptFailed)
}

/// Decrypts credential ciphertext directly to a UTF-8 string.
pub fn decrypt_credential_to_string(encoded: &[u8]) -> Result<String, CryptoError> {
    String::from_utf8(decrypt_credential(encoded)?).map_err(|_| CryptoError::DecryptFailed)
}

/// One-way hash contract for credential/key material: HMAC-SHA256 with the
/// same decoded 256-bit key, hex encoded.
pub fn hash_secret(secret: &str) -> Result<String, CryptoError> {
    let key = encryption_key()?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|_| CryptoError::KeyMissing)?;
    mac.update(secret.as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_key() {
        set_credential_encryption_key_for_testing(Some([7u8; 32]));
    }

    #[test]
    fn envelope_layout_is_iv_tag_ciphertext_and_round_trips() {
        install_key();
        let plaintext = b"sk-test-secret";
        let encrypted = encrypt_credential(plaintext).unwrap();
        assert_eq!(
            encrypted.len(),
            IV_LENGTH + AUTH_TAG_LENGTH + plaintext.len()
        );
        assert_eq!(decrypt_credential(&encrypted).unwrap(), plaintext);
        assert_eq!(
            decrypt_credential_to_string(&encrypted).unwrap(),
            "sk-test-secret"
        );
    }

    #[test]
    fn tampering_and_short_buffers_fail_closed() {
        install_key();
        let mut encrypted = encrypt_credential(b"secret").unwrap();
        encrypted[IV_LENGTH] ^= 0xff;
        assert_eq!(
            decrypt_credential(&encrypted),
            Err(CryptoError::DecryptFailed)
        );
        assert_eq!(decrypt_credential(&[0u8; 4]), Err(CryptoError::TooShort));
    }

    #[test]
    fn hashing_is_deterministic_and_keyed() {
        install_key();
        let first = hash_secret("token").unwrap();
        let second = hash_secret("token").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_ne!(hash_secret("other").unwrap(), first);
    }
}
