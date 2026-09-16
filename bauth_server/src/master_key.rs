use std::fmt;

use aws_lc_rs::hmac;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::aead::Payload;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum MasterKeyError {
    #[error(
        "BAUTH_MASTER_KEY must be 32 bytes encoded in base64 (generate one with `openssl rand -base64 32`)"
    )]
    InvalidKey,
    #[error("decryption failed: wrong master key or corrupted data")]
    Decrypt,
}

/// Encrypts secrets stored in the database (signing keys, TOTP secrets…) and derives the other
/// server keys. Losing this key makes every encrypted value unrecoverable.
pub struct MasterKey {
    cipher: XChaCha20Poly1305,
    derivation: hmac::Key,
}

impl MasterKey {
    pub fn from_base64(encoded: &str) -> Result<Self, MasterKeyError> {
        let bytes: [u8; KEY_LEN] = STANDARD
            .decode(encoded.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(MasterKeyError::InvalidKey)?;
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&bytes.into()),
            derivation: hmac::Key::new(hmac::HMAC_SHA256, &bytes),
        })
    }

    /// An independent 256-bit key for one `purpose` (HMAC-SHA-256 of the purpose).
    /// Changing `purpose` changes the key: whatever was built with the old one stops matching.
    pub fn derive(&self, purpose: &str) -> [u8; KEY_LEN] {
        let tag = hmac::sign(&self.derivation, format!("bauth/{purpose}").as_bytes());
        tag.as_ref().try_into().expect("HMAC-SHA-256 is 32 bytes")
    }

    /// Returns `nonce || ciphertext || tag`.
    /// `context` is authenticated but not stored: the same value is required to decrypt,
    /// so a ciphertext copied into another row or column won't open.
    pub fn encrypt(&self, plaintext: &[u8], context: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("OS random number generator is available");
        let ciphertext = self
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: context,
                },
            )
            .expect("plaintext fits in memory, so it is below the AEAD size limit");
        [nonce.as_slice(), &ciphertext].concat()
    }

    pub fn decrypt(&self, sealed: &[u8], context: &[u8]) -> Result<Vec<u8>, MasterKeyError> {
        if sealed.len() < NONCE_LEN {
            return Err(MasterKeyError::Decrypt);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        self.cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: context,
                },
            )
            .map_err(|_| MasterKeyError::Decrypt)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn roundtrip() {
        let key = MasterKey::from_base64(KEY).unwrap();
        let sealed = key.encrypt(b"secret", b"signing_key:1");
        assert_eq!(key.decrypt(&sealed, b"signing_key:1").unwrap(), b"secret");
    }

    #[test]
    fn same_plaintext_encrypts_differently() {
        let key = MasterKey::from_base64(KEY).unwrap();
        assert_ne!(
            key.encrypt(b"secret", b"ctx"),
            key.encrypt(b"secret", b"ctx")
        );
    }

    #[test]
    fn rejects_wrong_context_key_or_tampering() {
        let key = MasterKey::from_base64(KEY).unwrap();
        let sealed = key.encrypt(b"secret", b"signing_key:1");
        assert!(key.decrypt(&sealed, b"signing_key:2").is_err());

        let other = MasterKey::from_base64("HxwdHh8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRo=").unwrap();
        assert!(other.decrypt(&sealed, b"signing_key:1").is_err());

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(key.decrypt(&tampered, b"signing_key:1").is_err());
        assert!(key.decrypt(&[0u8; 10], b"signing_key:1").is_err());
    }

    #[test]
    fn derived_keys_depend_on_purpose_and_master_key() {
        let key = MasterKey::from_base64(KEY).unwrap();
        assert_eq!(key.derive("magic_code"), key.derive("magic_code"));
        assert_ne!(key.derive("magic_code"), key.derive("other"));
        let other = MasterKey::from_base64("HxwdHh8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRo=").unwrap();
        assert_ne!(key.derive("magic_code"), other.derive("magic_code"));
    }

    #[test]
    fn rejects_invalid_master_key() {
        assert!(MasterKey::from_base64("too short").is_err());
        assert!(MasterKey::from_base64("AAECAwQFBgcICQoLDA0ODw==").is_err()); // 16 bytes
        assert_eq!(
            format!("{:?}", MasterKey::from_base64(KEY).unwrap()),
            "MasterKey(<redacted>)"
        );
    }
}
