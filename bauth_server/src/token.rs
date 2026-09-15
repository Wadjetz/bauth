use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// 256 bits of entropy: guessing is impossible, so a fast hash is enough to store it.
const TOKEN_BYTES: usize = 32;

/// A secret sent to the user (email link, refresh token…). Only `hash` is stored.
pub struct SecretToken {
    /// URL-safe base64, 43 characters. Send it, never store or log it.
    pub plain: String,
    /// SHA-256 of `plain`, what the database keeps.
    pub hash: Vec<u8>,
}

pub fn generate() -> SecretToken {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).expect("OS random number generator is available");
    let plain = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash(&plain);
    SecretToken { plain, hash }
}

/// Hash a token received from a client, to look it up in the database.
pub fn hash(plain: &str) -> Vec<u8> {
    Sha256::digest(plain.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_is_url_safe_and_hash_matches() {
        let token = generate();
        assert_eq!(token.plain.len(), 43);
        assert!(
            token
                .plain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_eq!(token.hash.len(), 32);
        assert_eq!(hash(&token.plain), token.hash);
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(generate().plain, generate().plain);
    }
}
