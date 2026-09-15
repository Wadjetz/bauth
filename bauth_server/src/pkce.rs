use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// base64url(SHA-256) without padding is always 43 characters.
const S256_CHALLENGE_LEN: usize = 43;

fn is_base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Shape check for a `code_challenge` sent with `code_challenge_method=S256`.
pub fn is_valid_challenge(challenge: &str) -> bool {
    challenge.len() == S256_CHALLENGE_LEN && is_base64url(challenge)
}

/// RFC 7636 §4.1: 43 to 128 characters from [A-Z a-z 0-9 - . _ ~].
fn is_valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Used by `/oauth/token`: does this verifier match the challenge stored with the flow?
pub fn verify(verifier: &str, challenge: &str) -> bool {
    is_valid_verifier(verifier)
        && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from RFC 7636 Appendix B.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc_7636_test_vector() {
        assert!(is_valid_challenge(CHALLENGE));
        assert!(verify(VERIFIER, CHALLENGE));
    }

    #[test]
    fn rejects_wrong_or_malformed_values() {
        assert!(!verify(
            "wrong-verifier-wrong-verifier-wrong-verifier",
            CHALLENGE
        ));
        assert!(!verify("short", CHALLENGE));
        assert!(!is_valid_challenge("too-short"));
        assert!(!is_valid_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"
        )); // '+' is not base64url
        assert!(!is_valid_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM="
        )); // padding
    }
}
