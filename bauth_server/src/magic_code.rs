//! 6-digit codes sent by email: with magic links (typed on the device that asked for the email)
//! and to confirm sensitive account changes.
//!
//! A code only has 10^6 values: it is only safe bound to what it unlocks (a login flow, a
//! session), with few attempts. The database keeps an HMAC keyed by a secret derived from the
//! master key, one per purpose: a dump alone doesn't reveal the codes.

use aws_lc_rs::hmac;
use chrono::TimeDelta;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::master_key::MasterKey;

const CODE_RANGE: u32 = 1_000_000;

/// How long an emailed code (and its magic link) works.
pub const CODE_TTL: TimeDelta = TimeDelta::minutes(15);
/// Wrong codes on one email before it is consumed.
pub const MAX_FAILURES_PER_CODE: i32 = 5;
/// Wrong codes over a day on one address (magic links) or account (confirmations): new emails
/// would otherwise keep adding guesses. Once reached, codes stop working for a day.
pub const MAX_FAILURES_PER_DAY: i64 = 10;

/// A code to email. Only `hash` is stored.
pub struct MagicCode {
    /// Six digits, leading zeros included. Send it, never store or log it.
    pub plain: String,
    pub hash: Vec<u8>,
}

/// One key per purpose: a code emailed for one can't be replayed for the other.
pub struct CodeKeys {
    pub magic_link: CodeKey,
    pub confirmation: CodeKey,
}

impl CodeKeys {
    pub fn new(master_key: &MasterKey) -> Self {
        Self {
            magic_link: CodeKey::new(master_key, "magic_code"),
            confirmation: CodeKey::new(master_key, "confirmation_code"),
        }
    }
}

pub struct CodeKey(hmac::Key);

impl CodeKey {
    fn new(master_key: &MasterKey, purpose: &str) -> Self {
        Self(hmac::Key::new(
            hmac::HMAC_SHA256,
            &master_key.derive(purpose),
        ))
    }

    /// A new code bound to `owner` (the login flow or the session it unlocks).
    pub fn generate(&self, owner: Uuid) -> MagicCode {
        let plain = format!("{:06}", random_below(CODE_RANGE));
        let hash = hmac::sign(&self.0, &message(owner, &plain))
            .as_ref()
            .to_vec();
        MagicCode { plain, hash }
    }

    /// Constant-time check of a code typed for `owner`.
    pub fn verify(&self, owner: Uuid, code: &str, hash: &[u8]) -> bool {
        hmac::verify(&self.0, &message(owner, code), hash).is_ok()
    }
}

/// Rejects anything but six ASCII digits, before any database work.
pub fn check_format(code: &str) -> Result<(), ApiError> {
    if is_well_formed(code) {
        Ok(())
    } else {
        Err(ApiError::InvalidRequest("code must be 6 digits".into()))
    }
}

fn is_well_formed(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

fn message(owner: Uuid, code: &str) -> Vec<u8> {
    [owner.as_bytes().as_slice(), code.as_bytes()].concat()
}

/// Uniform in `0..range`: values past the last multiple of `range` are drawn again.
fn random_below(range: u32) -> u32 {
    let zone = u32::MAX - (u32::MAX - range + 1) % range;
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).expect("OS random number generator is available");
        let value = u32::from_le_bytes(bytes);
        if value <= zone {
            return value % range;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> CodeKeys {
        CodeKeys::new(
            &MasterKey::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap(),
        )
    }

    fn key() -> CodeKey {
        keys().magic_link
    }

    #[test]
    fn code_is_six_digits_and_verifies_only_for_its_flow() {
        let key = key();
        let flow_id = Uuid::now_v7();
        let code = key.generate(flow_id);
        assert!(is_well_formed(&code.plain), "{}", code.plain);
        assert!(key.verify(flow_id, &code.plain, &code.hash));

        let wrong = format!(
            "{:06}",
            (code.plain.parse::<u32>().unwrap() + 1) % CODE_RANGE
        );
        assert!(!key.verify(flow_id, &wrong, &code.hash));
        assert!(!key.verify(Uuid::now_v7(), &code.plain, &code.hash));
    }

    #[test]
    fn hash_depends_on_the_master_key_and_the_purpose() {
        let flow_id = Uuid::now_v7();
        let code = key().generate(flow_id);
        let other = CodeKeys::new(
            &MasterKey::from_base64("HxwdHh8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRo=").unwrap(),
        );
        assert!(!other.magic_link.verify(flow_id, &code.plain, &code.hash));
        assert!(!keys().confirmation.verify(flow_id, &code.plain, &code.hash));
    }

    #[test]
    fn well_formed_codes() {
        assert!(is_well_formed("012345"));
        for code in ["12345", "1234567", "12 345", "١٢٣٤٥٦", "abcdef", ""] {
            assert!(!is_well_formed(code), "{code}");
            assert!(check_format(code).is_err());
        }
    }

    #[test]
    fn random_below_stays_in_range() {
        assert!((0..1000).all(|_| random_below(CODE_RANGE) < CODE_RANGE));
        assert!((0..100).all(|_| random_below(3) < 3));
    }
}
