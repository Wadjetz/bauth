//! 6-digit codes sent with magic links, typed on the device that asked for the email.
//!
//! A code only has 10^6 values: it is only safe bound to its login flow, with few attempts.
//! The database keeps an HMAC keyed by a secret derived from the master key, bound to the flow:
//! a dump alone doesn't reveal the codes.

use aws_lc_rs::hmac;
use uuid::Uuid;

use crate::master_key::MasterKey;

const CODE_RANGE: u32 = 1_000_000;

/// A code to email. Only `hash` is stored.
pub struct MagicCode {
    /// Six digits, leading zeros included. Send it, never store or log it.
    pub plain: String,
    pub hash: Vec<u8>,
}

pub struct MagicCodeKey(hmac::Key);

impl MagicCodeKey {
    pub fn new(master_key: &MasterKey) -> Self {
        Self(hmac::Key::new(
            hmac::HMAC_SHA256,
            &master_key.derive("magic_code"),
        ))
    }

    pub fn generate(&self, flow_id: Uuid) -> MagicCode {
        let plain = format!("{:06}", random_below(CODE_RANGE));
        let hash = hmac::sign(&self.0, &message(flow_id, &plain))
            .as_ref()
            .to_vec();
        MagicCode { plain, hash }
    }

    /// Constant-time check of a code typed for `flow_id`.
    pub fn verify(&self, flow_id: Uuid, code: &str, hash: &[u8]) -> bool {
        hmac::verify(&self.0, &message(flow_id, code), hash).is_ok()
    }
}

/// Exactly six ASCII digits.
pub fn is_well_formed(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

fn message(flow_id: Uuid, code: &str) -> Vec<u8> {
    [flow_id.as_bytes().as_slice(), code.as_bytes()].concat()
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

    fn key() -> MagicCodeKey {
        MagicCodeKey::new(
            &MasterKey::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap(),
        )
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
    fn hash_depends_on_the_master_key() {
        let flow_id = Uuid::now_v7();
        let code = key().generate(flow_id);
        let other = MagicCodeKey::new(
            &MasterKey::from_base64("HxwdHh8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRo=").unwrap(),
        );
        assert!(!other.verify(flow_id, &code.plain, &code.hash));
    }

    #[test]
    fn well_formed_codes() {
        assert!(is_well_formed("012345"));
        for code in ["12345", "1234567", "12 345", "١٢٣٤٥٦", "abcdef", ""] {
            assert!(!is_well_formed(code), "{code}");
        }
    }

    #[test]
    fn random_below_stays_in_range() {
        assert!((0..1000).all(|_| random_below(CODE_RANGE) < CODE_RANGE));
        assert!((0..100).all(|_| random_below(3) < 3));
    }
}
