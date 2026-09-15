use std::sync::LazyLock;

use argon2::password_hash::Error as HashError;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use tokio::sync::Semaphore;

/// Minimum length in characters (not bytes).
pub const MIN_CHARS: usize = 12;
/// Upper bound to reject absurd payloads; NIST asks to accept at least 64.
pub const MAX_CHARS: usize = 128;

/// OWASP baseline for argon2id: m = 19 MiB, t = 2, p = 1.
const M_COST_KIB: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

/// Each hash uses ~19 MiB and a full CPU core: cap concurrency to the core count.
static PERMITS: LazyLock<Semaphore> = LazyLock::new(|| {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    Semaphore::new(cores)
});

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("password_too_short")]
    TooShort,
    #[error("password_too_long")]
    TooLong,
}

#[derive(Debug, thiserror::Error)]
pub enum HashingError {
    #[error("password hashing failed: {0}")]
    Hash(HashError),
    #[error("password hashing task failed")]
    Task(#[from] tokio::task::JoinError),
}

pub fn validate(password: &str) -> Result<(), PolicyError> {
    let chars = password.chars().count();
    if chars < MIN_CHARS {
        Err(PolicyError::TooShort)
    } else if chars > MAX_CHARS {
        Err(PolicyError::TooLong)
    } else {
        Ok(())
    }
}

fn argon2() -> Argon2<'static> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Returns a PHC string: `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
pub async fn hash(password: String) -> Result<String, HashingError> {
    let _permit = PERMITS.acquire().await.expect("semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        argon2()
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
            .map_err(HashingError::Hash)
    })
    .await?
}

/// `Ok(false)` means wrong password; `Err` means the stored hash is unusable.
pub async fn verify(password: String, hash: String) -> Result<bool, HashingError> {
    let _permit = PERMITS.acquire().await.expect("semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        match argon2().verify_password(password.as_bytes(), hash.as_str()) {
            Ok(()) => Ok(true),
            Err(HashError::PasswordInvalid) => Ok(false),
            Err(error) => Err(HashingError::Hash(error)),
        }
    })
    .await?
}

/// Argon2id hash of a random string, with the same parameters as real hashes.
/// Verifying against it costs exactly as much as verifying a real password.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$YLveCzz77YQObuuv+2CDVw$EESUFpZDDEfrbLPpr55N73etZztt7pc9sN6y0h7Rw4E";

/// Burn the same CPU time as `verify` when the account doesn't exist,
/// so response time doesn't reveal which emails are registered.
pub async fn verify_dummy(password: String) {
    let _ = verify(password, DUMMY_HASH.to_owned()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_counts_characters_not_bytes() {
        assert_eq!(validate("short"), Err(PolicyError::TooShort));
        assert_eq!(validate("ééééééééééé"), Err(PolicyError::TooShort)); // 11 chars, 22 bytes
        assert_eq!(validate("correct horse"), Ok(()));
        assert_eq!(
            validate(&"a".repeat(MAX_CHARS + 1)),
            Err(PolicyError::TooLong)
        );
    }

    #[tokio::test]
    async fn hash_then_verify() {
        let hash = hash("correct horse battery".into()).await.unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(
            verify("correct horse battery".into(), hash.clone())
                .await
                .unwrap()
        );
        assert!(!verify("wrong password!!".into(), hash).await.unwrap());
    }

    #[tokio::test]
    async fn verify_rejects_garbage_hash() {
        assert!(
            verify("whatever password".into(), "not-a-hash".into())
                .await
                .is_err()
        );
    }
}
