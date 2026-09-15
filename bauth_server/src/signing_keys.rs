//! Ed25519 keys signing access tokens, and their rotation.
//!
//! ```text
//! day 0            day 0 + 24 h                 day 0 + 48 h
//! │ K2 created     │ K2 starts signing           │ K1 leaves the JWKS
//! │ and published  │ K1 stops signing (retired)  │
//! ```
//! Published before signing, so APIs caching the JWKS know K2 before seeing its tokens;
//! published after retirement, so tokens K1 signed stay verifiable until they expire.

use std::sync::Arc;

use arc_swap::ArcSwap;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use uuid::Uuid;

use crate::db::DbPool;
use crate::master_key::{MasterKey, MasterKeyError};
use crate::queries;

/// A new key is created once the signing key is this old.
pub const ROTATION_INTERVAL: TimeDelta = TimeDelta::days(30);
/// A new key is published this long before it starts signing.
/// Must exceed the JWKS cache lifetime (`Cache-Control: max-age`, 1 h).
pub const PREPUBLICATION: TimeDelta = TimeDelta::hours(24);
/// Retired keys stay in the JWKS this long, so tokens they signed can still be verified.
/// Must exceed the access token lifetime.
pub const RETIRED_KEY_GRACE: TimeDelta = TimeDelta::hours(24);
/// `pg_try_advisory_xact_lock` key, so only one instance rotates at a time.
const ROTATION_LOCK_KEY: i64 = 0x6261_7574_686b_6579; // "bauthkey"

const SEED_LEN: usize = 32;

/// PKCS#8 v1 prefix for an Ed25519 private key; followed by the 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("signing key {kid}: {source}")]
    Decrypt { kid: Uuid, source: MasterKeyError },
    #[error("signing key {kid} is not a valid Ed25519 key")]
    InvalidKey { kid: Uuid },
}

/// The shared, hot-swappable key set: reloaded by a background job.
pub type SharedSigningKeys = Arc<ArcSwap<SigningKeys>>;

/// A key allowed to sign from `active_at` until `retired_at`.
pub struct LoadedKey {
    pub kid: Uuid,
    pub encoding_key: EncodingKey,
    active_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
}

impl LoadedKey {
    fn can_sign(&self, now: DateTime<Utc>) -> bool {
        self.active_at <= now && self.retired_at.is_none_or(|retired_at| retired_at > now)
    }
}

pub struct SigningKeys {
    /// Keys that sign now or will later, newest `active_at` first.
    keys: Vec<LoadedKey>,
    /// Every published key: pending, active, and retired within the grace period.
    pub jwks: JwkSet,
}

impl SigningKeys {
    /// The key to sign with at `now`. Chosen per token, so a pending key takes over exactly
    /// at its `active_at`, whenever the key set was loaded.
    pub fn signing_key(&self, now: DateTime<Utc>) -> Option<&LoadedKey> {
        self.keys.iter().find(|key| key.can_sign(now))
    }

    /// Key to verify a token bauth signed itself, by `kid`.
    pub fn decoding_key(&self, kid: &str) -> Option<DecodingKey> {
        DecodingKey::from_jwk(self.jwks.find(kid)?).ok()
    }

    /// Reads published keys from the database and decrypts those that can still sign.
    pub async fn load(db: &DbPool, master_key: &MasterKey) -> Result<Self, SigningKeyError> {
        let now = Utc::now();
        let rows = queries::signing_keys::list_published(db, now, RETIRED_KEY_GRACE).await?;

        let mut keys = Vec::new();
        for row in rows
            .iter()
            .filter(|row| row.retired_at.is_none_or(|at| at > now))
        {
            let seed = master_key
                .decrypt(&row.encrypted_private_key, context(row.id).as_bytes())
                .map_err(|source| SigningKeyError::Decrypt {
                    kid: row.id,
                    source,
                })?;
            if seed.len() != SEED_LEN {
                return Err(SigningKeyError::InvalidKey { kid: row.id });
            }
            keys.push(LoadedKey {
                kid: row.id,
                encoding_key: encoding_key(&seed),
                active_at: row.active_at,
                retired_at: row.retired_at,
            });
        }

        Ok(Self {
            keys,
            jwks: JwkSet {
                keys: rows
                    .iter()
                    .map(|row| jwk(row.id, &row.public_key))
                    .collect(),
            },
        })
    }
}

/// Creates a key signing right away if none can sign now: first start, or every key was
/// retired by hand (emergency rotation). Then loads the key set.
pub async fn ensure_and_load(
    db: &DbPool,
    master_key: &MasterKey,
) -> Result<SigningKeys, SigningKeyError> {
    let keys = SigningKeys::load(db, master_key).await?;
    if keys.signing_key(Utc::now()).is_some() {
        return Ok(keys);
    }
    let key = generate(master_key);
    queries::signing_keys::insert(
        db,
        key.kid,
        &key.public_key,
        &key.encrypted_private_key,
        Utc::now(),
    )
    .await?;
    tracing::info!(kid = %key.kid, "created signing key");
    SigningKeys::load(db, master_key).await
}

/// Publishes a new key if the signing key is older than `ROTATION_INTERVAL` and none is pending.
/// Returns the new key id. Other instances holding the lock make this a no-op.
pub async fn rotate_if_due(
    db: &DbPool,
    master_key: &MasterKey,
) -> Result<Option<Uuid>, SigningKeyError> {
    let mut tx = db.begin().await?;
    let locked = sqlx::query_scalar!(
        r#"SELECT pg_try_advisory_xact_lock($1) AS "locked!""#,
        ROTATION_LOCK_KEY
    )
    .fetch_one(&mut *tx)
    .await?;
    if !locked {
        return Ok(None);
    }

    let now = Utc::now();
    let rows = queries::signing_keys::list_published(&mut *tx, now, RETIRED_KEY_GRACE).await?;
    let pending = rows.iter().any(|row| row.active_at > now);
    let current = rows
        .iter()
        .find(|row| row.active_at <= now && row.retired_at.is_none_or(|at| at > now));
    let due = current.is_none_or(|key| now - key.active_at >= ROTATION_INTERVAL);
    if pending || !due {
        return Ok(None);
    }

    let key = generate(master_key);
    let takes_over_at = now + PREPUBLICATION;
    queries::signing_keys::insert(
        &mut *tx,
        key.kid,
        &key.public_key,
        &key.encrypted_private_key,
        takes_over_at,
    )
    .await?;
    queries::signing_keys::retire_all_except(&mut *tx, key.kid, takes_over_at).await?;
    tx.commit().await?;

    tracing::info!(kid = %key.kid, %takes_over_at, "published new signing key");
    Ok(Some(key.kid))
}

/// Replaces the shared key set with a fresh load from the database.
pub async fn reload(
    db: &DbPool,
    master_key: &MasterKey,
    shared: &SharedSigningKeys,
) -> Result<(), SigningKeyError> {
    let keys = ensure_and_load(db, master_key).await?;
    tracing::debug!(published = keys.jwks.keys.len(), "signing keys reloaded");
    shared.store(Arc::new(keys));
    Ok(())
}

fn context(kid: Uuid) -> String {
    format!("signing_key:{kid}")
}

fn jwk(kid: Uuid, public_key: &[u8]) -> Jwk {
    Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: Some(kid.to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(public_key),
        }),
    }
}

fn encoding_key(seed: &[u8]) -> EncodingKey {
    EncodingKey::from_ed_der(&[ED25519_PKCS8_PREFIX.as_slice(), seed].concat())
}

struct GeneratedKey {
    kid: Uuid,
    public_key: Vec<u8>,
    encrypted_private_key: Vec<u8>,
}

fn generate(master_key: &MasterKey) -> GeneratedKey {
    let kid = Uuid::now_v7();
    let mut seed = [0u8; SEED_LEN];
    getrandom::fill(&mut seed).expect("OS random number generator is available");
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .expect("any 32-byte seed is a valid Ed25519 key");
    GeneratedKey {
        kid,
        public_key: pair.public_key().as_ref().to_vec(),
        encrypted_private_key: master_key.encrypt(&seed, context(kid).as_bytes()),
    }
}

#[cfg(test)]
impl SigningKeys {
    /// In-memory key set for tests, no database: one key per `(active_at, retired_at)` window.
    pub fn for_tests_with(windows: &[(DateTime<Utc>, Option<DateTime<Utc>>)]) -> Self {
        let master_key =
            MasterKey::from_base64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap();
        let mut keys = Vec::new();
        let mut jwks = Vec::new();
        for &(active_at, retired_at) in windows {
            let key = generate(&master_key);
            let seed = master_key
                .decrypt(&key.encrypted_private_key, context(key.kid).as_bytes())
                .unwrap();
            jwks.push(jwk(key.kid, &key.public_key));
            keys.push(LoadedKey {
                kid: key.kid,
                encoding_key: encoding_key(&seed),
                active_at,
                retired_at,
            });
        }
        keys.sort_by_key(|key| std::cmp::Reverse(key.active_at));
        Self {
            keys,
            jwks: JwkSet { keys: jwks },
        }
    }

    pub fn for_tests() -> Self {
        Self::for_tests_with(&[(Utc::now() - TimeDelta::days(1), None)])
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: u64,
    }

    const MASTER: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn generated_key_signs_tokens_verifiable_with_its_jwk() {
        let master_key = MasterKey::from_base64(MASTER).unwrap();
        let key = generate(&master_key);
        let seed = master_key
            .decrypt(&key.encrypted_private_key, context(key.kid).as_bytes())
            .unwrap();

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key.kid.to_string());
        let claims = Claims {
            sub: "user".into(),
            exp: 4_102_444_800,
        };
        let token = encode(&header, &claims, &encoding_key(&seed)).unwrap();

        let jwk = jwk(key.kid, &key.public_key);
        let decoded = decode::<Claims>(
            &token,
            &DecodingKey::from_jwk(&jwk).unwrap(),
            &Validation::new(Algorithm::EdDSA),
        )
        .unwrap();
        assert_eq!(decoded.claims, claims);
        assert_eq!(
            decoded.header.kid.as_deref(),
            Some(key.kid.to_string().as_str())
        );
    }

    #[test]
    fn jwk_is_serialized_as_expected() {
        let json = serde_json::to_value(jwk(Uuid::nil(), &[0u8; 32])).unwrap();
        assert_eq!(json["kty"], "OKP");
        assert_eq!(json["crv"], "Ed25519");
        assert_eq!(json["alg"], "EdDSA");
        assert_eq!(json["use"], "sig");
        assert_eq!(json["kid"], Uuid::nil().to_string());
        assert_eq!(json["x"].as_str().unwrap().len(), 43);
    }

    #[test]
    fn signing_key_hands_over_at_the_new_key_activation() {
        let now = Utc::now();
        let takeover = now + TimeDelta::hours(24);
        let keys = SigningKeys::for_tests_with(&[
            (now - TimeDelta::days(30), Some(takeover)),
            (takeover, None),
        ]);
        let (old, new) = (keys.keys[1].kid, keys.keys[0].kid);

        assert_eq!(keys.signing_key(now).unwrap().kid, old);
        assert_eq!(
            keys.signing_key(takeover - TimeDelta::seconds(1))
                .unwrap()
                .kid,
            old
        );
        assert_eq!(keys.signing_key(takeover).unwrap().kid, new);
        assert_eq!(
            keys.jwks.keys.len(),
            2,
            "both published during the handover"
        );
    }

    #[test]
    fn no_signing_key_when_all_are_retired() {
        let now = Utc::now();
        let keys = SigningKeys::for_tests_with(&[(
            now - TimeDelta::days(2),
            Some(now - TimeDelta::hours(1)),
        )]);
        assert!(keys.signing_key(now).is_none());
    }
}
