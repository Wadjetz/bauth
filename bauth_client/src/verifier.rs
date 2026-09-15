use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bauth_core::AccessTokenClaims;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Refetch the JWKS at least this often, to pick up rotated keys.
const JWKS_MAX_AGE: Duration = Duration::from_secs(60 * 60);
/// A token with an unknown `kid` triggers a refetch, but not more often than this,
/// so garbage tokens can't make every request hit bauth.
const MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Tolerated clock difference between bauth and this API.
const LEEWAY_SECONDS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("token is not a bauth access token")]
    Malformed,
    #[error("token is signed with an unknown key")]
    UnknownKey,
    #[error("token is invalid: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),
    #[error("cannot fetch the bauth JWKS: {0}")]
    Jwks(#[from] reqwest::Error),
}

/// The authenticated user behind a verified access token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub client_id: String,
    pub claims: AccessTokenClaims,
}

/// Verifies access tokens against the JWKS of a bauth issuer. Cheap to clone.
#[derive(Clone)]
pub struct Verifier {
    inner: Arc<Inner>,
}

struct Inner {
    jwks_uri: String,
    http: reqwest::Client,
    validation: Validation,
    cache: RwLock<KeyCache>,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
}

impl KeyCache {
    fn is_stale(&self) -> bool {
        self.fetched_at
            .is_none_or(|at| at.elapsed() >= JWKS_MAX_AGE)
    }

    fn can_refetch(&self) -> bool {
        self.fetched_at
            .is_none_or(|at| at.elapsed() >= MIN_REFETCH_INTERVAL)
    }

    fn replace(&mut self, jwks: &JwkSet) {
        self.keys = jwks
            .keys
            .iter()
            .filter_map(|jwk| Some((jwk.common.key_id.clone()?, DecodingKey::from_jwk(jwk).ok()?)))
            .collect();
        self.fetched_at = Some(Instant::now());
    }
}

impl Verifier {
    /// `issuer`: bauth base URL, exactly as in the `iss` claim (no trailing slash).
    /// `audience`: this API's name, as configured in the clients' `audience`.
    /// The JWKS is fetched lazily, on the first verification.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        let issuer = issuer.into();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&issuer]);
        validation.set_audience(&[audience.into()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY_SECONDS;

        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("TLS backend is available");

        Self {
            inner: Arc::new(Inner {
                jwks_uri: format!("{issuer}/.well-known/jwks.json"),
                http,
                validation,
                cache: RwLock::default(),
            }),
        }
    }

    pub async fn verify(&self, token: &str) -> Result<AuthUser, VerifyError> {
        let header = decode_header(token).map_err(|_| VerifyError::Malformed)?;
        // Only access tokens: refuse other JWTs even if bauth signed them.
        if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some("at+jwt") {
            return Err(VerifyError::Malformed);
        }
        let kid = header.kid.ok_or(VerifyError::Malformed)?;
        let key = self.decoding_key(&kid).await?;

        let claims = decode::<AccessTokenClaims>(token, &key, &self.inner.validation)?.claims;
        Ok(AuthUser {
            id: claims.sub,
            client_id: claims.client_id.clone(),
            claims,
        })
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, VerifyError> {
        {
            let cache = self.inner.cache.read().await;
            if let Some(key) = cache.keys.get(kid)
                && !cache.is_stale()
            {
                return Ok(key.clone());
            }
        }

        let mut cache = self.inner.cache.write().await;
        // Another request may have refreshed while we waited for the lock.
        let needs_refresh = cache.is_stale() || !cache.keys.contains_key(kid);
        if needs_refresh && cache.can_refetch() {
            match self.fetch_jwks().await {
                Ok(jwks) => cache.replace(&jwks),
                // bauth unreachable: keep verifying with the keys we already have.
                Err(error) if !cache.keys.is_empty() => {
                    tracing::warn!(%error, "JWKS refresh failed, using cached keys");
                }
                Err(error) => return Err(error.into()),
            }
        }
        cache.keys.get(kid).cloned().ok_or(VerifyError::UnknownKey)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, reqwest::Error> {
        self.inner
            .http
            .get(&self.inner.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
}
