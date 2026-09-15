use chrono::{DateTime, TimeDelta, Utc};
use jsonwebtoken::{Algorithm, Header, encode};
use uuid::Uuid;

pub use bauth_core::AccessTokenClaims;

use crate::clients::Client;
use crate::signing_keys::SigningKeys;

pub const ACCESS_TOKEN_TTL: TimeDelta = TimeDelta::minutes(15);

#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("no signing key is active")]
    NoSigningKey,
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub struct IssuedAccessToken {
    pub token: String,
    pub expires_in: i64,
}

pub fn issue(
    keys: &SigningKeys,
    issuer: &str,
    user_id: Uuid,
    session_id: Uuid,
    client: &Client,
    now: DateTime<Utc>,
) -> Result<IssuedAccessToken, IssueError> {
    let key = keys.signing_key(now).ok_or(IssueError::NoSigningKey)?;
    let claims = AccessTokenClaims {
        iss: issuer.to_owned(),
        sub: user_id,
        aud: client.audience().to_owned(),
        client_id: client.id.clone(),
        sid: session_id,
        iat: now.timestamp(),
        exp: (now + ACCESS_TOKEN_TTL).timestamp(),
        jti: Uuid::now_v7(),
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(key.kid.to_string());
    // Distinguishes access tokens from other JWTs (e.g. a future ID token).
    header.typ = Some("at+jwt".to_owned());
    Ok(IssuedAccessToken {
        token: encode(&header, &claims, &key.encoding_key)?,
        expires_in: ACCESS_TOKEN_TTL.num_seconds(),
    })
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

    use super::*;
    use crate::clients::Clients;

    const ISSUER: &str = "http://localhost:8401";

    fn client(extra: &str) -> Client {
        let toml = format!(
            "[[clients]]\nid = \"my-app-web\"\nname = \"My App\"\nredirect_uris = [\"http://localhost:8025/auth/callback\"]\n{extra}"
        );
        Clients::from_toml(&toml)
            .unwrap()
            .get("my-app-web")
            .unwrap()
            .clone()
    }

    fn validation(audience: &str) -> Validation {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[audience]);
        validation
    }

    #[test]
    fn issued_token_verifies_against_jwks() {
        let keys = SigningKeys::for_tests();
        let user_id = Uuid::now_v7();
        let issued = issue(
            &keys,
            ISSUER,
            user_id,
            Uuid::now_v7(),
            &client("audience = \"my-app\""),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(issued.expires_in, 900);

        let header = decode_header(&issued.token).unwrap();
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        let jwk = keys.jwks.find(header.kid.as_deref().unwrap()).unwrap();

        let claims = decode::<AccessTokenClaims>(
            &issued.token,
            &DecodingKey::from_jwk(jwk).unwrap(),
            &validation("my-app"),
        )
        .unwrap()
        .claims;
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.aud, "my-app");
        assert_eq!(claims.client_id, "my-app-web");
        assert_eq!(claims.exp - claims.iat, 900);
    }

    #[test]
    fn audience_defaults_to_client_id_and_is_enforced() {
        let keys = SigningKeys::for_tests();
        let issued = issue(
            &keys,
            ISSUER,
            Uuid::now_v7(),
            Uuid::now_v7(),
            &client(""),
            Utc::now(),
        )
        .unwrap();
        let key = DecodingKey::from_jwk(&keys.jwks.keys[0]).unwrap();
        assert!(
            decode::<AccessTokenClaims>(&issued.token, &key, &validation("my-app-web")).is_ok()
        );
        assert!(
            decode::<AccessTokenClaims>(&issued.token, &key, &validation("other-api")).is_err()
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let keys = SigningKeys::for_tests();
        let issued = issue(
            &keys,
            ISSUER,
            Uuid::now_v7(),
            Uuid::now_v7(),
            &client(""),
            Utc::now() - TimeDelta::hours(1),
        )
        .unwrap();
        let key = DecodingKey::from_jwk(&keys.jwks.keys[0]).unwrap();
        assert!(
            decode::<AccessTokenClaims>(&issued.token, &key, &validation("my-app-web")).is_err()
        );
    }
}
