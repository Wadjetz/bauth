//! Verify bauth access tokens in an API.
//!
//! ```no_run
//! # async fn example(token: &str) -> Result<(), bauth_client::VerifyError> {
//! use bauth_client::Verifier;
//!
//! let verifier = Verifier::new("https://auth.example.com", "my-app");
//! let user = verifier.verify(token).await?;
//! println!("{} via {}", user.id, user.client_id);
//! # Ok(())
//! # }
//! ```
//!
//! With the `axum` feature, extract the user directly in handlers: see `AuthUser`'s extractors.
//! `Verifier::me` asks bauth for the account of a token (its email: tokens don't carry it).
//! The `test-support` feature brings `testing::FakeBauth`, a bauth issuer for an API's tests.

#[cfg(feature = "axum")]
mod extract;
#[cfg(feature = "test-support")]
pub mod testing;
mod verifier;

pub use bauth_core::AccessTokenClaims;
#[cfg(feature = "axum")]
pub use extract::AuthRejection;
#[cfg(feature = "axum")]
pub use extract::bearer_token;
pub use verifier::AuthUser;
pub use verifier::Me;
pub use verifier::MeError;
pub use verifier::Verifier;
pub use verifier::VerifyError;
