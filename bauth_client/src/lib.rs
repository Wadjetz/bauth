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

#[cfg(feature = "axum")]
mod extract;
mod verifier;

pub use bauth_core::AccessTokenClaims;
#[cfg(feature = "axum")]
pub use extract::AuthRejection;
pub use verifier::{AuthUser, Verifier, VerifyError};
