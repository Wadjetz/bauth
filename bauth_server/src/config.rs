use std::net::SocketAddr;

use envconfig::Envconfig;

#[derive(Clone, Envconfig)]
pub struct ServerConfig {
    #[envconfig(from = "BAUTH_BIND_ADDR", default = "0.0.0.0:3000")]
    pub bind_addr: SocketAddr,
    #[envconfig(from = "BAUTH_DATABASE_URL")]
    pub database_url: String,
    #[envconfig(from = "BAUTH_SMTP_URL", default = "smtp://localhost:1025")]
    pub smtp_url: String,
    #[envconfig(from = "BAUTH_MAIL_FROM", default = "bauth <no-reply@example.com>")]
    pub mail_from: String,
    #[envconfig(
        from = "BAUTH_VERIFICATION_URL",
        default = "http://localhost:8401/verify-email"
    )]
    pub verification_url: String,
    #[envconfig(from = "BAUTH_CONFIG", default = "bauth.toml")]
    pub config_path: std::path::PathBuf,
    #[envconfig(from = "BAUTH_MASTER_KEY")]
    pub master_key: String,
    /// Public base URL of bauth, used as the `iss` claim. No trailing slash.
    #[envconfig(from = "BAUTH_ISSUER", default = "http://localhost:8401")]
    pub issuer: String,
    /// Comma-separated IPs of reverse proxies and app servers allowed to set `X-Forwarded-For`.
    #[envconfig(from = "BAUTH_TRUSTED_PROXIES", default = "")]
    pub trusted_proxies: String,
}

/// Tokens are compared on `iss` byte for byte: reject anything but a bare origin (+ optional path).
pub fn validate_issuer(issuer: &str) -> Result<(), String> {
    let url = url::Url::parse(issuer).map_err(|e| format!("BAUTH_ISSUER `{issuer}`: {e}"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(format!(
            "BAUTH_ISSUER `{issuer}` must use https (http only for localhost)"
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "BAUTH_ISSUER `{issuer}` must not have a query or fragment"
        ));
    }
    if issuer.ends_with('/') {
        return Err(format!("BAUTH_ISSUER `{issuer}` must not end with `/`"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_issuer;

    #[test]
    fn issuer_validation() {
        assert!(validate_issuer("https://auth.example.com").is_ok());
        assert!(validate_issuer("http://localhost:8401").is_ok());
        assert!(validate_issuer("https://auth.example.com/").is_err());
        assert!(validate_issuer("http://auth.example.com").is_err());
        assert!(validate_issuer("https://auth.example.com?x=1").is_err());
        assert!(validate_issuer("auth.example.com").is_err());
    }
}
