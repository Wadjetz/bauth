use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ClientsError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("client `{client}`: {reason}")]
    Invalid { client: String, reason: String },
}

/// Content of `bauth.toml`. Unknown keys are rejected so typos fail at startup.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    clients: Vec<Client>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub id: String,
    pub name: String,
    /// Compared byte for byte with the `redirect_uri` sent by the app.
    pub redirect_uris: Vec<String>,
    /// Lets `POST /registration` create accounts for this client. Off by default.
    #[serde(default)]
    pub allow_signup: bool,
    /// API that accepts this client's access tokens (`aud` claim). Defaults to the client id.
    pub audience: Option<String>,
    /// App page that receives `#token=…` to choose a new password. Enables password reset.
    pub password_reset_url: Option<String>,
    /// App page that receives `#token=…` to finish a magic link login. Enables magic links.
    pub magic_link_url: Option<String>,
    /// App page that receives `#token=…` to confirm an email address and sends it to
    /// `POST /verification/confirm`: registration with a password, verification resend, and the
    /// new address of an email change. Required by those three routes.
    pub verification_url: Option<String>,
    /// Browser origins allowed to call bauth (CORS), on top of the origins of the http(s) URLs above.
    /// For apps whose origin appears in no URL, like Tauri: `tauri://localhost`, `http://tauri.localhost`.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Rules shared by every URL of a client: absolute, no fragment, and one of
/// - `https`,
/// - `http` on localhost (development),
/// - a native app's private-use scheme named after a domain it owns, like
///   `com.example.app:/auth/callback` (RFC 8252 §7.1). The dot rules out `javascript:`, `data:`…
fn check_url(field: &str, url: &str) -> Result<Url, String> {
    let parsed = Url::parse(url).map_err(|e| format!("{field} `{url}`: {e}"))?;
    if parsed.fragment().is_some() {
        return Err(format!("{field} `{url}` must not contain a fragment"));
    }
    let scheme = parsed.scheme();
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let allowed = scheme == "https" || (scheme == "http" && loopback) || scheme.contains('.');
    if !allowed {
        return Err(format!(
            "{field} `{url}` must use https, http on localhost, or an app scheme like `fr.example.app:/callback`"
        ));
    }
    Ok(parsed)
}

/// `scheme://host[:port]`. Built by hand because `Url::origin()` is opaque for custom schemes
/// like `tauri://`. `None` for URLs without a host (`com.example.app:/callback`).
pub fn origin_of(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

impl Client {
    /// Origins that may call bauth from a browser for this client.
    pub fn origins(&self) -> impl Iterator<Item = String> + '_ {
        self.redirect_uris
            .iter()
            .map(String::as_str)
            .chain(self.password_reset_url.as_deref())
            .chain(self.magic_link_url.as_deref())
            .chain(self.verification_url.as_deref())
            .filter_map(|url| Url::parse(url).ok())
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .filter_map(|url| origin_of(&url))
            .chain(self.allowed_origins.iter().cloned())
    }

    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|allowed| allowed == redirect_uri)
    }

    fn validate(&self) -> Result<(), ClientsError> {
        let invalid = |reason: String| ClientsError::Invalid {
            client: self.id.clone(),
            reason,
        };

        let valid_id = !self.id.is_empty()
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !valid_id {
            return Err(invalid("id must match [a-z0-9_-]+".into()));
        }
        if self.redirect_uris.is_empty() {
            return Err(invalid("at least one redirect_uri is required".into()));
        }
        for uri in &self.redirect_uris {
            let parsed =
                Url::parse(uri).map_err(|e| invalid(format!("redirect_uri `{uri}`: {e}")))?;
            // Byte-for-byte matching only works if the configured value is already canonical.
            if parsed.as_str() != uri {
                return Err(invalid(format!(
                    "redirect_uri `{uri}` must be written `{parsed}`"
                )));
            }

            check_url("redirect_uri", uri).map_err(invalid)?;
        }

        if let Some(url) = &self.password_reset_url {
            check_url("password_reset_url", url).map_err(invalid)?;
        }
        if let Some(url) = &self.magic_link_url {
            check_url("magic_link_url", url).map_err(invalid)?;
        }
        if let Some(url) = &self.verification_url {
            check_url("verification_url", url).map_err(invalid)?;
        }
        for origin in &self.allowed_origins {
            // Compared byte for byte with the browser's `Origin` header.
            let parsed = Url::parse(origin)
                .map_err(|e| invalid(format!("allowed_origin `{origin}`: {e}")))?;
            if origin_of(&parsed).as_deref() != Some(origin.as_str()) {
                return Err(invalid(format!(
                    "allowed_origin `{origin}` must be an origin like `https://app.example.com` (no path, no trailing slash)"
                )));
            }
        }

        Ok(())
    }

    pub fn audience(&self) -> &str {
        self.audience.as_deref().unwrap_or(&self.id)
    }
}

/// Registered OAuth clients, loaded once at startup.
#[derive(Debug)]
pub struct Clients(HashMap<String, Client>);

impl Clients {
    pub fn load(path: &Path) -> Result<Self, ClientsError> {
        let content = std::fs::read_to_string(path).map_err(|source| ClientsError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&content)
    }

    pub fn from_toml(content: &str) -> Result<Self, ClientsError> {
        let file: FileConfig = toml::from_str(content)?;
        let mut clients = HashMap::new();
        for client in file.clients {
            client.validate()?;
            if clients.contains_key(&client.id) {
                return Err(ClientsError::Invalid {
                    client: client.id,
                    reason: "duplicate id".into(),
                });
            }
            clients.insert(client.id.clone(), client);
        }
        Ok(Self(clients))
    }

    pub fn get(&self, id: &str) -> Option<&Client> {
        self.0.get(id)
    }

    /// Every client's browser origins, deduplicated.
    pub fn origins(&self) -> BTreeSet<String> {
        self.0.values().flat_map(Client::origins).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        [[clients]]
        id = "my-app"
        name = "My App"
        redirect_uris = ["http://localhost:5173/auth/callback", "https://app.example.com/auth/callback"]
        allow_signup = true
    "#;

    fn error_of(toml: &str) -> String {
        Clients::from_toml(toml).unwrap_err().to_string()
    }

    #[test]
    fn loads_valid_clients() {
        let clients = Clients::from_toml(VALID).unwrap();
        let client = clients.get("my-app").unwrap();
        assert!(client.allow_signup);
        assert!(client.allows_redirect_uri("http://localhost:5173/auth/callback"));
        assert!(clients.get("unknown").is_none());
    }

    #[test]
    fn accepts_native_app_schemes() {
        let toml = r#"
            [[clients]]
            id = "my-app-mobile"
            name = "My App"
            redirect_uris = ["com.example.app:/auth/callback"]
            magic_link_url = "com.example.app:/auth/magic-link"
        "#;
        let clients = Clients::from_toml(toml).unwrap();
        let client = clients.get("my-app-mobile").unwrap();
        assert!(client.allows_redirect_uri("com.example.app:/auth/callback"));
        assert!(!client.allows_redirect_uri("com.example.app:/auth/callback/"));

        let base = |uri: &str| {
            format!("[[clients]]\nid = \"app\"\nname = \"App\"\nredirect_uris = [\"{uri}\"]")
        };
        for uri in [
            "javascript:alert(1)",
            "data:text/html,hi",
            "myapp:/callback",
        ] {
            assert!(
                Clients::from_toml(&base(uri)).is_err(),
                "{uri} should be rejected"
            );
        }
    }

    #[test]
    fn origins_come_from_urls_and_allowed_origins() {
        let toml = r#"
            [[clients]]
            id = "my-app"
            name = "My App"
            redirect_uris = ["http://localhost:8025/auth/callback", "https://app.example.com/auth/callback"]
            magic_link_url = "https://app.example.com/auth/magic-link"
            password_reset_url = "https://www.example.com:8443/reset"
            verification_url = "https://verify.example.com/email"

            [[clients]]
            id = "my-app-mobile"
            name = "My App"
            redirect_uris = ["com.example.app:/auth/callback"]
            allowed_origins = ["tauri://localhost", "http://tauri.localhost"]
        "#;
        let origins: Vec<_> = Clients::from_toml(toml)
            .unwrap()
            .origins()
            .into_iter()
            .collect();
        assert_eq!(
            origins,
            [
                "http://localhost:8025",
                "http://tauri.localhost",
                "https://app.example.com",
                "https://verify.example.com",
                "https://www.example.com:8443",
                "tauri://localhost",
            ]
        );
    }

    #[test]
    fn rejects_allowed_origins_that_are_not_origins() {
        let base = |origin: &str| {
            format!(
                "[[clients]]\nid = \"app\"\nname = \"App\"\nredirect_uris = [\"https://a.fr/cb\"]\nallowed_origins = [\"{origin}\"]"
            )
        };
        for origin in ["https://a.fr/", "https://a.fr/path", "a.fr", "*"] {
            assert!(
                Clients::from_toml(&base(origin)).is_err(),
                "{origin} should be rejected"
            );
        }
        assert!(Clients::from_toml(&base("https://a.fr")).is_ok());
    }

    #[test]
    fn redirect_uri_match_is_exact() {
        let clients = Clients::from_toml(VALID).unwrap();
        let client = clients.get("my-app").unwrap();
        for uri in [
            "http://localhost:5173/auth/callback/",
            "http://localhost:5173/auth/callback?x=1",
            "http://LOCALHOST:5173/auth/callback",
            "https://app.example.com/auth/callback.evil.com",
        ] {
            assert!(!client.allows_redirect_uri(uri), "{uri} should be rejected");
        }
    }

    #[test]
    fn rejects_invalid_config() {
        let base = |extra: &str| format!("[[clients]]\nid = \"app\"\nname = \"App\"\n{extra}");
        assert!(error_of(&base("redirect_uris = []")).contains("at least one"));
        assert!(error_of(&base(r#"redirect_uris = ["http://example.com/cb"]"#)).contains("https"));
        assert!(
            error_of(&base(r#"redirect_uris = ["https://example.com"]"#))
                .contains("must be written `https://example.com/`")
        );
        assert!(
            error_of(&base(r#"redirect_uris = ["https://example.com/cb#x"]"#)).contains("fragment")
        );
        assert!(
            error_of(&base(
                "redirect_uris = [\"https://a.fr/cb\"]\nallow_sigup = true"
            ))
            .contains("unknown field")
        );
        assert!(
            error_of(
                "[[clients]]\nid = \"Bad Id\"\nname = \"x\"\nredirect_uris = [\"https://a.fr/cb\"]"
            )
            .contains("id must match")
        );
        let dup = format!("{0}\n{0}", base(r#"redirect_uris = ["https://a.fr/cb"]"#));
        assert!(error_of(&dup).contains("duplicate id"));

        assert!(
            error_of(&base(
                "redirect_uris = [\"https://a.fr/cb\"]\npassword_reset_url = \"http://a.fr/reset\""
            ))
            .contains("password_reset_url")
        );
    }
}
