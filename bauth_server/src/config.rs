use envy::Error;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub base_uri: String,
    pub database_url: String,
    pub host: Option<String>,
    pub port: Option<usize>,
    pub admin_app_name: Option<String>,
}

impl Config {
    pub fn new() -> Result<Self, Error> {
        envy::from_env()
    }

    pub fn address(&self) -> String {
        let default_host = "0.0.0.0".to_owned();
        let host = self.host.as_ref().unwrap_or(&default_host);
        let port = self.port.unwrap_or(5000);
        format!("{}:{}", host, port)
    }

    pub fn admin_app_name(&self) -> String {
        self.admin_app_name
            .clone()
            .unwrap_or_else(|| "Bauth Admin Web Client".to_string())
    }
}
