use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Server configuration. SQLite in dev; Postgres later via the same sqlx API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Socket address to listen on. Default localhost only — the UI has no
    /// auth in M2, so do not expose it to the network.
    pub listen: String,
    /// sqlx database URL. "sqlite::memory:" works only for tests.
    pub db_url: String,
    /// Shared bearer token agents must present. Per-host tokens are M6.
    pub auth_token: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: "127.0.0.1:8787".into(),
            db_url: "sqlite:///var/lib/watchtower/watchtower.db".into(),
            auth_token: String::new(),
        }
    }
}

pub fn load(path: &PathBuf) -> ServerConfig {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!("invalid config {}: {}; using defaults", path.display(), e);
            ServerConfig::default()
        }),
        Err(e) => {
            eprintln!("no config at {} ({}); using defaults", path.display(), e);
            ServerConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_with_defaults() {
        let raw = "listen = \"0.0.0.0:9999\"\nauth_token = \"tok\"\n";
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9999");
        assert_eq!(cfg.auth_token, "tok");
        assert!(cfg.db_url.contains("watchtower.db"));
    }
}
