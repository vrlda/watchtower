use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::probes::ProbeConfig;

/// TOML intermediate for `ServerConfig`: accepts both `[[probe]]` and
/// `[[probes]]` keys and merges them, so older docs keep working and no
/// config is silently dropped.
#[derive(Debug, Clone, Deserialize)]
struct ServerConfigToml {
    listen: Option<String>,
    db_url: Option<String>,
    auth_token: Option<String>,
    #[serde(default)]
    probe: Vec<ProbeConfig>,
    #[serde(default)]
    probes: Vec<ProbeConfig>,
}

impl From<ServerConfigToml> for ServerConfig {
    fn from(t: ServerConfigToml) -> Self {
        let defaults = ServerConfig::default();
        let mut probes = t.probe;
        probes.extend(t.probes);
        ServerConfig {
            listen: t.listen.unwrap_or(defaults.listen),
            db_url: t.db_url.unwrap_or(defaults.db_url),
            auth_token: t.auth_token.unwrap_or(defaults.auth_token),
            probes,
        }
    }
}

/// Server configuration. SQLite in dev; Postgres later via the same sqlx API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "ServerConfigToml")]
pub struct ServerConfig {
    /// Socket address to listen on. Default localhost only — the UI has no
    /// auth in M2, so do not expose it to the network.
    pub listen: String,
    /// sqlx database URL. "sqlite::memory:" works only for tests.
    pub db_url: String,
    /// Shared bearer token agents must present. Per-host tokens are M6.
    pub auth_token: String,
    /// External endpoints to probe for reachability. Accepts both
    /// `[[probe]]` and `[[probes]]` TOML keys (alias for docs compatibility).
    pub probes: Vec<ProbeConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: "127.0.0.1:8787".into(),
            db_url: "sqlite:///var/lib/watchtower/watchtower.db".into(),
            auth_token: String::new(),
            probes: Vec::new(),
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

    #[test]
    fn probes_accept_both_toml_keys() {
        let raw = "[[probe]]\nurl = \"http://a\"\n[[probes]]\nurl = \"http://b\"\n";
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.probes.len(), 2);
        assert_eq!(cfg.probes[0].url, "http://a");
        assert_eq!(cfg.probes[1].url, "http://b");
    }
}
