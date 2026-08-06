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
    scan_interval_secs: Option<i64>,
    #[serde(default)]
    rule: Vec<crate::correlation::Rule>,
    rules: Option<Vec<crate::correlation::Rule>>,
    notify: Option<crate::notify::NotifyConfig>,
    ui_base_url: Option<String>,
    watchdog_heartbeat_grace_secs: Option<i64>,
    watchdog_queue_threshold: Option<i64>,
}

impl From<ServerConfigToml> for ServerConfig {
    fn from(t: ServerConfigToml) -> Self {
        let defaults = ServerConfig::default();
        let mut probes = t.probe;
        probes.extend(t.probes);
        let mut rules = t.rule;
        rules.extend(t.rules.unwrap_or_default());
        ServerConfig {
            listen: t.listen.unwrap_or(defaults.listen),
            db_url: t.db_url.unwrap_or(defaults.db_url),
            auth_token: t.auth_token.unwrap_or(defaults.auth_token),
            probes,
            scan_interval_secs: t.scan_interval_secs.unwrap_or(defaults.scan_interval_secs),
            rules,
            notify: t.notify.unwrap_or(defaults.notify),
            ui_base_url: t.ui_base_url.unwrap_or(defaults.ui_base_url),
            watchdog_heartbeat_grace_secs: t
                .watchdog_heartbeat_grace_secs
                .unwrap_or(defaults.watchdog_heartbeat_grace_secs),
            watchdog_queue_threshold: t
                .watchdog_queue_threshold
                .unwrap_or(defaults.watchdog_queue_threshold),
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
    /// Correlation scan interval (seconds).
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: i64,
    /// Correlation rules; entries override built-in defaults by id.
    #[serde(default)]
    pub rules: Vec<crate::correlation::Rule>,
    /// Notification channels and per-severity routing.
    #[serde(default)]
    pub notify: crate::notify::NotifyConfig,
    /// UI base URL for links in notifications.
    #[serde(default)]
    pub ui_base_url: String,
    /// Seconds a host may go without a heartbeat before the watchdog fires.
    #[serde(default = "default_heartbeat_grace")]
    pub watchdog_heartbeat_grace_secs: i64,
    /// Spool queue length that triggers AgentQueueGrowing.
    #[serde(default = "default_queue_threshold")]
    pub watchdog_queue_threshold: i64,
}

fn default_heartbeat_grace() -> i64 {
    90
}

fn default_queue_threshold() -> i64 {
    100
}

fn default_scan_interval() -> i64 {
    10
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: "127.0.0.1:8787".into(),
            db_url: "sqlite:///var/lib/watchtower/watchtower.db".into(),
            auth_token: String::new(),
            probes: Vec::new(),
            scan_interval_secs: default_scan_interval(),
            rules: Vec::new(),
            notify: crate::notify::NotifyConfig::default(),
            ui_base_url: "http://127.0.0.1:8787".into(),
            watchdog_heartbeat_grace_secs: default_heartbeat_grace(),
            watchdog_queue_threshold: default_queue_threshold(),
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

    #[test]
    fn rules_accept_both_toml_keys() {
        let raw = "[[rule]]\nid = \"a\"\ntrigger = \"CpuSpike\"\nseverity = \"Warning\"\nheadline = \"x\"\n[[rules]]\nid = \"b\"\ntrigger = \"CpuSpike\"\nseverity = \"Warning\"\nheadline = \"y\"\n";
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].id, "a");
        assert_eq!(cfg.rules[1].id, "b");
    }
}
