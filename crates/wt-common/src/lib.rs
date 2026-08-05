use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EventKind {
    Reboot,
    ServiceFailed,
    ServiceCrashLoop,
    DiskHigh,
    InodeHigh,
    CpuSpike,
    MemHigh,
    LoadHigh,
    SwapHigh,
    NetDevErrors,
    /// Emitted by the server's uptime checker, not the agent.
    HostUnreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// unix millis
    pub ts: i64,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub id: String,
    /// unix millis
    pub ts: i64,
    pub host_id: String,
    /// Dedup key within a kind, e.g. "svc:nginx" or "mount:/".
    pub key: String,
    pub kind: EventKind,
    pub severity: Severity,
    pub summary: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub host_id: String,
    /// unix millis
    pub ts: i64,
    pub version: String,
    pub queue_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub host_id: String,
    pub server_url: String,
    pub token: String,
    pub poll_interval_secs: u64,
    pub heartbeat_secs: u64,
    pub dedup_secs: i64,
    pub disk_warn_pct: f64,
    pub disk_crit_pct: f64,
    pub inode_crit_pct: f64,
    pub load_warn_ratio: f64,
    pub load_crit_ratio: f64,
    pub cpu_spike_ratio: f64,
    pub mem_warn_pct: f64,
    pub swap_warn_pct: f64,
    pub spool_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host_id: "auto".into(),
            server_url: String::new(),
            token: String::new(),
            poll_interval_secs: 15,
            heartbeat_secs: 30,
            dedup_secs: 300,
            disk_warn_pct: 80.0,
            disk_crit_pct: 90.0,
            inode_crit_pct: 90.0,
            load_warn_ratio: 2.0,
            load_crit_ratio: 4.0,
            cpu_spike_ratio: 2.5,
            mem_warn_pct: 85.0,
            swap_warn_pct: 50.0,
            spool_dir: "/var/lib/watchtower/spool".into(),
        }
    }
}

impl Config {
    pub fn host_id_valid(&self) -> bool {
        !self.host_id.trim().is_empty() && !self.host_id.trim().eq_ignore_ascii_case("auto")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_to_expected_json_shape() {
        let ev = AgentEvent {
            id: "e-1".into(),
            ts: 1000,
            host_id: "h-1".into(),
            key: "svc:nginx".into(),
            kind: EventKind::ServiceFailed,
            severity: Severity::Critical,
            summary: "nginx.service entered failed state".into(),
            evidence: vec![Evidence {
                ts: 999,
                source: "systemd".into(),
                detail: "ActiveState=failed".into(),
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["kind"], "ServiceFailed");
        assert_eq!(v["severity"], "Critical");
        assert_eq!(v["evidence"][0]["source"], "systemd");
    }

    #[test]
    fn host_unreachable_kind_serializes() {
        let v: serde_json::Value = serde_json::to_value(EventKind::HostUnreachable).unwrap();
        assert_eq!(v, "HostUnreachable");
    }

    #[test]
    fn severity_ordering_critical_gt_warning_gt_info() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn heartbeat_serializes() {
        let hb = Heartbeat {
            host_id: "h-1".into(),
            ts: 5,
            version: "0.1.0".into(),
            queue_len: 2,
        };
        let v: serde_json::Value = serde_json::to_value(&hb).unwrap();
        assert_eq!(v["queue_len"], 2);
    }

    #[test]
    fn config_parses_with_defaults() {
        let raw = "server_url = \"https://ctl.example.com\"\ntoken = \"abc\"\n";
        let cfg: Config = toml::from_str(raw).unwrap();
        assert_eq!(cfg.server_url, "https://ctl.example.com");
        assert_eq!(cfg.poll_interval_secs, 15);
        assert_eq!(cfg.disk_crit_pct, 90.0);
    }

    #[test]
    fn host_id_auto_is_invalid_for_shipping() {
        let cfg = Config::default();
        assert!(!cfg.host_id_valid());
    }

    #[test]
    fn host_id_valid_accepts_real_id_rejects_whitespace() {
        let cfg = Config {
            host_id: "abc123".into(),
            ..Config::default()
        };
        assert!(cfg.host_id_valid());
        let cfg = Config {
            host_id: "  ".into(),
            ..Config::default()
        };
        assert!(!cfg.host_id_valid());
        let cfg = Config {
            host_id: "Auto".into(),
            ..Config::default()
        };
        assert!(!cfg.host_id_valid());
    }
}
