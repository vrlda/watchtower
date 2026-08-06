use serde::{Deserialize, Serialize};

pub mod civil;

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
    /// SSH login that succeeded (Info; Warning on a first-seen source IP).
    SshLogin,
    /// A failed SSH authentication attempt (Warning; episodes escalate to
    /// SshBruteForce).
    SshFailed,
    /// >= threshold failed SSH logins for one (user, ip) within a window.
    SshBruteForce,
    /// A login as root over ssh or su (Warning; Critical on first-seen IP).
    RootLogin,
    /// A successful sudo invocation (Info — timeline context).
    SudoUsed,
    /// A configured important file changed (Warning).
    FileChanged,
    /// A new listening port appeared (Warning).
    NewListeningPort,
    /// A connection to a previously unseen remote IP (Warning).
    NewOutboundConnection,
    /// Established-connection rate deviated from the rolling baseline (Warning).
    ConnectionRateSpike,
    /// A systemd unit transitioned to active (Info — timeline context).
    /// Emitted by the agent's journald sensor.
    ServiceRestarted,
    /// Server-generated: a host's heartbeat stopped arriving within the
    /// grace period (Critical).
    AgentHeartbeatMissing,
    /// Server-generated: a host's telemetry spool queue is growing (Warning).
    AgentQueueGrowing,
    /// Error-pattern count in application logs exceeded the threshold
    /// within the window (Warning).
    ErrorRateSpike,
    /// A tracked container stopped or exited (Warning).
    ContainerStopped,
    /// A container is crash-looping (restarting repeatedly) (Critical).
    ContainerCrashLoop,
    /// A TLS certificate is nearing expiry or expired (Warning/Critical).
    CertExpiring,
    /// The kernel OOM killer terminated a process (Critical).
    OomKill,
    /// Kernel panic evidence in the journal (Critical).
    KernelPanic,
    /// A mounted filesystem went read-only (Critical).
    FsReadOnly,
    /// The system clock was adjusted (NTP step) (Warning).
    ClockChange,
    /// Request volume from access logs exceeded the threshold within the
    /// window (Warning).
    RequestRateSpike,
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
    /// Files (absolute paths) watched for modification by the FIM sensor.
    #[serde(default)]
    pub watch_paths: Vec<String>,
    /// Regex patterns counted as application errors in journald lines.
    #[serde(default)]
    pub error_patterns: Vec<String>,
    /// Seconds window for error counting.
    pub error_window_secs: i64,
    /// Errors within the window that trigger an ErrorRateSpike.
    pub error_threshold: u32,
    /// Watch Docker container states (docker binary required).
    pub docker_enabled: bool,
    /// Certificate paths (files or globs) to scan for expiry. Defaults to
    /// common locations when empty.
    #[serde(default)]
    pub cert_paths: Vec<String>,
    /// Days before expiry that raise a Warning.
    pub cert_warn_days: i64,
    /// Days before expiry that raise a Critical.
    pub cert_crit_days: i64,
    /// Seconds between certificate scans (they spawn openssl per cert).
    pub cert_scan_interval_secs: i64,
    /// Failed logins for one (user, ip) within the window that constitute a
    /// brute-force episode.
    pub ssh_brute_threshold: u32,
    /// Seconds window for brute-force counting.
    pub ssh_brute_window_secs: u64,
    /// Access log files (nginx/apache combined format) to tail for 5xx and
    /// request-rate signals. Empty = sensor off.
    #[serde(default)]
    pub access_log_paths: Vec<String>,
    /// Requests within the window that trigger a RequestRateSpike.
    pub request_rate_threshold: u32,
    /// Seconds window for request-rate counting.
    pub request_rate_window_secs: i64,
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
            watch_paths: Vec::new(),
            error_patterns: Vec::new(),
            error_window_secs: 300,
            error_threshold: 10,
            docker_enabled: true,
            cert_paths: Vec::new(),
            cert_warn_days: 14,
            cert_crit_days: 3,
            cert_scan_interval_secs: 3600,
            ssh_brute_threshold: 5,
            ssh_brute_window_secs: 300,
            access_log_paths: Vec::new(),
            request_rate_threshold: 200,
            request_rate_window_secs: 60,
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

    #[test]
    fn security_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::SshLogin, "SshLogin"),
            (EventKind::SshFailed, "SshFailed"),
            (EventKind::SshBruteForce, "SshBruteForce"),
            (EventKind::RootLogin, "RootLogin"),
            (EventKind::SudoUsed, "SudoUsed"),
            (EventKind::FileChanged, "FileChanged"),
            (EventKind::NewListeningPort, "NewListeningPort"),
            (EventKind::NewOutboundConnection, "NewOutboundConnection"),
            (EventKind::ConnectionRateSpike, "ConnectionRateSpike"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn config_has_security_fields() {
        let cfg = Config::default();
        assert_eq!(cfg.ssh_brute_threshold, 5);
        assert_eq!(cfg.ssh_brute_window_secs, 300);
        assert!(cfg.watch_paths.is_empty());
    }

    #[test]
    fn m4_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::ServiceRestarted, "ServiceRestarted"),
            (EventKind::AgentHeartbeatMissing, "AgentHeartbeatMissing"),
            (EventKind::AgentQueueGrowing, "AgentQueueGrowing"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn m5_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::ErrorRateSpike, "ErrorRateSpike"),
            (EventKind::ContainerStopped, "ContainerStopped"),
            (EventKind::ContainerCrashLoop, "ContainerCrashLoop"),
            (EventKind::CertExpiring, "CertExpiring"),
            (EventKind::OomKill, "OomKill"),
            (EventKind::KernelPanic, "KernelPanic"),
            (EventKind::FsReadOnly, "FsReadOnly"),
            (EventKind::ClockChange, "ClockChange"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn config_has_m5_fields() {
        let cfg = Config::default();
        assert!(cfg.error_patterns.is_empty());
        assert_eq!(cfg.error_window_secs, 300);
        assert_eq!(cfg.error_threshold, 10);
        assert!(cfg.docker_enabled);
        assert_eq!(cfg.cert_warn_days, 14);
        assert_eq!(cfg.cert_crit_days, 3);
        assert_eq!(cfg.cert_scan_interval_secs, 3600);
    }

    #[test]
    fn p2t5_kind_serializes() {
        let v: serde_json::Value = serde_json::to_value(EventKind::RequestRateSpike).unwrap();
        assert_eq!(v, "RequestRateSpike");
    }

    #[test]
    fn config_has_accesslog_fields() {
        let cfg = Config::default();
        assert!(cfg.access_log_paths.is_empty());
        assert_eq!(cfg.request_rate_threshold, 200);
        assert_eq!(cfg.request_rate_window_secs, 60);
    }
}
