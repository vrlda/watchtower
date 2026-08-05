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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub ts: i64,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub id: String,
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
    pub ts: i64,
    pub version: String,
    pub queue_len: usize,
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
            evidence: vec![Evidence { ts: 999, source: "systemd".into(), detail: "ActiveState=failed".into() }],
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["kind"], "ServiceFailed");
        assert_eq!(v["severity"], "Critical");
        assert_eq!(v["evidence"][0]["source"], "systemd");
    }

    #[test]
    fn severity_ordering_critical_gt_warning_gt_info() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn heartbeat_serializes() {
        let hb = Heartbeat { host_id: "h-1".into(), ts: 5, version: "0.1.0".into(), queue_len: 2 };
        let v: serde_json::Value = serde_json::to_value(&hb).unwrap();
        assert_eq!(v["queue_len"], 2);
    }
}
