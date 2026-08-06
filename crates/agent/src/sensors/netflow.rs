use std::collections::HashSet;

use crate::engine::SpikeDetector;
use crate::procfs::{ProcFs, TcpEntry};
use wt_common::{AgentEvent, EventKind, Evidence, Severity};

/// Snapshot state for network monitoring: previous listen/remote sets and a
/// rolling detector on the established-connection count.
// wired in engine Task 6
#[allow(dead_code)]
pub struct NetState {
    prev_listen: HashSet<String>,
    prev_remote: HashSet<String>,
    prev_count: usize,
    rate_detector: SpikeDetector,
}

impl Default for NetState {
    fn default() -> Self {
        NetState {
            prev_listen: HashSet::new(),
            prev_remote: HashSet::new(),
            prev_count: 0,
            rate_detector: SpikeDetector::new(20, 2.5),
        }
    }
}

impl NetState {
    /// Observe the current network state at ts_ms; emit events for changes.
    // wired in engine Task 6
    #[allow(dead_code)]
    pub fn observe(&mut self, p: &ProcFs, ts: i64) -> Vec<AgentEvent> {
        let mut evs = Vec::new();
        let listen: HashSet<String> = entries(p, "LISTEN")
            .into_iter()
            .map(|e| format!("tcp:{}:{}", e.local_ip, e.local_port))
            .collect();
        let remote: HashSet<String> = entries(p, "ESTABLISHED")
            .into_iter()
            .map(|e| e.remote_ip.clone())
            .filter(|ip| ip != "0.0.0.0" && ip != "::")
            .collect();
        let count = entries(p, "ESTABLISHED").len();

        for new in listen.difference(&self.prev_listen) {
            evs.push(AgentEvent {
                id: format!("port-{}-{}", new, ts),
                ts,
                // host_id parameterized in engine Task 6
                host_id: "h".into(),
                key: format!("port:{}", new),
                kind: EventKind::NewListeningPort,
                severity: Severity::Warning,
                summary: format!("new listening port: {}", new),
                evidence: vec![Evidence {
                    ts,
                    source: "netflow".into(),
                    detail: format!("Entry={}", new),
                }],
            });
        }
        for new in remote.difference(&self.prev_remote) {
            evs.push(AgentEvent {
                id: format!("out-{}-{}", new, ts),
                ts,
                // host_id parameterized in engine Task 6
                host_id: "h".into(),
                key: format!("net:out:{}", new),
                kind: EventKind::NewOutboundConnection,
                severity: Severity::Warning,
                summary: format!("new outbound connection to {}", new),
                evidence: vec![Evidence {
                    ts,
                    source: "netflow".into(),
                    detail: format!("RemoteIp={}", new),
                }],
            });
        }

        self.rate_detector.push(count as f64);
        if self.prev_count > 0 && self.rate_detector.is_spike(count as f64) {
            evs.push(AgentEvent {
                id: format!("rate-{}", ts),
                ts,
                // host_id parameterized in engine Task 6
                host_id: "h".into(),
                key: "net:rate".into(),
                kind: EventKind::ConnectionRateSpike,
                severity: Severity::Warning,
                summary: format!("established-connection count spiked to {}", count),
                evidence: vec![Evidence {
                    ts,
                    source: "netflow".into(),
                    detail: format!("Established={}", count),
                }],
            });
        }

        self.prev_listen = listen;
        self.prev_remote = remote;
        self.prev_count = count;
        evs
    }
}

// wired in engine Task 6
#[allow(dead_code)]
fn entries(p: &ProcFs, state: &str) -> Vec<TcpEntry> {
    let mut out = Vec::new();
    for e in p
        .tcp_entries()
        .unwrap_or_default()
        .into_iter()
        .chain(p.tcp6_entries().unwrap_or_default())
    {
        if e.state == state {
            out.push(e);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wt_common::{EventKind, Severity};

    fn procfs() -> crate::procfs::ProcFs {
        crate::procfs::ProcFs::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        )
    }

    #[test]
    fn new_listening_port_and_outbound_emitted_then_quiet() {
        let p = procfs();
        let mut state = NetState::default();
        let evs = state.observe(&p, 1000);
        let port_ev = evs
            .iter()
            .find(|e| e.key == "port:tcp:127.0.0.1:8080")
            .expect("port event");
        assert_eq!(port_ev.kind, EventKind::NewListeningPort);
        assert_eq!(port_ev.severity, Severity::Warning);
        let out_ev = evs
            .iter()
            .find(|e| e.key == "net:out:93.184.216.47")
            .expect("outbound event");
        assert_eq!(out_ev.kind, EventKind::NewOutboundConnection);
        assert_eq!(out_ev.severity, Severity::Warning);
        assert!(evs.iter().any(|e| e.key == "net:out:127.0.0.1"));
        // second observation with identical state: nothing new
        let evs = state.observe(&p, 2000);
        assert!(evs.is_empty());
    }

    #[test]
    fn connection_rate_spike_detected() {
        let mut det = SpikeDetector::new(6, 2.0);
        for _ in 0..6 {
            det.push(10.0);
        }
        assert!(det.is_spike(30.0));
    }
}
