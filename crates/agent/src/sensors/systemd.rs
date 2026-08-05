use std::collections::HashMap;

use crate::cmd::CommandRunner;
use wt_common::{AgentEvent, EventKind, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Active,
    Failed,
    Other,
}

/// Parse `systemctl list-units --type=service --all --no-legend --plain` output
/// into unit -> state. Non-.service lines are ignored.
pub fn systemctl_list_units(runner: &dyn CommandRunner) -> Result<HashMap<String, ServiceState>, String> {
    let out = runner.run(&[
        "list-units", "--type=service", "--all", "--no-legend", "--plain",
    ])?;
    let mut map = HashMap::new();
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let unit = parts.next().unwrap_or("").to_string();
        let active = parts.nth(1).unwrap_or("").to_string();
        if !unit.is_empty() && unit.ends_with(".service") {
            let state = match active.as_str() {
                "active" => ServiceState::Active,
                "failed" => ServiceState::Failed,
                _ => ServiceState::Other,
            };
            map.insert(unit, state);
        }
    }
    Ok(map)
}

/// Tracks service transitions to emit ServiceFailed and ServiceCrashLoop events.
pub struct CrashTracker {
    window_secs: u64,
    restarts: HashMap<String, Vec<u64>>,
}

impl CrashTracker {
    pub fn new(window_secs: u64) -> Self {
        CrashTracker { window_secs, restarts: HashMap::new() }
    }

    /// Observe one unit state at `ts` (unix seconds). A failed state appends a
    /// restart timestamp; >=3 restarts within the window = crash loop.
    pub fn observe(&mut self, unit: &str, state: ServiceState, ts: u64, evs: &mut Vec<AgentEvent>) {
        if state == ServiceState::Failed {
            let list = self.restarts.entry(unit.to_string()).or_default();
            list.push(ts);
            list.retain(|t| *t + self.window_secs >= ts);
            let is_loop = list.len() >= 3;
            evs.push(AgentEvent {
                id: format!("{}-{}", unit, ts),
                ts: ts as i64 * 1000,
                host_id: "h".into(),
                key: format!("svc:{}", unit),
                kind: if is_loop { EventKind::ServiceCrashLoop } else { EventKind::ServiceFailed },
                severity: if is_loop { Severity::Critical } else { Severity::Warning },
                summary: format!("{} {} ({} restarts in {}s)", unit,
                    if is_loop { "crash-looping" } else { "entered failed state" },
                    list.len(), self.window_secs),
                evidence: vec![wt_common::Evidence {
                    ts: ts as i64 * 1000,
                    source: "systemd".into(),
                    detail: format!("ActiveState=failed at t={}", ts),
                }],
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_runner(out: &'static str) -> FakeRunner {
        FakeRunner { out: out.to_string() }
    }

    struct FakeRunner {
        out: String,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, _args: &[&str]) -> Result<String, String> {
            Ok(self.out.clone())
        }
    }

    const LIST: &str = "\
sshd.service        loaded active running sshd
nginx.service       loaded failed  failed  nginx
cron.service        loaded active running cron
";

    #[test]
    fn parses_service_states_from_list_units_output() {
        let states = systemctl_list_units(&fake_runner(LIST)).unwrap();
        assert_eq!(states["sshd.service"], ServiceState::Active);
        assert_eq!(states["nginx.service"], ServiceState::Failed);
        assert_eq!(states["cron.service"], ServiceState::Active);
    }

    #[test]
    fn active_to_failed_transition_emits_service_failed_event() {
        let mut m = CrashTracker::new(120);
        let mut evs = Vec::new();
        m.observe("nginx.service", ServiceState::Active, 1000, &mut evs);
        assert!(evs.is_empty());
        m.observe("nginx.service", ServiceState::Failed, 1015, &mut evs);
        assert_eq!(evs[0].kind, EventKind::ServiceFailed);
        assert_eq!(evs[0].key, "svc:nginx.service");
        assert_eq!(evs[0].severity, Severity::Warning);
    }

    #[test]
    fn three_restarts_within_window_is_crash_loop() {
        let mut m = CrashTracker::new(120);
        let mut evs = Vec::new();
        for ts in [1000, 1010, 1020, 1030, 1040, 1050] {
            m.observe("flaky.service", ServiceState::Active, ts, &mut evs);
            m.observe("flaky.service", ServiceState::Failed, ts + 5, &mut evs);
        }
        let crash = evs.iter().filter(|e| e.kind == EventKind::ServiceCrashLoop).count();
        assert!(crash >= 1, "expected crash-loop event, got {evs:?}");
    }

    #[test]
    fn restarts_older_than_window_do_not_crash_loop() {
        let mut m = CrashTracker::new(10);
        let mut evs = Vec::new();
        for ts in [1000u64, 2000, 2010, 2020] {
            m.observe("ok.service", ServiceState::Active, ts, &mut evs);
            m.observe("ok.service", ServiceState::Failed, ts + 5, &mut evs);
        }
        assert!(!evs.iter().any(|e| e.kind == EventKind::ServiceCrashLoop));
    }
}
