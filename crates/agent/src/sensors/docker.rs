use std::collections::HashMap;

use serde::Deserialize;
use wt_common::{AgentEvent, EventKind, Evidence, Severity};

/// One `docker ps` line (--format '{{json .}}').
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DockerPsLine {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: String,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
}

/// Reduced container state for tracking.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerState {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
}

/// Parse `docker ps --format '{{json .}}'` output: one JSON object per line.
/// Non-JSON lines are skipped (fail-open).
pub fn parse_docker_ps(out: &str) -> Result<Vec<ContainerState>, String> {
    let mut containers = Vec::new();
    for line in out.lines() {
        let Ok(v) = serde_json::from_str::<DockerPsLine>(line) else {
            continue;
        };
        containers.push(ContainerState {
            id: v.id,
            name: v.names,
            image: v.image,
            state: v.state,
        });
    }
    Ok(containers)
}

/// Per-container transition tracker: running→exited = stopped (Warning);
/// N consecutive "restarting" observations within a window = crash loop
/// (Critical, episode resets on emit).
#[derive(Default)]
pub struct ContainerTracker {
    prev: HashMap<String, String>,
    restarting_count: HashMap<String, u32>,
}

impl ContainerTracker {
    pub fn observe(
        &mut self,
        containers: &[ContainerState],
        ts: i64,
        host_id: &str,
        evs: &mut Vec<AgentEvent>,
    ) {
        let mut seen: std::collections::HashSet<String> = Default::default();
        for c in containers {
            seen.insert(c.name.clone());
            let prev_state = self.prev.insert(c.name.clone(), c.state.clone());
            match (prev_state.as_deref(), c.state.as_str()) {
                (Some("running"), "exited") | (Some("running"), "dead") => {
                    evs.push(AgentEvent {
                        id: format!("dstop-{}-{}", c.name, ts),
                        ts,
                        host_id: host_id.into(),
                        key: format!("docker:{}", c.name),
                        kind: EventKind::ContainerStopped,
                        severity: Severity::Warning,
                        summary: format!("container {} stopped ({})", c.name, c.image),
                        evidence: vec![Evidence {
                            ts,
                            source: "docker".into(),
                            detail: format!("Container={} State={}", c.name, c.state),
                        }],
                    });
                    self.restarting_count.remove(&c.name);
                }
                _ => {}
            }
            if c.state == "restarting" {
                let n = self.restarting_count.entry(c.name.clone()).or_insert(0);
                *n += 1;
                if *n >= 3 {
                    evs.push(AgentEvent {
                        id: format!("dloop-{}-{}", c.name, ts),
                        ts,
                        host_id: host_id.into(),
                        key: format!("docker:{}", c.name),
                        kind: EventKind::ContainerCrashLoop,
                        severity: Severity::Critical,
                        summary: format!("container {} is crash-looping", c.name),
                        evidence: vec![Evidence {
                            ts,
                            source: "docker".into(),
                            detail: format!("Container={} RestartCount={}", c.name, n),
                        }],
                    });
                    self.restarting_count.remove(&c.name); // episode resets
                }
            } else {
                self.restarting_count.remove(&c.name);
            }
        }
        // containers that vanished entirely (removed) — stop tracking
        self.prev.retain(|name, _| seen.contains(name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wt_common::{EventKind, Severity};

    fn fixture() -> String {
        std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docker/ps.jsonl"),
        )
        .unwrap()
    }

    #[test]
    fn parses_ps_json_lines() {
        let containers = parse_docker_ps(&fixture()).unwrap();
        assert_eq!(containers.len(), 3);
        let web = containers.iter().find(|c| c.name == "web").unwrap();
        assert_eq!(web.state, "running");
        let worker = containers.iter().find(|c| c.name == "worker").unwrap();
        assert_eq!(worker.state, "restarting");
        let cache = containers.iter().find(|c| c.name == "cache").unwrap();
        assert_eq!(cache.state, "exited");
    }

    #[test]
    fn skips_non_json_lines() {
        let out = "not json\n\n{\"State\":\"running\",\"Names\":\"x\",\"ID\":\"1\",\"Image\":\"i\",\"Status\":\"Up\"}\n";
        let containers = parse_docker_ps(out).unwrap();
        assert_eq!(containers.len(), 1);
    }

    #[test]
    fn running_to_exited_emits_stopped() {
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        t.observe(&[container("web", "running")], 1000, "h-1", &mut evs);
        assert!(evs.is_empty());
        t.observe(&[container("web", "exited")], 2000, "h-1", &mut evs);
        let stopped = evs.iter().find(|e| e.kind == EventKind::ContainerStopped);
        assert!(stopped.is_some());
        assert_eq!(stopped.unwrap().severity, Severity::Warning);
        assert_eq!(stopped.unwrap().key, "docker:web");
    }

    #[test]
    fn restarting_state_counts_as_crash_loop() {
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        t.observe(&[container("worker", "restarting")], 1000, "h-1", &mut evs);
        t.observe(&[container("worker", "restarting")], 2000, "h-1", &mut evs);
        t.observe(&[container("worker", "restarting")], 3000, "h-1", &mut evs);
        let loop_ev = evs.iter().find(|e| e.kind == EventKind::ContainerCrashLoop);
        assert!(loop_ev.is_some());
        assert_eq!(loop_ev.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn steady_running_is_quiet() {
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        for ts in [1000, 2000, 3000] {
            t.observe(&[container("web", "running")], ts, "h-1", &mut evs);
        }
        assert!(evs.is_empty());
    }

    fn container(name: &str, state: &str) -> ContainerState {
        ContainerState {
            id: format!("id-{}", name),
            name: name.to_string(),
            image: String::new(),
            state: state.to_string(),
        }
    }
}
