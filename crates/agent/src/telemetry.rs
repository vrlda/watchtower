use std::fs;
use std::io::Write;
use std::path::PathBuf;

use wt_common::{AgentEvent, Heartbeat};

/// JSONL spool: one event per line, appended on failure, replayed on start.
/// Replay reads and deletes files oldest-first (sorted by filename).
pub struct Spool {
    dir: PathBuf,
}

impl Spool {
    pub fn new(dir: PathBuf) -> Self {
        fs::create_dir_all(&dir).ok();
        Spool { dir }
    }

    pub fn append(&self, events: &[AgentEvent]) -> std::io::Result<()> {
        let path = self.dir.join(format!("spool-{}.jsonl", std::process::id()));
        let mut file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
        for ev in events {
            let line = serde_json::to_string(ev)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Read and delete all spool files, oldest first. Unparseable lines are
    /// skipped (fail-open: never lose the whole spool to one corrupt line).
    pub fn replay(&self) -> Result<Vec<AgentEvent>, String> {
        let mut out = Vec::new();
        let mut entries: Vec<_> = fs::read_dir(&self.dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let text = fs::read_to_string(entry.path()).map_err(|e| e.to_string())?;
            for line in text.lines() {
                if let Ok(ev) = serde_json::from_str::<AgentEvent>(line) {
                    out.push(ev);
                }
            }
            fs::remove_file(entry.path()).ok();
        }
        Ok(out)
    }
}

pub fn post_batch(url: &str, token: &str, events: &[AgentEvent]) -> Result<(), String> {
    let body = serde_json::to_string(&serde_json::json!({ "batch": events }))
        .map_err(|e| e.to_string())?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(&format!("{}/v1/telemetry", url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status()) {
        return Err(format!("server responded {}", resp.status()));
    }
    Ok(())
}

pub fn post_heartbeat(url: &str, token: &str, hb: &Heartbeat) -> Result<(), String> {
    let body = serde_json::to_string(hb).map_err(|e| e.to_string())?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(&format!("{}/v1/heartbeat", url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status()) {
        return Err(format!("server responded {}", resp.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use wt_common::{AgentEvent, EventKind, Heartbeat, Severity};

    fn sample_event(ts: i64) -> AgentEvent {
        AgentEvent {
            id: format!("e-{}", ts),
            ts,
            host_id: "h-1".into(),
            key: "svc:nginx".into(),
            kind: EventKind::ServiceFailed,
            severity: Severity::Critical,
            summary: "nginx failed".into(),
            evidence: vec![],
        }
    }

    #[test]
    fn spool_roundtrips_events_in_order() {
        let dir = std::env::temp_dir().join(format!("wt-spool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1), sample_event(2)]).unwrap();
        let out = spool.replay().unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].ts, 1);
        assert_eq!(out[1].ts, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn post_batch_sends_json_with_auth_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            let req = String::from_utf8_lossy(&req).into_owned();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
            req
        });
        let url = format!("http://{}", addr);
        post_batch(&url, "secret-token", &[sample_event(1)]).unwrap();
        let req = handle.join().unwrap();
        assert!(req.contains("Authorization: Bearer secret-token"));
        assert!(req.contains("\"kind\":\"ServiceFailed\""));
    }

    #[test]
    fn heartbeat_ships_minimal_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            let req = String::from_utf8_lossy(&req).into_owned();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
            req
        });
        let url = format!("http://{}", addr);
        let hb = Heartbeat { host_id: "h-1".into(), ts: 9, version: "0.1.0".into(), queue_len: 3 };
        post_heartbeat(&url, "secret-token", &hb).unwrap();
        let req = handle.join().unwrap();
        assert!(req.contains("\"queue_len\":3"));
    }

    #[test]
    fn spool_replay_is_idempotent_after_successful_post() {
        let dir = std::env::temp_dir().join(format!("wt-spool-2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(42)]).unwrap();
        let first = spool.replay().unwrap();
        let second = spool.replay().unwrap();
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
