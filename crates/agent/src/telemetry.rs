use std::fs;
use std::io::Write;
use std::path::PathBuf;

use wt_common::{AgentEvent, Heartbeat};

/// JSONL spool: one event per line, appended on failure. Reads are
/// non-destructive; files are acked (deleted) only after delivery.
pub struct Spool {
    dir: PathBuf,
}

/// One spool file's contents, read non-destructively.
pub struct SpoolFile {
    pub path: PathBuf,
    pub events: Vec<AgentEvent>,
}

/// Result of a drain pass.
#[derive(Debug, Default)]
pub struct DrainStats {
    pub delivered: usize,
    pub dropped: usize,
    pub deferred: usize,
}

impl Spool {
    pub fn new(dir: PathBuf) -> Self {
        fs::create_dir_all(&dir).ok();
        Spool { dir }
    }

    pub fn append(&self, events: &[AgentEvent]) -> std::io::Result<()> {
        let path = self.dir.join(format!("spool-{}.jsonl", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        for ev in events {
            let line = serde_json::to_string(ev)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Read all spool files oldest-first WITHOUT deleting them. Unreadable
    /// files are skipped (fail-open); individual corrupt lines are skipped.
    pub fn read_all(&self) -> Vec<SpoolFile> {
        let mut out = Vec::new();
        let mut entries: Vec<_> = match fs::read_dir(&self.dir) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(e) => {
                eprintln!("spool read_dir failed: {e}");
                Vec::new()
            }
        };
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let text = match fs::read_to_string(entry.path()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("spool skip unreadable {}: {e}", entry.path().display());
                    continue;
                }
            };
            let mut events = Vec::new();
            for line in text.lines() {
                if let Ok(ev) = serde_json::from_str::<AgentEvent>(line) {
                    events.push(ev);
                }
            }
            out.push(SpoolFile {
                path: entry.path(),
                events,
            });
        }
        out
    }

    /// Delete a spool file — call ONLY after its events were delivered.
    pub fn ack(&self, path: &std::path::Path) {
        std::fs::remove_file(path).ok();
    }

    /// Number of spooled events (non-destructive).
    pub fn count(&self) -> usize {
        self.read_all().iter().map(|f| f.events.len()).sum()
    }

    /// Post all spooled files oldest-first. Ack what delivered; drop only
    /// permanent 4xx failures (except 408/429 which are retryable); keep
    /// transport/5xx failures spooled and stop the drain.
    pub fn drain(&self, url: &str, token: &str) -> DrainStats {
        let mut stats = DrainStats::default();
        for file in self.read_all() {
            match post_batch(url, token, &file.events) {
                Ok(()) => {
                    self.ack(&file.path);
                    stats.delivered += file.events.len();
                }
                Err(PostError::HttpStatus(code))
                    if (400..500).contains(&code) && code != 408 && code != 429 =>
                {
                    eprintln!(
                        "permanent failure ({}); dropping {} spooled events",
                        code,
                        file.events.len()
                    );
                    self.ack(&file.path);
                    stats.dropped += file.events.len();
                }
                Err(e) => {
                    eprintln!(
                        "drain deferred ({}): {} events stay spooled",
                        e,
                        file.events.len()
                    );
                    stats.deferred += file.events.len();
                    break;
                }
            }
        }
        stats
    }
}

/// Distinguishes retryable failures (transport, 5xx) from permanent ones
/// (4xx: bad token, bad payload — retrying is pointless).
#[derive(Debug)]
pub enum PostError {
    Transport(String),
    HttpStatus(u16),
}

impl std::fmt::Display for PostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostError::Transport(msg) => write!(f, "transport: {msg}"),
            PostError::HttpStatus(code) => write!(f, "http {code}"),
        }
    }
}

pub fn post_batch(url: &str, token: &str, events: &[AgentEvent]) -> Result<(), PostError> {
    let body = serde_json::to_string(&serde_json::json!({ "batch": events }))
        .map_err(|e| PostError::Transport(e.to_string()))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(&format!("{}/v1/telemetry", url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => PostError::HttpStatus(code),
            ureq::Error::Transport(t) => PostError::Transport(t.to_string()),
        })?;
    if !(200..300).contains(&resp.status()) {
        return Err(PostError::HttpStatus(resp.status()));
    }
    Ok(())
}

pub fn post_heartbeat(url: &str, token: &str, hb: &Heartbeat) -> Result<(), PostError> {
    let body = serde_json::to_string(hb).map_err(|e| PostError::Transport(e.to_string()))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(&format!("{}/v1/heartbeat", url.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => PostError::HttpStatus(code),
            ureq::Error::Transport(t) => PostError::Transport(t.to_string()),
        })?;
    if !(200..300).contains(&resp.status()) {
        return Err(PostError::HttpStatus(resp.status()));
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
        let files = spool.read_all();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].events.len(), 2);
        assert_eq!(files[0].events[0].ts, 1);
        assert_eq!(files[0].events[1].ts, 2);
        spool.ack(&files[0].path);
        assert!(spool.read_all().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn post_batch_sends_json_with_auth_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
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
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
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
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
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
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
            req
        });
        let url = format!("http://{}", addr);
        let hb = Heartbeat {
            host_id: "h-1".into(),
            ts: 9,
            version: "0.1.0".into(),
            queue_len: 3,
        };
        post_heartbeat(&url, "secret-token", &hb).unwrap();
        let req = handle.join().unwrap();
        assert!(req.contains("\"queue_len\":3"));
    }

    #[test]
    fn post_batch_reports_http_status_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        let url = format!("http://{}", addr);
        let err = post_batch(&url, "secret-token", &[sample_event(1)]).unwrap_err();
        assert!(matches!(err, PostError::HttpStatus(500)));
        handle.join().unwrap();
    }

    #[test]
    fn spool_read_does_not_delete_until_acked() {
        let dir = std::env::temp_dir().join(format!("wt-spool-2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(42)]).unwrap();
        assert_eq!(spool.read_all().len(), 1);
        assert_eq!(spool.count(), 1);
        spool.ack(&spool.read_all()[0].path);
        assert!(spool.read_all().is_empty());
        assert_eq!(spool.count(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spool_read_all_skips_unreadable_files() {
        let dir = std::env::temp_dir().join(format!("wt-spool-3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        std::fs::create_dir_all(dir.join("spool-bad.jsonl")).unwrap();
        spool.append(&[sample_event(7)]).unwrap();
        let files = spool.read_all();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].events[0].ts, 7);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Spawn a mock server answering every request with the given status line.
    fn mock_server(status: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut req = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => req.extend_from_slice(&chunk[..n]),
                    Err(_) => break, // read timeout: client finished sending
                }
            }
            let _ = String::from_utf8_lossy(&req).into_owned();
            stream
                .write_all(format!("{status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        (format!("http://{}", addr), handle)
    }

    fn drain_spool_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wt-spool-drain-{name}-{}", std::process::id()))
    }

    #[test]
    fn drain_acks_on_success() {
        let (url, handle) = mock_server("HTTP/1.1 200 OK");
        let dir = drain_spool_dir("ok");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 0);
        assert!(spool.read_all().is_empty(), "delivered file must be acked");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_keeps_events_on_500() {
        let (url, handle) = mock_server("HTTP/1.1 500 Internal Server Error");
        let dir = drain_spool_dir("500");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 1);
        assert_eq!(spool.count(), 1, "5xx must stay spooled");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_drops_on_401() {
        let (url, handle) = mock_server("HTTP/1.1 401 Unauthorized");
        let dir = drain_spool_dir("401");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.deferred, 0);
        assert!(spool.read_all().is_empty(), "permanent 4xx must be acked");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn drain_defers_on_429_rate_limit() {
        let (url, handle) = mock_server("HTTP/1.1 429 Too Many Requests");
        let dir = drain_spool_dir("429");
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::new(dir.clone());
        spool.append(&[sample_event(1)]).unwrap();
        let stats = spool.drain(&url, "secret-token");
        handle.join().unwrap();
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.deferred, 1);
        assert_eq!(spool.count(), 1, "429 must stay spooled, not dropped");
        std::fs::remove_dir_all(&dir).ok();
    }
}
