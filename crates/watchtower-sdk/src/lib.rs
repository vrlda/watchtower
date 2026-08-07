//! Minimal watchtower exception-capture SDK. Apps call [`Client::capture`]
//! with the exception type, message, level, and stack frames; the server
//! fingerprints and groups them into incidents. Blocking, no async, no
//! external services beyond the watchtower server.

use std::time::Duration;

/// SDK configuration. All fields have env defaults (the WATCHTOWER_* family).
#[derive(Debug, Clone)]
pub struct Client {
    pub endpoint: String,
    pub token: String,
    pub host_id: String,
    pub service: String,
    pub environment: String,
}

impl Client {
    /// Build from the WATCHTOWER_ENDPOINT / WATCHTOWER_TOKEN /
    /// WATCHTOWER_HOST_ID / WATCHTOWER_SERVICE / WATCHTOWER_ENVIRONMENT
    /// env vars (host_id defaults to the OS hostname, service to "app",
    /// environment to "prod").
    pub fn from_env() -> Option<Client> {
        let endpoint = std::env::var("WATCHTOWER_ENDPOINT").ok()?;
        let token = std::env::var("WATCHTOWER_TOKEN").ok()?;
        let host_id = std::env::var("WATCHTOWER_HOST_ID")
            .ok()
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "host".into());
        let service = std::env::var("WATCHTOWER_SERVICE")
            .ok()
            .unwrap_or_else(|| "app".into());
        let environment = std::env::var("WATCHTOWER_ENVIRONMENT")
            .ok()
            .unwrap_or_else(|| "prod".into());
        Some(Client {
            endpoint,
            token,
            host_id,
            service,
            environment,
        })
    }

    /// Report an exception. Frames: (file, line, function) — innermost
    /// first. Best-effort with one retry; never panics.
    pub fn capture(
        &self,
        level: &str,
        kind: &str,
        message: &str,
        frames: &[(String, u32, String)],
    ) -> bool {
        let body = serde_json::json!({
            "host_id": self.host_id,
            "service": self.service,
            "environment": self.environment,
            "exception": {
                "type": kind,
                "message": message,
                "level": level,
                "frames": frames.iter().map(|(file, line, function)| serde_json::json!({
                    "file": file, "line": line, "function": function
                })).collect::<Vec<_>>(),
            }
        });
        let url = format!("{}/v1/errors", self.endpoint.trim_end_matches('/'));
        for attempt in 0..2 {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build();
            let res = agent
                .post(&url)
                .set("Content-Type", "application/json")
                .set("Authorization", &format!("Bearer {}", self.token))
                .send_string(&body.to_string());
            match res {
                Ok(r) if (200..300).contains(&r.status()) => return true,
                _ => {
                    if attempt == 0 {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        }
        false
    }

    /// Convenience for panics: capture a formatted panic message
    /// (type "Panic", level "fatal").
    pub fn capture_panic(&self, message: &str) -> bool {
        self.capture("fatal", "Panic", message, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn capture_posts_expected_payload() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for _ in 0..100 {
                if let Ok((mut stream, _)) = listener
                    .set_nonblocking(true)
                    .and_then(|_| listener.accept())
                {
                    listener.set_nonblocking(false).ok();
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                    while std::time::Instant::now() < deadline {
                        match stream.read(&mut tmp) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                        let text = String::from_utf8_lossy(&buf);
                        if let Some(head_end) = text.find("\r\n\r\n") {
                            let content_len = text[..head_end]
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if head_end + 4 + content_len <= buf.len() {
                                break;
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    let req = String::from_utf8_lossy(&buf).to_string();
                    let body_start = req.find("\r\n\r\n").unwrap() + 4;
                    let body: serde_json::Value = serde_json::from_str(&req[body_start..]).unwrap();
                    assert!(
                        req.contains("POST /v1/errors HTTP/1.1"),
                        "method+path: {}",
                        req
                    );
                    assert!(req.contains("Authorization: Bearer tok"), "auth header");
                    assert_eq!(body["host_id"], "h-1");
                    assert_eq!(body["service"], "api");
                    assert_eq!(body["exception"]["type"], "ValueError");
                    assert_eq!(body["exception"]["level"], "error");
                    assert_eq!(body["exception"]["frames"][0]["file"], "app.rs");
                    assert_eq!(body["exception"]["frames"][0]["line"], 42);
                    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    stream.write_all(resp.as_bytes()).unwrap();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            panic!("no request within 2s");
        });
        let client = Client {
            endpoint: format!("http://{}", addr),
            token: "tok".into(),
            host_id: "h-1".into(),
            service: "api".into(),
            environment: "prod".into(),
        };
        let ok = client.capture(
            "error",
            "ValueError",
            "bad input",
            &[("app.rs".into(), 42, "validate".into())],
        );
        assert!(ok);
        handle.join().unwrap();
    }

    #[test]
    fn capture_retries_once_then_returns_false() {
        let client = Client {
            endpoint: "http://127.0.0.1:1".into(),
            token: "t".into(),
            host_id: "h".into(),
            service: "s".into(),
            environment: "e".into(),
        };
        assert!(!client.capture("error", "T", "m", &[]));
    }
}
