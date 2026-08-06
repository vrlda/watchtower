use std::collections::HashMap;

use serde_json::json;

/// Per-severity channel routing. Defaults: Critical → webhook+slack,
/// Warning → slack, Info → none (timeline only).
pub fn default_routing() -> HashMap<String, Vec<String>> {
    let mut m = HashMap::new();
    m.insert("Critical".into(), vec!["webhook".into(), "slack".into()]);
    m.insert("Warning".into(), vec!["slack".into()]);
    m.insert("Info".into(), vec![]);
    m
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub webhook_url: String,
    pub slack_url: String,
    pub routing: HashMap<String, Vec<String>>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            webhook_url: String::new(),
            slack_url: String::new(),
            routing: default_routing(),
        }
    }
}

/// Channels configured for a severity.
pub fn channels_for(cfg: &NotifyConfig, severity: &str) -> Vec<String> {
    cfg.routing.get(severity).cloned().unwrap_or_default()
}

/// Generic webhook payload — the full incident anatomy.
pub fn webhook_payload(incident_json: &serde_json::Value, ui_base_url: &str) -> String {
    serde_json::to_string(&json!({
        "type": "watchtower.incident",
        "severity": incident_json["severity"],
        "status": incident_json["status"],
        "headline": incident_json["headline"],
        "cause": incident_json["cause"],
        "affected": incident_json["affected"],
        "actions": incident_json["actions"],
        "timeline": incident_json["timeline"],
        "incident_id": incident_json["id"],
        "host_id": incident_json["host_id"],
        "url": format!("{}/#/incidents/{}", ui_base_url.trim_end_matches('/'), incident_json["id"]),
    }))
    .unwrap_or_else(|_| "{}".into())
}

/// Slack incoming-webhook payload (legacy attachments API).
pub fn slack_payload(incident_json: &serde_json::Value, ui_base_url: &str) -> String {
    let color = match incident_json["severity"].as_str() {
        Some("Critical") => "danger",
        Some("Warning") => "warning",
        _ => "good",
    };
    let timeline: Vec<String> = incident_json["timeline"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|e| {
                    let ts = e["ts"].as_i64().unwrap_or(0);
                    format!(
                        "- {} — {} ({})",
                        format_ts(ts),
                        e["summary"].as_str().unwrap_or(""),
                        e["kind"].as_str().unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let text = format!(
        "{}\n{}\n{}",
        incident_json["headline"].as_str().unwrap_or(""),
        incident_json["cause"].as_str().unwrap_or(""),
        timeline.join("\n")
    );
    serde_json::to_string(&json!({
        "attachments": [{
            "color": color,
            "title": format!("[{}] {}", incident_json["severity"].as_str().unwrap_or(""), incident_json["headline"].as_str().unwrap_or("")),
            "text": text,
            "footer": format!("watchtower · {}", ui_base_url.trim_end_matches('/')),
        }]
    }))
    .unwrap_or_else(|_| "{}".into())
}

/// Timestamp → "YYYY-MM-DD HH:MM:SS" (UTC). No chrono — civil-from-days.
pub fn format_ts(ts: i64) -> String {
    let secs = ts / 1000;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, h, min, s)
}

/// Deliver a payload to a channel; Ok on 2xx.
pub fn deliver(url: &str, payload: &str) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(payload)
        .map_err(|e| e.to_string())?;
    if (200..300).contains(&resp.status()) {
        Ok(())
    } else {
        Err(format!("http {}", resp.status()))
    }
}

/// Send one incident to all channels configured for its severity.
/// Returns the (url, payload) pairs that failed delivery (for the retry queue).
pub async fn notify_incident(
    cfg: &NotifyConfig,
    incident_json: &serde_json::Value,
    ui_base_url: &str,
) -> Vec<(String, String)> {
    let severity = incident_json["severity"].as_str().unwrap_or("Info");
    let mut failed = Vec::new();
    let webhook = webhook_payload(incident_json, ui_base_url);
    let slack = slack_payload(incident_json, ui_base_url);
    for channel in channels_for(cfg, severity) {
        let (url, payload) = match channel.as_str() {
            "webhook" => (cfg.webhook_url.clone(), webhook.clone()),
            "slack" => (cfg.slack_url.clone(), slack.clone()),
            _ => continue,
        };
        if url.is_empty() {
            continue;
        }
        let url2 = url.clone();
        let payload2 = payload.clone();
        let ok = tokio::task::spawn_blocking(move || deliver(&url2, &payload2))
            .await
            .unwrap_or_else(|_| Err("join failed".into()));
        if let Err(e) = ok {
            eprintln!("notify {} failed: {}", channel, e);
            failed.push((url, payload));
        }
    }
    failed
}

/// In-memory retry queue: (url, payload, attempts). try_take POPS; retry()
/// re-queues or drops at the cap. A server restart loses the queue
/// (documented debt).
pub struct RetryQueue {
    max_attempts: u32,
    items: std::collections::VecDeque<(String, String, u32)>,
}

impl RetryQueue {
    pub fn new(max_attempts: u32) -> Self {
        RetryQueue {
            max_attempts,
            items: Default::default(),
        }
    }

    pub fn push(&mut self, url: String, payload: String) {
        self.items.push_back((url, payload, 0));
    }

    /// Next item to retry with its attempt count. None when empty.
    pub fn try_take(&mut self) -> Option<(String, String, u32)> {
        self.items.pop_front()
    }

    /// Re-queue for another attempt (call on delivery failure); drops at cap.
    pub fn retry(&mut self, url: String, payload: String, attempts: u32) {
        if attempts >= self.max_attempts {
            eprintln!("notify retry exhausted for {} ({} attempts)", url, attempts);
        } else {
            self.items.push_back((url, payload, attempts));
        }
    }
}

/// Retry undelivered notifications every 10s until dropped by the queue cap.
pub fn spawn_retry_loop(state: crate::app::AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let item = {
                let mut queue = state.notify_queue.lock().unwrap();
                queue.try_take()
            };
            let Some((url, payload, attempts)) = item else {
                continue;
            };
            let url2 = url.clone();
            let payload2 = payload.clone();
            let ok = tokio::task::spawn_blocking(move || deliver(&url2, &payload2))
                .await
                .unwrap_or_else(|_| Err("join failed".into()));
            match ok {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("notify retry failed ({e}); requeueing {}", url);
                    state
                        .notify_queue
                        .lock()
                        .unwrap()
                        .retry(url, payload, attempts + 1);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_incidents::incident_json;
    use crate::incidents::{Incident, IncidentEvent, IncidentStatus};

    fn sample_incident() -> Incident {
        Incident {
            id: "inc-1".into(),
            key: "rule:cfg:h-1".into(),
            host_id: "h-1".into(),
            severity: "Critical".into(),
            status: IncidentStatus::Open,
            headline: "myapp.service became unhealthy after a configuration change".into(),
            cause: "A configuration change was followed by a service failure within 300 seconds."
                .into(),
            actions: vec!["Roll back the config".into()],
            affected: vec!["h-1".into(), "svc:myapp.service".into()],
            created_at: 1000,
            updated_at: 1000,
            acked_at: None,
            resolved_at: None,
            timeline: vec![IncidentEvent {
                id: "e-1".into(),
                ts: 900,
                host_id: "h-1".into(),
                kind: "ServiceFailed".into(),
                severity: "Critical".into(),
                summary: "myapp failed".into(),
                evidence: vec![],
            }],
        }
    }

    #[test]
    fn webhook_payload_has_incident_anatomy() {
        let payload = webhook_payload(&incident_json(&sample_incident()), "http://ui/");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["severity"], "Critical");
        assert_eq!(
            v["headline"],
            "myapp.service became unhealthy after a configuration change"
        );
        assert!(v["cause"]
            .as_str()
            .unwrap()
            .contains("configuration change"));
        assert!(!v["timeline"].as_array().unwrap().is_empty());
        assert!(!v["actions"].as_array().unwrap().is_empty());
        assert_eq!(v["affected"][1], "svc:myapp.service");
        assert!(v["url"].as_str().unwrap().contains("inc-1"));
    }

    #[test]
    fn slack_payload_has_severity_color() {
        let payload = slack_payload(&incident_json(&sample_incident()), "http://ui/");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let att = &v["attachments"][0];
        assert_eq!(att["color"], "danger");
        assert!(att["title"].as_str().unwrap().contains("myapp.service"));
        assert!(att["text"]
            .as_str()
            .unwrap()
            .contains("configuration change"));
        assert!(att["text"].as_str().unwrap().contains("myapp failed"));
    }

    #[test]
    fn routing_resolves_channels_per_severity() {
        let cfg = NotifyConfig {
            webhook_url: "http://w".into(),
            slack_url: "http://s".into(),
            routing: default_routing(),
        };
        let c = channels_for(&cfg, "Critical");
        assert!(c.iter().any(|s| s == "webhook"));
        assert!(c.iter().any(|s| s == "slack"));
        let c = channels_for(&cfg, "Warning");
        assert!(!c.iter().any(|s| s == "webhook"));
        assert!(c.iter().any(|s| s == "slack"));
        let c = channels_for(&cfg, "Info");
        assert!(c.is_empty());
    }

    #[test]
    fn format_ts_known_epoch() {
        assert_eq!(format_ts(1_000_000_000_000), "2001-09-09 01:46:40");
        assert_eq!(format_ts(1_758_000_000_000), "2025-09-16 05:20:00");
    }

    #[test]
    fn retry_queue_drops_after_max_attempts() {
        let mut q = RetryQueue::new(3);
        q.push("http://u".into(), "p".into());
        let (_, _, a1) = q.try_take().unwrap();
        q.retry("http://u".into(), "p".into(), a1 + 1);
        let (_, _, a2) = q.try_take().unwrap();
        q.retry("http://u".into(), "p".into(), a2 + 1);
        assert_eq!(a1, 0);
        assert_eq!(a2, 1);
        let (_, _, a3) = q.try_take().unwrap();
        q.retry("http://u".into(), "p".into(), a3 + 1); // attempts 3 >= max 3 → dropped
        assert!(q.try_take().is_none());
    }
}
