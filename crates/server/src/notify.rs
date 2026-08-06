use std::collections::HashMap;

use serde_json::json;

/// Per-severity channel routing. Defaults: Critical → telegram,
/// Warning → telegram, Info → none (timeline only).
pub fn default_routing() -> HashMap<String, Vec<String>> {
    let mut m = HashMap::new();
    m.insert("Critical".into(), vec!["telegram".into()]);
    m.insert("Warning".into(), vec!["telegram".into()]);
    m.insert("Info".into(), vec![]);
    m
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub webhook_url: String,
    pub slack_url: String,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<i64>,
    pub telegram_password: Option<String>,
    pub routing: HashMap<String, Vec<String>>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            webhook_url: String::new(),
            slack_url: String::new(),
            telegram_token: None,
            telegram_chat_id: None,
            telegram_password: None,
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

/// Slack message text parses `&`, `<`, `>` — escape them so untrusted
/// content renders literally.
pub fn escape_slack(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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
                        escape_slack(e["summary"].as_str().unwrap_or("")),
                        escape_slack(e["kind"].as_str().unwrap_or(""))
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let text = format!(
        "{}\n{}\n{}",
        escape_slack(incident_json["headline"].as_str().unwrap_or("")),
        escape_slack(incident_json["cause"].as_str().unwrap_or("")),
        timeline.join("\n")
    );
    serde_json::to_string(&json!({
        "attachments": [{
            "color": color,
            "title": format!("[{}] {}", escape_slack(incident_json["severity"].as_str().unwrap_or("")), escape_slack(incident_json["headline"].as_str().unwrap_or(""))),
            "text": text,
            "footer": format!("watchtower · {}", escape_slack(ui_base_url.trim_end_matches('/'))),
        }]
    }))
    .unwrap_or_else(|_| "{}".into())
}

// ---------- Telegram ----------

/// Telegram bot delivery. Token comes from the TELEGRAM_BOT_TOKEN env line
/// (injected at config load); the chat id auto-resolves from the bot's
/// updates — the operator messages the bot once (e.g. /start) and the chat
/// is remembered.
pub struct TelegramClient {
    pub token: String,
    pub chat_id: std::sync::Mutex<Option<i64>>,
}

impl TelegramClient {
    pub fn new(token: String, chat: Option<i64>) -> Self {
        TelegramClient {
            token,
            chat_id: std::sync::Mutex::new(chat),
        }
    }
}

pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// Incident → Telegram message text (plain text, no markdown).
pub fn telegram_payload(incident_json: &serde_json::Value, ui_base_url: &str) -> String {
    let sev = incident_json["severity"].as_str().unwrap_or("?");
    let mut lines = vec![format!(
        "[{}] {}",
        sev.to_uppercase(),
        incident_json["headline"].as_str().unwrap_or("")
    )];
    if let Some(cause) = incident_json["cause"].as_str() {
        if !cause.is_empty() {
            lines.push(cause.to_string());
        }
    }
    if let Some(tl) = incident_json["timeline"].as_array() {
        for e in tl {
            lines.push(format!(
                " - {} — {} ({})",
                format_ts(e["ts"].as_i64().unwrap_or(0)),
                e["summary"].as_str().unwrap_or(""),
                e["kind"].as_str().unwrap_or("")
            ));
        }
    }
    if let Some(actions) = incident_json["actions"].as_array() {
        for a in actions {
            lines.push(format!("> {}", a.as_str().unwrap_or("")));
        }
    }
    lines.push(format!(
        "{}/#/incidents/{}",
        ui_base_url.trim_end_matches('/'),
        incident_json["id"].as_str().unwrap_or("")
    ));
    lines.join("\n")
}

/// GET the bot's updates; return the first chat id found.
pub fn resolve_chat_id(api_base: &str, token: &str) -> Result<Option<i64>, String> {
    let updates = resolve_updates_sync(api_base, token)?;
    Ok(resolve_chat_id_from_updates(&updates))
}

/// Send a text message to the bot's chat, resolving the chat if unknown.
/// Ok(false) = no chat registered yet (message the bot once).
pub fn telegram_send(client: &TelegramClient, api_base: &str, text: &str) -> Result<bool, String> {
    let known = {
        let guard = client.chat_id.lock().unwrap();
        *guard
    };
    let chat = match known {
        Some(c) => c,
        None => match resolve_chat_id(api_base, &client.token)? {
            Some(c) => {
                eprintln!("telegram: resolved chat id {}", c);
                *client.chat_id.lock().unwrap() = Some(c);
                c
            }
            None => return Ok(false),
        },
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let url = format!(
        "{}/bot{}/sendMessage",
        api_base.trim_end_matches('/'),
        client.token
    );
    let resp = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({ "chat_id": chat, "text": text }).to_string())
        .map_err(|e| e.to_string())?;
    Ok((200..300).contains(&resp.status()))
}

// ---------- Telegram registration handshake ----------

#[derive(Debug, PartialEq, Eq)]
pub enum RegStep {
    Noop,             // no password configured → legacy discovery
    AskPassword,      // reply: please send the password
    Register(String), // password accepted → register this chat
    Reject,           // awaiting + wrong password
    Ignore,           // nothing to do
}

/// Pure: one step of the registration state machine.
/// `awaiting` = the chat sent /start and is waiting for the password.
pub fn registrar_step(password: Option<&str>, chat: &str, text: &str, awaiting: bool) -> RegStep {
    let Some(pw) = password else {
        return RegStep::Noop;
    };
    match text.trim() {
        "/start" => RegStep::AskPassword,
        t => {
            if awaiting && constant_time_eq(t, pw) {
                RegStep::Register(chat.to_string())
            } else if awaiting {
                RegStep::Reject
            } else {
                RegStep::Ignore
            }
        }
    }
}

/// Timing-safe string comparison.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Extract (chat_id, text) from a getUpdates entry; None for the bot's own
/// messages and non-message updates.
pub fn update_chat_and_text(update: &serde_json::Value) -> Option<(i64, String)> {
    let msg = update.get("message")?;
    if msg["from"]["is_bot"].as_bool().unwrap_or(false) {
        return None;
    }
    let chat = msg["chat"]["id"].as_i64()?;
    let text = msg["text"].as_str()?.to_string();
    Some((chat, text))
}

/// getUpdates result array (sync core — ureq is blocking; the async
/// wrapper and `resolve_chat_id` share it).
fn resolve_updates_sync(api_base: &str, token: &str) -> Result<Vec<serde_json::Value>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let url = format!("{}/bot{}/getUpdates", api_base.trim_end_matches('/'), token);
    let body: serde_json::Value = agent
        .get(&url)
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    Ok(body["result"].as_array().cloned().unwrap_or_default())
}

/// getUpdates result array.
pub async fn resolve_updates(
    api_base: &str,
    token: &str,
) -> Result<Vec<serde_json::Value>, String> {
    resolve_updates_sync(api_base, token)
}

/// First chat id found across updates (message or my_chat_member).
pub fn resolve_chat_id_from_updates(updates: &[serde_json::Value]) -> Option<i64> {
    updates.iter().find_map(|u| {
        u["message"]["chat"]["id"]
            .as_i64()
            .or_else(|| u["my_chat_member"]["chat"]["id"].as_i64())
    })
}

/// Direct sendMessage to a specific chat.
pub async fn send_to_chat(
    api_base: &str,
    token: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let url = format!(
        "{}/bot{}/sendMessage",
        api_base.trim_end_matches('/'),
        token
    );
    let resp = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({ "chat_id": chat_id, "text": text }).to_string())
        .map_err(|e| e.to_string())?;
    if (200..300).contains(&resp.status()) {
        Ok(())
    } else {
        Err(format!("http {}", resp.status()))
    }
}

/// Module-level client built once from the configured token. Token changes
/// require a restart (documented).
static TELEGRAM: std::sync::OnceLock<TelegramClient> = std::sync::OnceLock::new();

/// Log the missing-token misconfig once per process, not per incident.
static TELEGRAM_MISCONFIG_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn telegram_client(
    token: Option<&str>,
    pinned_chat: Option<i64>,
) -> Option<&'static TelegramClient> {
    let token = token?;
    Some(TELEGRAM.get_or_init(|| TelegramClient::new(token.to_string(), pinned_chat)))
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
        if channel == "telegram" {
            match cfg.telegram_token.as_deref() {
                None => {
                    // telegram-only default routing + no token = silent
                    // black hole; make the misconfig self-evident (once)
                    if !TELEGRAM_MISCONFIG_LOGGED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        eprintln!("telegram channel configured but TELEGRAM_BOT_TOKEN is not set");
                    }
                    continue;
                }
                Some(token) => {
                    if let Some(client) = telegram_client(Some(token), cfg.telegram_chat_id) {
                        let text = telegram_payload(incident_json, ui_base_url);
                        let ok = tokio::task::spawn_blocking(move || {
                            telegram_send(client, TELEGRAM_API, &text)
                        })
                        .await
                        .unwrap_or_else(|_| Err("join failed".into()));
                        match ok {
                            Ok(true) => {}
                            Ok(false) => {
                                eprintln!(
                                    "telegram: no chat registered yet — message the bot once"
                                );
                            }
                            Err(e) => {
                                eprintln!("telegram send failed: {}", e);
                                // best-effort: no retry-queue push (empty-url items would
                                // retry pointlessly); the next incident retries naturally
                            }
                        }
                    }
                    continue;
                }
            }
        }
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
/// re-queues or drops at max_attempts or max_len. A server restart loses the
/// queue (documented debt).
pub struct RetryQueue {
    max_attempts: u32,
    max_len: usize,
    items: std::collections::VecDeque<(String, String, u32)>,
}

impl Default for RetryQueue {
    fn default() -> Self {
        RetryQueue::new(3)
    }
}

impl RetryQueue {
    /// Hard cap on queue length — beyond it, new pushes are dropped loudly.
    const DEFAULT_MAX_LEN: usize = 256;

    pub fn new(max_attempts: u32) -> Self {
        RetryQueue {
            max_attempts,
            max_len: Self::DEFAULT_MAX_LEN,
            items: Default::default(),
        }
    }

    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    pub fn push(&mut self, url: String, payload: String) {
        if self.items.len() >= self.max_len {
            eprintln!(
                "notify queue full ({} items) — dropping new notification",
                self.max_len
            );
            return;
        }
        self.items.push_back((url, payload, 0));
    }

    /// Next item to retry with its attempt count. None when empty.
    pub fn try_take(&mut self) -> Option<(String, String, u32)> {
        self.items.pop_front()
    }

    /// Re-queue for another attempt (call on delivery failure); drops at
    /// max_attempts or when the queue is at max_len.
    pub fn retry(&mut self, url: String, payload: String, attempts: u32) {
        if attempts >= self.max_attempts {
            eprintln!("notify retry exhausted for {} ({} attempts)", url, attempts);
        } else if self.items.len() >= self.max_len {
            eprintln!(
                "notify queue full ({} items) — dropping retry for {}",
                self.max_len, url
            );
        } else {
            self.items.push_back((url, payload, attempts));
        }
    }
}

/// Retry undelivered notifications every 10s until dropped at max_attempts
/// or when the queue is at max_len.
pub fn spawn_retry_loop(state: crate::app::AppState) {
    tokio::spawn(crate::supervise::spawn_supervised("notify", move || {
        retry_loop(state.clone())
    }));
}

/// Poll getUpdates, run the handshake, reply via sendMessage, and register
/// the chat in the shared client cache. Tracks processed update_ids — with
/// no-offset getUpdates, updates re-deliver; without dedup every poll would
/// re-prompt the operator.
pub fn spawn_telegram_registrar(state: crate::app::AppState) {
    let Some(token) = state.notify.telegram_token.clone() else {
        return;
    };
    let Some(password) = state.notify.telegram_password.clone() else {
        return; // legacy first-chat discovery — no handshake needed
    };
    tokio::spawn(async move {
        let mut seen: std::collections::HashSet<i64> = Default::default();
        let mut awaiting: std::collections::HashMap<i64, bool> = Default::default();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Ok(updates) = resolve_updates(TELEGRAM_API, &token).await else {
                continue;
            };
            for u in &updates {
                let Some(update_id) = u["update_id"].as_i64() else {
                    continue;
                };
                if !seen.insert(update_id) {
                    continue;
                }
                let Some((chat, text)) = update_chat_and_text(u) else {
                    continue;
                };
                let is_awaiting = *awaiting.get(&chat).unwrap_or(&false);
                match registrar_step(Some(&password), &chat.to_string(), &text, is_awaiting) {
                    RegStep::AskPassword => {
                        awaiting.insert(chat, true);
                        let _ = send_to_chat(
                            TELEGRAM_API,
                            &token,
                            chat,
                            "Send the password to register this chat.",
                        )
                        .await;
                    }
                    RegStep::Register(_) => {
                        awaiting.remove(&chat);
                        if let Some(client) = telegram_client(Some(&token), None) {
                            *client.chat_id.lock().unwrap() = Some(chat);
                        }
                        let _ = send_to_chat(
                            TELEGRAM_API,
                            &token,
                            chat,
                            "Chat registered — notifications will be sent here.",
                        )
                        .await;
                        eprintln!("telegram: chat {} registered", chat);
                    }
                    RegStep::Reject => {
                        let _ = send_to_chat(TELEGRAM_API, &token, chat, "Wrong password.").await;
                    }
                    _ => {}
                }
            }
        }
    });
}

async fn retry_loop(state: crate::app::AppState) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_incidents::incident_json;
    use crate::incidents::{Incident, IncidentEvent, IncidentStatus};
    use std::io::{Read, Write};

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
            telegram_token: None,
            telegram_chat_id: None,
            telegram_password: None,
            routing: default_routing(),
        };
        let c = channels_for(&cfg, "Critical");
        assert_eq!(c, vec!["telegram".to_string()]);
        let c = channels_for(&cfg, "Warning");
        assert_eq!(c, vec!["telegram".to_string()]);
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

    #[test]
    fn retry_queue_caps_length() {
        let mut q = RetryQueue::new(3);
        q.set_max_len(2);
        q.push("http://u1".into(), "p1".into());
        q.push("http://u2".into(), "p2".into());
        q.push("http://u3".into(), "p3".into()); // beyond cap → dropped
        let (url, _, _) = q.try_take().unwrap();
        assert_eq!(url, "http://u1", "oldest preserved");
        let (url, _, _) = q.try_take().unwrap();
        assert_eq!(url, "http://u2");
        assert!(q.try_take().is_none(), "the third was dropped at push");
    }

    #[test]
    fn slack_payload_escapes_special_chars() {
        let mut inc = sample_incident();
        inc.headline = "host <a&b> & \"quoted\"".into();
        let payload = slack_payload(&incident_json(&inc), "http://ui");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let text = v["attachments"][0]["title"].as_str().unwrap();
        assert!(text.contains("&lt;a&amp;b&gt;"), "escaped: {}", text);
        assert!(!text.contains("<a&b>"));
    }

    #[test]
    fn telegram_payload_has_incident_anatomy() {
        let text = telegram_payload(&incident_json(&sample_incident()), "http://ui");
        assert!(text.contains("[CRITICAL]"));
        assert!(text.contains("myapp.service became unhealthy"));
        assert!(text.contains("configuration change"));
        assert!(text.contains("myapp failed"));
        assert!(text.contains("http://ui/#/incidents/inc-1"));
        assert!(text.contains("Roll back the config"));
    }

    #[test]
    fn default_routing_is_single_telegram_channel() {
        let r = default_routing();
        assert_eq!(r.get("Critical").unwrap(), &vec!["telegram".to_string()]);
        assert_eq!(r.get("Warning").unwrap(), &vec!["telegram".to_string()]);
        assert!(r.get("Info").unwrap().is_empty());
    }

    #[test]
    fn telegram_send_posts_to_bot_api() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(5000)))
                .unwrap();
            let mut buf = [0u8; 65536];
            let mut got = 0;
            let mut total = usize::MAX; // full request: headers + body
            loop {
                if got >= total {
                    break;
                }
                match stream.read(&mut buf[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        if total == usize::MAX {
                            if let Some(end) = buf[..got].windows(4).position(|w| w == b"\r\n\r\n")
                            {
                                let head_end = end + 4;
                                let head = String::from_utf8_lossy(&buf[..end]);
                                let clen = head
                                    .lines()
                                    .find_map(|l| {
                                        let (name, value) = l.split_once(':')?;
                                        name.trim()
                                            .eq_ignore_ascii_case("content-length")
                                            .then(|| value.trim().parse::<usize>().unwrap_or(0))
                                    })
                                    .unwrap_or(0);
                                total = head_end + clen;
                            }
                        }
                    }
                }
            }
            let req = String::from_utf8_lossy(&buf[..got]).into_owned();
            let body = "{\"ok\":true,\"result\":{}}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
            req
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::new("test-token".into(), Some(42)); // pre-seeded (auto-resolve covered elsewhere)
        let ok = telegram_send(&client, &base, "hello").unwrap();
        assert!(ok);
        let req = handle.join().unwrap();
        assert!(req.contains("/bottest-token/sendMessage"));
        assert!(req.contains("chat_id"));
        assert!(req.contains("hello"));
    }

    #[test]
    fn telegram_get_updates_resolves_chat_id() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(5000)))
                .unwrap();
            let mut buf = [0u8; 65536];
            let mut got = 0;
            loop {
                match stream.read(&mut buf[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        if buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                            break; // full request read (headers terminator)
                        }
                    }
                }
            }
            let body = r#"{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":12345}}}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        });
        let base = format!("http://{}", addr);
        let chat = resolve_chat_id(&base, "tok").unwrap();
        assert_eq!(chat, Some(12345));
        handle.join().unwrap();
    }

    #[test]
    fn telegram_pinned_chat_skips_get_updates() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 65536];
            let mut n = 0;
            loop {
                match stream.read(&mut buf[n..]) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        n += read;
                        let text = String::from_utf8_lossy(&buf[..n]);
                        if let Some(pos) = text.find("\r\n\r\n") {
                            let cl = text[..pos]
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if n >= pos + 4 + cl {
                                break;
                            }
                        }
                    }
                }
            }
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                !text.contains("getUpdates"),
                "pinned chat must never call getUpdates, got: {}",
                text.lines().next().unwrap_or("")
            );
            let body = r#"{"ok":true,"result":{}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::new("tok".into(), Some(999));
        let ok = telegram_send(&client, &base, "hello").unwrap();
        assert!(ok);
        assert_eq!(*client.chat_id.lock().unwrap(), Some(999));
        handle.join().unwrap();
    }

    #[test]
    fn telegram_send_resolves_chat_when_unknown() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(5000)))
                    .unwrap();
                let mut buf = [0u8; 65536];
                let mut got = 0;
                let mut total = usize::MAX; // full request: headers + body
                loop {
                    if got >= total {
                        break;
                    }
                    match stream.read(&mut buf[got..]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            got += n;
                            if total == usize::MAX {
                                if let Some(end) =
                                    buf[..got].windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    let head_end = end + 4;
                                    let head = String::from_utf8_lossy(&buf[..end]);
                                    let clen = head
                                        .lines()
                                        .find_map(|l| {
                                            let (name, value) = l.split_once(':')?;
                                            name.trim()
                                                .eq_ignore_ascii_case("content-length")
                                                .then(|| value.trim().parse::<usize>().unwrap_or(0))
                                        })
                                        .unwrap_or(0);
                                    total = head_end + clen;
                                }
                            }
                        }
                    }
                }
                let req = String::from_utf8_lossy(&buf[..got]).into_owned();
                let body = if req.starts_with("GET /bottok/getUpdates") {
                    r#"{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":12345}}}]}"#
                        .to_string()
                } else {
                    r#"{"ok":true,"result":{}}"#.to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
            }
        });
        let base = format!("http://{}", addr);
        let client = TelegramClient::new("tok".into(), None); // unknown chat → resolve path
        assert_eq!(*client.chat_id.lock().unwrap(), None);
        let ok = telegram_send(&client, &base, "hello").unwrap();
        assert!(ok);
        assert_eq!(
            *client.chat_id.lock().unwrap(),
            Some(12345),
            "chat resolved and cached"
        );
        handle.join().unwrap();
    }

    #[test]
    fn registrar_state_machine_handshake() {
        assert_eq!(
            registrar_step(None, "chat-1", "/start", false),
            RegStep::Noop
        );
        let pw = Some("hunter2".to_string());
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "/start", false),
            RegStep::AskPassword
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "hunter2", true),
            RegStep::Register("chat-1".into())
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "wrong", true),
            RegStep::Reject
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "hunter2", false),
            RegStep::Ignore,
            "must /start first"
        );
        assert_eq!(
            registrar_step(pw.as_deref(), "chat-1", "hello", false),
            RegStep::Ignore
        );
    }

    #[test]
    fn registrar_extracts_chat_and_text_from_update() {
        let u: serde_json::Value = serde_json::from_str(
            r#"{"update_id":7,"message":{"chat":{"id":12345},"from":{"is_bot":false},"text":"/start"}}"#,
        )
        .unwrap();
        assert_eq!(
            update_chat_and_text(&u),
            Some((12345, "/start".to_string()))
        );
        let bot_msg: serde_json::Value = serde_json::from_str(
            r#"{"update_id":8,"message":{"chat":{"id":12345},"from":{"is_bot":true},"text":"/start"}}"#,
        )
        .unwrap();
        assert_eq!(
            update_chat_and_text(&bot_msg),
            None,
            "the bot's own messages are filtered"
        );
        let no_text: serde_json::Value = serde_json::from_str(
            r#"{"update_id":9,"message":{"chat":{"id":1},"from":{"is_bot":false}}}"#,
        )
        .unwrap();
        assert_eq!(update_chat_and_text(&no_text), None);
    }

    #[test]
    fn constant_time_eq_matches_and_mismatches() {
        assert!(constant_time_eq("hunter2", "hunter2"));
        assert!(!constant_time_eq("hunter2", "hunter3"));
        assert!(!constant_time_eq("a", "bb"));
    }
}
