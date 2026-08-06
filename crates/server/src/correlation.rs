use serde::Deserialize;
use wt_common::{AgentEvent, EventKind, Severity};

/// One correlation rule: a trigger kind plus supporting kinds within a
/// sliding window per host.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub trigger: EventKind,
    #[serde(default)]
    pub supporting: Vec<EventKind>,
    #[serde(default = "default_min_supporting")]
    pub min_supporting: u32,
    #[serde(default = "default_window")]
    pub window_secs: i64,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: i64,
    pub severity: Severity,
    pub headline: String,
    #[serde(default)]
    pub cause: String,
    #[serde(default)]
    pub actions: Vec<String>,
    /// The fallback rule matches no trigger; handled separately.
    #[serde(skip)]
    pub is_fallback: bool,
}

fn default_min_supporting() -> u32 {
    1
}
fn default_window() -> i64 {
    300
}
fn default_cooldown() -> i64 {
    600
}

/// A rule match: the events that constitute it.
#[derive(Debug)]
pub struct RuleMatch {
    pub events: Vec<AgentEvent>,
    /// The unit name from the trigger event's key ("svc:myapp.service").
    pub service: Option<String>,
}

/// Default rules shipped with the server. `[[rule]]` entries in server.toml
/// override by id or add new ones.
pub fn default_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "config_change_outage".into(),
            trigger: EventKind::ServiceFailed,
            supporting: vec![
                EventKind::FileChanged,
                EventKind::SshLogin,
                EventKind::SudoUsed,
                EventKind::ServiceRestarted,
                EventKind::CpuSpike, // absorbed INTO the incident so the demo yields one notification
                EventKind::HostUnreachable, // probe failure joins the outage incident, not a second one
            ],
            min_supporting: 1,
            window_secs: 300,
            cooldown_secs: 600,
            severity: Severity::Critical,
            headline: "{service} became unhealthy after a configuration change".into(),
            cause:
                "A configuration change was followed by a service failure within {window} seconds."
                    .into(),
            actions: vec![
                "Review the change to the affected configuration file".into(),
                "Roll back the latest configuration".into(),
                "Verify the SSH session that preceded the change".into(),
            ],
            is_fallback: false,
        },
        Rule {
            id: "ssh_bruteforce".into(),
            trigger: EventKind::SshBruteForce,
            supporting: vec![EventKind::SshFailed],
            min_supporting: 1,
            window_secs: 300,
            cooldown_secs: 600,
            severity: Severity::Critical,
            headline: "Brute-force attack against {host}".into(),
            cause: "Repeated failed SSH logins exceeded the threshold.".into(),
            actions: vec![
                "Block the source IP at the firewall".into(),
                "Check for successful logins from the same source".into(),
            ],
            is_fallback: false,
        },
        Rule {
            id: "root_login".into(),
            trigger: EventKind::RootLogin,
            supporting: vec![EventKind::SshLogin],
            min_supporting: 0,
            window_secs: 300,
            cooldown_secs: 600,
            severity: Severity::Critical,
            headline: "Root access on {host}".into(),
            cause: "A login as root was recorded.".into(),
            actions: vec!["Verify the session was authorized".into()],
            is_fallback: false,
        },
        Rule {
            id: "server_unreachable".into(),
            trigger: EventKind::HostUnreachable,
            supporting: vec![],
            min_supporting: 0,
            window_secs: 300,
            cooldown_secs: 600,
            severity: Severity::Critical,
            headline: "{host} is unreachable".into(),
            cause: "External probes failed consecutively.".into(),
            actions: vec!["Check power and network".into()],
            is_fallback: false,
        },
        Rule {
            id: "fallback".into(),
            trigger: EventKind::CpuSpike, // placeholder — is_fallback handles semantics
            supporting: vec![],
            min_supporting: 0,
            window_secs: 300,
            cooldown_secs: 300,
            severity: Severity::Warning,
            headline: String::new(),
            cause: String::new(),
            actions: vec![],
            is_fallback: true,
        },
    ]
}

/// Match a rule against a host's window events. Events already absorbed by
/// an earlier rule (in `exclude`) never match — this keeps one event in one
/// incident and lets the config-change rule claim the HostUnreachable event
/// before the server_unreachable rule can.
pub fn match_rule(
    rule: &Rule,
    events: &[AgentEvent],
    now: i64,
    _host: &str,
    exclude: &std::collections::HashSet<String>,
) -> Option<RuleMatch> {
    if rule.is_fallback {
        return None;
    }
    let window_start = now - rule.window_secs * 1000;
    let in_window: Vec<&AgentEvent> = events
        .iter()
        .filter(|e| !exclude.contains(&e.id) && e.ts >= window_start && e.ts <= now)
        .collect();
    let trigger = in_window.iter().find(|e| e.kind == rule.trigger)?;
    let supporting_count = in_window
        .iter()
        .filter(|e| e.kind != rule.trigger && rule.supporting.contains(&e.kind))
        .count();
    if (supporting_count as u32) < rule.min_supporting {
        return None;
    }
    let service = trigger.key.strip_prefix("svc:").map(|s| s.to_string());
    Some(RuleMatch {
        events: in_window.into_iter().cloned().collect(),
        service,
    })
}

/// Fill {host} and {service} slots in a template.
pub fn fill_template(tpl: &str, host: &str, service: Option<&str>) -> String {
    tpl.replace("{host}", host)
        .replace("{service}", service.unwrap_or("a service"))
}

/// Assemble an incident draft from a rule match.
pub fn assemble(rule: &Rule, m: &RuleMatch, host: &str) -> IncidentDraft {
    let service = m.service.as_deref();
    let window = rule.window_secs;
    IncidentDraft {
        key: format!("rule:{}:{}", rule.id, host),
        host_id: host.into(),
        severity: crate::ingest::severity_wire(rule.severity),
        headline: fill_template(&rule.headline, host, service),
        cause: fill_template(&rule.cause, host, service).replace("{window}", &window.to_string()),
        actions: rule.actions.clone(),
        affected: {
            let mut v = vec![host.to_string()];
            for e in &m.events {
                if !v.contains(&e.key) {
                    v.push(e.key.clone());
                }
            }
            v
        },
        events: m.events.clone(),
    }
}

/// An incident about to be persisted.
#[derive(Debug)]
pub struct IncidentDraft {
    pub key: String,
    pub host_id: String,
    pub severity: String,
    pub headline: String,
    pub cause: String,
    pub actions: Vec<String>,
    pub affected: Vec<String>,
    pub events: Vec<AgentEvent>,
}

/// Fallback: unmatched Warning+ events become single-event incidents.
pub fn fallback_incidents(events: &[AgentEvent], _now: i64, host: &str) -> Vec<IncidentDraft> {
    let mut out = Vec::new();
    for e in events {
        if e.severity == Severity::Info {
            continue;
        }
        let kind = crate::ingest::kind_wire(e.kind);
        out.push(IncidentDraft {
            key: format!("event:{}:{}:{}", kind, host, e.key),
            host_id: host.into(),
            severity: crate::ingest::severity_wire(e.severity),
            headline: format!("{}: {}", kind, e.key),
            cause: String::new(),
            actions: vec![],
            affected: vec![host.into(), e.key.clone()],
            events: vec![e.clone()],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wt_common::{AgentEvent, EventKind, Severity};

    fn ev(id: &str, ts: i64, kind: EventKind, sev: Severity, key: &str) -> AgentEvent {
        AgentEvent {
            id: id.into(),
            ts,
            host_id: "h-1".into(),
            key: key.into(),
            kind,
            severity: sev,
            summary: format!("{} {:?}", id, kind),
            evidence: vec![],
        }
    }

    const CFG_RULE: &str = r#"
id = "config_change_outage"
trigger = "ServiceFailed"
supporting = ["FileChanged", "SshLogin", "SudoUsed", "ServiceRestarted"]
min_supporting = 1
window_secs = 300
cooldown_secs = 600
severity = "Critical"
headline = "{service} became unhealthy after a configuration change"
cause = "A configuration change was followed by a service failure within {window} seconds."
actions = ["Review the change to the affected file", "Roll back the latest configuration"]
"#;

    fn no_exclude() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    #[test]
    fn parses_rule_from_toml() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        assert_eq!(rule.id, "config_change_outage");
        assert_eq!(rule.trigger, EventKind::ServiceFailed);
        assert_eq!(rule.supporting.len(), 4);
        assert_eq!(rule.cooldown_secs, 600);
        assert!(!rule.is_fallback);
    }

    #[test]
    fn matches_rule_when_trigger_and_supporting_in_window() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::SshLogin,
                Severity::Info,
                "ssh:login:deploy",
            ),
            ev(
                "e-2",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:/etc/myapp/config.yml",
            ),
            ev(
                "e-3",
                999_999_750_000,
                EventKind::ServiceRestarted,
                Severity::Info,
                "svc:myapp.service",
            ),
            ev(
                "e-4",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        let m = match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude());
        let matched = m.expect("matched");
        assert_eq!(matched.events.len(), 4);
        assert!(matched
            .events
            .iter()
            .any(|e| e.kind == EventKind::ServiceFailed));
        assert_eq!(matched.service, Some("myapp.service".to_string()));
    }

    #[test]
    fn does_not_match_trigger_without_supporting() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![ev(
            "e-1",
            999_999_800_000,
            EventKind::ServiceFailed,
            Severity::Critical,
            "svc:myapp.service",
        )];
        assert!(match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).is_none());
    }

    #[test]
    fn does_not_match_events_outside_window() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-1",
                999_600_000_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:x",
            ),
        ];
        // e-1: now - e-1 = 400_000_000 ms > window 300_000 ms → outside
        assert!(match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).is_none());
    }

    #[test]
    fn excluded_events_do_not_match() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-2",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-4",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:x",
            ),
        ];
        let mut exclude = std::collections::HashSet::new();
        exclude.insert("e-4".to_string());
        assert!(
            match_rule(&rule, &events, 1_000_000_000_000, "h-1", &exclude).is_none(),
            "trigger already absorbed"
        );
    }

    #[test]
    fn headline_slots_are_filled() {
        let rule: Rule = toml::from_str(CFG_RULE).unwrap();
        let events = vec![
            ev(
                "e-1",
                999_999_700_000,
                EventKind::FileChanged,
                Severity::Warning,
                "fim:x",
            ),
            ev(
                "e-2",
                999_999_800_000,
                EventKind::ServiceFailed,
                Severity::Critical,
                "svc:myapp.service",
            ),
        ];
        let m = match_rule(&rule, &events, 1_000_000_000_000, "h-1", &no_exclude()).unwrap();
        let assembled = assemble(&rule, &m, "h-1");
        assert_eq!(
            assembled.headline,
            "myapp.service became unhealthy after a configuration change"
        );
        assert!(assembled.cause.contains("300"));
        assert_eq!(assembled.actions.len(), 2);
        assert!(assembled.affected.iter().any(|a| a == "h-1"));
        assert!(assembled.affected.iter().any(|a| a == "svc:myapp.service"));
    }

    #[test]
    fn fallback_covers_unmatched_warning_events() {
        let evs = vec![ev(
            "e-1",
            999_999_900_000,
            EventKind::CpuSpike,
            Severity::Warning,
            "cpu:usage",
        )];
        let incidents = fallback_incidents(&evs, 1_000_000_000_000, "h-1");
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].headline, "CpuSpike: cpu:usage");
        assert_eq!(incidents[0].severity, "Warning");
    }

    #[test]
    fn default_rules_include_config_change_and_fallback() {
        let rules = default_rules();
        assert!(rules.iter().any(|r| r.id == "config_change_outage"));
        assert!(rules.iter().any(|r| r.id == "fallback"));
        assert!(rules.iter().any(|r| r.id == "ssh_bruteforce"));
        let cfg = rules
            .iter()
            .find(|r| r.id == "config_change_outage")
            .unwrap();
        assert!(
            cfg.supporting.contains(&EventKind::CpuSpike),
            "cpu spike absorbed so the demo yields ONE incident"
        );
    }
}
