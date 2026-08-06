//! Agent state persisted across restarts (JSON). Written periodically; a
//! crash loses at most the last interval.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PersistedState {
    pub seen_ips: Vec<String>,
    pub journal_cursor_ms: i64,
    pub last_cert_scan: i64,
    pub known_exes: Vec<String>,
}

pub fn load(path: &Path) -> PersistedState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, s: &PersistedState) {
    if let Ok(json) = serde_json::to_string(s) {
        let _ = std::fs::write(path, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = std::env::temp_dir().join(format!("wt-state-{}", std::process::id()));
        let s = PersistedState {
            seen_ips: vec!["1.2.3.4".into()],
            journal_cursor_ms: 123,
            last_cert_scan: 456,
            known_exes: vec!["/usr/bin/x".into()],
        };
        save(&p, &s);
        let loaded = load(&p);
        assert_eq!(loaded.seen_ips, s.seen_ips);
        assert_eq!(loaded.journal_cursor_ms, 123);
        assert_eq!(loaded.known_exes, s.known_exes);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn missing_file_is_default() {
        let p = std::env::temp_dir().join("definitely-missing-wt-state");
        assert_eq!(load(&p), PersistedState::default());
    }

    #[test]
    fn corrupt_file_is_default() {
        let p = std::env::temp_dir().join(format!("wt-state-bad-{}", std::process::id()));
        std::fs::write(&p, "not json").unwrap();
        assert_eq!(load(&p), PersistedState::default());
        std::fs::remove_file(&p).ok();
    }
}
