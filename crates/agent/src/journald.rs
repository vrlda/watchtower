use std::path::Path;

use crate::cmd::CommandRunner;

/// One journal entry, reduced to what the sensors need.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // wired in engine Task 6
pub struct JournalLine {
    /// Unix millis (journal __REALTIME_TIMESTAMP is microseconds; /1000).
    pub ts_ms: i64,
    pub ident: String,
    pub pid: i64,
    pub message: String,
}

/// Parse journalctl -o json output: one JSON object per line.
/// Accepts either a file path or raw text. Non-JSON and empty lines are
/// skipped (fail-open).
#[allow(dead_code)] // wired in engine Task 6
pub fn parse_journal(path_or_text: &str) -> Result<Vec<JournalLine>, String> {
    let text = if Path::new(path_or_text).exists() {
        std::fs::read_to_string(path_or_text).map_err(|e| e.to_string())?
    } else {
        path_or_text.to_string()
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(ts) = v.get("__REALTIME_TIMESTAMP").and_then(|t| t.as_str()) else {
            continue;
        };
        let Ok(ts_us) = ts.parse::<i64>() else {
            continue;
        };
        let ident = v
            .get("SYSLOG_IDENTIFIER")
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();
        let pid = v
            .get("_PID")
            .and_then(|p| p.as_str())
            .and_then(|p| p.parse::<i64>().ok())
            .unwrap_or(0);
        let message = v
            .get("MESSAGE")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        out.push(JournalLine {
            ts_ms: ts_us / 1000,
            ident,
            pid,
            message,
        });
    }
    Ok(out)
}

/// Poll journalctl for lines with realtime timestamp >= since (unix seconds).
/// journalctl returns nothing (exit 0) when there are no new entries.
#[allow(dead_code)] // wired in engine Task 6
pub fn read_since(
    runner: &dyn CommandRunner,
    since_secs: i64,
    max_attempts: u32,
) -> Result<Vec<JournalLine>, String> {
    let since_arg = format!("@{since_secs}");
    let attempts = max_attempts.to_string();
    let mut args: Vec<&str> = vec!["--no-pager", "-o", "json", "--since", &since_arg];
    if max_attempts > 0 {
        args.push("-n");
        args.push(&attempts);
    }
    let out = runner.run(&args)?;
    parse_journal(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/journald/ssh.jsonl")
    }

    #[test]
    fn parses_journal_json_lines() {
        let lines = parse_journal(fixture_path().to_str().unwrap()).unwrap();
        assert!(lines.len() >= 8, "got {}", lines.len());
        let first = &lines[0];
        assert_eq!(first.ts_ms, 1_758_000_000_123);
        assert_eq!(first.ident, "sshd");
        assert!(first.message.contains("Accepted publickey"));
    }

    #[test]
    fn skips_non_json_and_empty_lines() {
        let tmp = std::env::temp_dir().join(format!("journal-bad-{}", std::process::id()));
        std::fs::write(
            &tmp,
            "not json\n\n{\"MESSAGE\":\"ok\",\"__REALTIME_TIMESTAMP\":\"1000\"}\n",
        )
        .unwrap();
        let lines = parse_journal(tmp.to_str().unwrap()).unwrap();
        assert_eq!(lines.len(), 1);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn journalctl_reader_uses_since_arg() {
        let runner = FakeRunner;
        let out = read_since(&runner, 1_758_000_000, 0).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].message, "accepted");
    }

    struct FakeRunner;

    impl crate::cmd::CommandRunner for FakeRunner {
        fn program(&self) -> &'static str {
            "journalctl"
        }
        fn run(&self, args: &[&str]) -> Result<String, String> {
            assert!(args.contains(&"--since"));
            assert!(args.contains(&"@1758000000"));
            Ok(r#"{"MESSAGE":"accepted","__REALTIME_TIMESTAMP":"1758000000123000","SYSLOG_IDENTIFIER":"sshd"}"#.to_string())
        }
    }
}
