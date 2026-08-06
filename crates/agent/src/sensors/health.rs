//! Journald health signals: OOM kills, kernel panics, clock changes.

use crate::journald::JournalLine;

/// One classified health signal from a journal line.
#[derive(Debug, Clone, PartialEq)]
pub enum HealthSignal {
    OomKill,
    KernelPanic,
    ClockChange,
}

/// Classify a journal line into a health signal, or None.
pub fn classify(line: &JournalLine) -> Option<HealthSignal> {
    let msg = line.message.as_str();
    if msg.contains("Out of memory: Killed process") {
        Some(HealthSignal::OomKill)
    } else if msg.contains("Kernel panic") || msg.contains("panic: kernel") {
        Some(HealthSignal::KernelPanic)
    } else if msg.contains("Time has been changed") || msg.contains("Clock change") {
        Some(HealthSignal::ClockChange)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(msg: &str) -> JournalLine {
        JournalLine {
            ts_ms: 1000,
            ident: "kernel".into(),
            pid: 0,
            message: msg.into(),
        }
    }

    #[test]
    fn classifies_oom() {
        assert_eq!(
            classify(&line(
                "Out of memory: Killed process 1234 (nginx) total-vm:..."
            )),
            Some(HealthSignal::OomKill)
        );
    }

    #[test]
    fn classifies_panic() {
        assert_eq!(
            classify(&line("Kernel panic - not syncing: Fatal exception")),
            Some(HealthSignal::KernelPanic)
        );
    }

    #[test]
    fn classifies_clock_change() {
        assert_eq!(
            classify(&line("systemd[1]: Time has been changed")),
            Some(HealthSignal::ClockChange)
        );
    }

    #[test]
    fn ignores_unrelated() {
        assert_eq!(classify(&line("normal log line")), None);
        assert_eq!(classify(&line("Out of memory: no process killed")), None);
    }
}
