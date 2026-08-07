//! In-app exception capture: wire format, fingerprinting, level mapping.

use wt_common::Severity;

/// One stack frame from an SDK.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Frame {
    pub file: String,
    pub line: u32,
    #[serde(default)]
    pub function: String,
}

/// The exception payload from an SDK.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Exception {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub frames: Vec<Frame>,
}

/// The /v1/errors request body.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ErrorEvent {
    pub host_id: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub environment: String,
    pub exception: Exception,
}

/// FNV-1a 64-bit (no external hash dep). A collision merely merges two
/// incidents — acceptable at this scale.
fn fnv1a(input: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in input {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Grouping key: service + exception type + first 3 frames' file:line.
/// Deterministic across SDKs and restarts — the same bug always lands in
/// the same incident.
pub fn fingerprint(service: &str, exception_type: &str, frames: &[(String, u32)]) -> String {
    let mut input = String::new();
    input.push_str(service);
    input.push('\0');
    input.push_str(exception_type);
    input.push('\0');
    for (file, line) in frames.iter().take(3) {
        input.push_str(file);
        input.push(':');
        input.push_str(&line.to_string());
        input.push(';');
    }
    format!("{:016x}", fnv1a(input.as_bytes()))
}

/// Exception level → incident severity (fatal/error → Critical, warning →
/// Warning, info/debug → Info; unknown/empty levels are loud).
pub fn severity_for(level: &str) -> Severity {
    match level.to_lowercase().as_str() {
        "fatal" | "error" | "" => Severity::Critical,
        "warning" => Severity::Warning,
        "info" | "debug" => Severity::Info,
        _ => Severity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wt_common::Severity;

    #[test]
    fn fingerprint_is_deterministic_and_discriminating() {
        let f1 = fingerprint(
            "api",
            "ValueError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        let f2 = fingerprint(
            "api",
            "ValueError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        assert_eq!(f1, f2, "same exception → same fingerprint");
        let f3 = fingerprint(
            "api",
            "ValueError",
            &[("app.py".into(), 41), ("app.py".into(), 10)],
        );
        assert_ne!(f1, f3, "different line → different fingerprint");
        let f4 = fingerprint(
            "web",
            "ValueError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        assert_ne!(f1, f4, "different service → different fingerprint");
        let f5 = fingerprint(
            "api",
            "TypeError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        assert_ne!(f1, f5, "different type → different fingerprint");
        assert!(f1.len() >= 16, "readable hash");
    }

    #[test]
    fn fingerprint_uses_first_three_frames() {
        let a = fingerprint(
            "s",
            "T",
            &[("f1".into(), 1), ("f2".into(), 2), ("f3".into(), 3)],
        );
        let b = fingerprint(
            "s",
            "T",
            &[
                ("f1".into(), 1),
                ("f2".into(), 2),
                ("f3".into(), 3),
                ("f4".into(), 99),
            ],
        );
        assert_eq!(a, b, "frames beyond the first 3 don't matter");
    }

    #[test]
    fn level_maps_to_severity() {
        assert_eq!(severity_for("fatal"), Severity::Critical);
        assert_eq!(severity_for("error"), Severity::Critical);
        assert_eq!(severity_for("warning"), Severity::Warning);
        assert_eq!(severity_for("info"), Severity::Info);
        assert_eq!(severity_for("debug"), Severity::Info);
        assert_eq!(
            severity_for("unknown-level"),
            Severity::Critical,
            "unknown → loud"
        );
        assert_eq!(severity_for(""), Severity::Critical);
    }
}
