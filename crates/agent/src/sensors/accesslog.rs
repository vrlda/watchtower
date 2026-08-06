//! nginx/apache combined-format access log parsing.

/// One combined-format access log line.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessLine {
    pub ip: String,
    pub status: u16,
    pub request: String,
}

/// Parse a combined-format line:
/// `ip - user [date] "METHOD path proto" status bytes "referrer" "ua"`
pub fn parse_combined(line: &str) -> Option<AccessLine> {
    let parts: Vec<&str> = line.split(' ').collect();
    let ip = parts.first().map(|s| s.to_string())?;
    if ip.starts_with('"') {
        return None; // the line starts with the request, not an ip
    }
    let req_idx = parts
        .iter()
        .position(|t| t.starts_with('"') && t.len() > 1)?;
    let req_len = parts[req_idx..].iter().position(|t| t.ends_with('"'))?;
    let status = parts.get(req_idx + req_len + 1).map(|s| s.to_string())?;
    let request = parts[req_idx..=req_idx + req_len]
        .join(" ")
        .trim_matches('"')
        .to_string();
    Some(AccessLine {
        ip,
        status: status.parse().ok()?,
        request,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_line() {
        let line = r#"127.0.0.1 - - [07/Aug/2026:10:00:00 +0000] "GET /health HTTP/1.1" 200 5 "-" "curl/8.0""#;
        let al = parse_combined(line).unwrap();
        assert_eq!(al.ip, "127.0.0.1");
        assert_eq!(al.status, 200);
        assert_eq!(al.request, "GET /health HTTP/1.1");
    }

    #[test]
    fn parses_5xx_and_malformed() {
        let line = r#"10.0.0.1 - - [07/Aug/2026:10:00:01 +0000] "POST /api/order HTTP/1.1" 503 12 "-" "curl/8.0""#;
        assert_eq!(parse_combined(line).unwrap().status, 503);
        assert!(parse_combined("not a log line").is_none());
        assert!(parse_combined("").is_none());
        assert!(
            parse_combined(r#""GET / HTTP/1.1" 200 1"#).is_none(),
            "no ip"
        );
    }
}
