//! Incremental file tailing with an offset cursor (no blocking watcher —
//! polled by the engine like every other sensor).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Tail cursor for one file.
#[derive(Debug, Clone, Copy, Default)]
pub struct TailState {
    offset: u64,
}

impl TailState {
    #[cfg(test)]
    pub fn new() -> Self {
        TailState { offset: 0 }
    }

    /// Read lines appended since the last call. A truncated/rotated file
    /// (offset > len) restarts from the beginning. Fail-open on any error.
    pub fn read_new(&mut self, path: &Path) -> Vec<String> {
        let Ok(meta) = std::fs::metadata(path) else {
            return vec![];
        };
        let len = meta.len();
        if len < self.offset {
            self.offset = 0; // truncated or rotated
        }
        let Ok(mut file) = std::fs::File::open(path) else {
            return vec![];
        };
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return vec![];
        }
        let mut buf = String::new();
        if file.read_to_string(&mut buf).is_err() {
            return vec![];
        }
        self.offset = len;
        buf.lines().map(|l| l.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("wt-tail-{}-{}", name, std::process::id()))
    }

    #[test]
    fn reads_only_new_lines() {
        let p = tmp("inc");
        std::fs::write(&p, "line1\nline2\n").unwrap();
        let mut t = TailState::new();
        let first = t.read_new(&p);
        assert_eq!(first, vec!["line1", "line2"]);
        let mut file = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        use std::io::Write;
        writeln!(file, "line3").unwrap();
        let second = t.read_new(&p);
        assert_eq!(second, vec!["line3"], "only appended lines");
        assert!(t.read_new(&p).is_empty(), "no changes → nothing");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn restarts_on_truncation() {
        let p = tmp("trunc");
        std::fs::write(&p, "aaaa\n").unwrap();
        let mut t = TailState::new();
        assert_eq!(t.read_new(&p).len(), 1);
        std::fs::write(&p, "b\n").unwrap(); // truncated (shorter)
        let lines = t.read_new(&p);
        assert_eq!(
            lines,
            vec!["b"],
            "restart from the beginning after truncation"
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn missing_file_is_empty() {
        let mut t = TailState::new();
        assert!(t
            .read_new(&std::env::temp_dir().join("definitely-missing-wt-tail"))
            .is_empty());
    }
}
