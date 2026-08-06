//! Security-relevant journald signals: user/package changes.

use std::collections::HashMap;
use std::path::Path;

use crate::journald::JournalLine;

#[derive(Debug, Clone, PartialEq)]
pub enum SecSignal {
    NewUser(String),
    PackageInstalled(String),
}

/// Classify a journal line into a security signal, or None.
pub fn classify(line: &JournalLine) -> Option<SecSignal> {
    let msg = line.message.as_str();
    let ident = line.ident.as_str();
    if ident == "useradd" || ident == "usermod" || ident == "userdel" || msg.contains("new user") {
        Some(SecSignal::NewUser(msg.to_string()))
    } else if (ident == "dpkg" || ident == "apt" || ident == "dnf" || ident == "yum")
        && (msg.contains("install")
            || msg.contains("Install:")
            || msg.contains("upgrade")
            || msg.contains("remove"))
    {
        Some(SecSignal::PackageInstalled(msg.to_string()))
    } else {
        None
    }
}

/// Snapshot of a directory's file metadata (path → (mtime, size)).
pub fn snapshot_dir(root: &Path) -> HashMap<String, (i64, u64)> {
    let mut out = HashMap::new();
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for e in entries.flatten() {
        if let Ok(meta) = e.metadata() {
            if let Ok(mtime) = meta.modified() {
                if let Ok(secs) = mtime.duration_since(std::time::UNIX_EPOCH) {
                    out.insert(
                        e.file_name().to_string_lossy().into_owned(),
                        (secs.as_secs() as i64, meta.len()),
                    );
                }
            }
        }
    }
    out
}

/// Changed/added/removed paths between two snapshots.
pub fn diff_snapshots(
    before: &HashMap<String, (i64, u64)>,
    after: &HashMap<String, (i64, u64)>,
) -> Vec<String> {
    let mut changed = Vec::new();
    for (path, meta) in after {
        match before.get(path) {
            Some(prev) if prev == meta => {}
            _ => changed.push(path.clone()),
        }
    }
    for path in before.keys() {
        if !after.contains_key(path) {
            changed.push(path.clone());
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(ident: &str, msg: &str) -> JournalLine {
        JournalLine {
            ts_ms: 1000,
            ident: ident.into(),
            pid: 0,
            message: msg.into(),
        }
    }

    #[test]
    fn classifies_user_changes() {
        assert_eq!(
            classify(&line("useradd", "new user: name=alice")),
            Some(SecSignal::NewUser("new user: name=alice".into()))
        );
        assert_eq!(
            classify(&line("usermod", "change user bob")),
            Some(SecSignal::NewUser("change user bob".into()))
        );
    }

    #[test]
    fn classifies_package_changes() {
        assert_eq!(
            classify(&line("dpkg", "status installed nginx:amd64 1.18.0")),
            Some(SecSignal::PackageInstalled(
                "status installed nginx:amd64 1.18.0".into()
            ))
        );
        assert_eq!(
            classify(&line("apt", "Install: redis-server:amd64")),
            Some(SecSignal::PackageInstalled(
                "Install: redis-server:amd64".into()
            ))
        );
    }

    #[test]
    fn ignores_unrelated() {
        assert_eq!(classify(&line("systemd", "Started nginx.service.")), None);
        assert_eq!(classify(&line("kernel", "normal line")), None);
        assert_eq!(classify(&line("dpkg", "startup archives unpack")), None);
    }

    fn temp_dir(suffix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wt-sec-{}-{}", std::process::id(), suffix))
    }

    #[test]
    fn snapshot_diff_detects_modified_added_removed() {
        let dir = temp_dir("modified");
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.conf");
        let b = dir.join("b.conf");
        std::fs::write(&a, "aaa").unwrap();
        std::fs::write(&b, "bbb").unwrap();
        let before = snapshot_dir(&dir);
        std::fs::write(&a, "changed").unwrap();
        std::fs::write(dir.join("c.conf"), "ccc").unwrap();
        std::fs::remove_file(&b).unwrap();
        let after = snapshot_dir(&dir);
        let mut changed = diff_snapshots(&before, &after);
        changed.sort();
        assert_eq!(changed, vec!["a.conf", "b.conf", "c.conf"]);
        for f in ["a.conf", "b.conf", "c.conf"] {
            std::fs::remove_file(dir.join(f)).ok();
        }
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn snapshot_diff_empty_when_unchanged() {
        let dir = temp_dir("unchanged");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.conf"), "aaa").unwrap();
        let before = snapshot_dir(&dir);
        let after = snapshot_dir(&dir);
        assert!(diff_snapshots(&before, &after).is_empty());
        std::fs::remove_file(dir.join("a.conf")).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
