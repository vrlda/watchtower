use std::path::{Path, PathBuf};

pub fn resolve_from_path(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let id = text.trim().to_string();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Machine id from /etc/machine-id, then /var/lib/dbus/machine-id,
/// then hostname as last resort.
pub fn resolve() -> String {
    resolve_from_path(&PathBuf::from("/etc/machine-id"))
        .or_else(|| resolve_from_path(&PathBuf::from("/var/lib/dbus/machine-id")))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown-host".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_machine_id_file() {
        let p = std::env::temp_dir().join(format!("machine-id-{}", std::process::id()));
        std::fs::write(&p, "abc123def\n").unwrap();
        assert_eq!(resolve_from_path(&p), Some("abc123def".to_string()));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn machine_id_missing_returns_none() {
        let p = std::env::temp_dir().join("definitely-missing-machine-id");
        assert_eq!(resolve_from_path(&p), None);
    }

    #[test]
    fn blank_machine_id_returns_none() {
        let p = std::env::temp_dir().join(format!("machine-id-blank-{}", std::process::id()));
        std::fs::write(&p, "   \n").unwrap();
        assert_eq!(resolve_from_path(&p), None);
        std::fs::remove_file(&p).ok();
    }
}
