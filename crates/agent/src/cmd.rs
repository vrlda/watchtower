use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub trait CommandRunner {
    // never called in non-test code; kept as part of the interface contract
    #[allow(dead_code)]
    fn program(&self) -> &'static str;
    fn run(&self, args: &[&str]) -> Result<String, String>;
}

pub struct SystemCtl;

impl CommandRunner for SystemCtl {
    fn program(&self) -> &'static str {
        "systemctl"
    }
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let out = run_with_timeout("systemctl", args).map_err(|e| e.to_string())?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "systemctl exited {}: {}",
                out.status,
                stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

pub struct JournalCtl;

impl CommandRunner for JournalCtl {
    fn program(&self) -> &'static str {
        "journalctl"
    }
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let out = run_with_timeout("journalctl", args).map_err(|e| e.to_string())?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "journalctl exited {}: {}",
                out.status,
                stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Spawn `program` with stdout/stderr captured and kill it after TIMEOUT.
/// Reader threads drain the pipes so a verbose child cannot deadlock us.
fn run_with_timeout(program: &str, args: &[&str]) -> Result<Output, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).ok();
        buf
    });
    let err_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf).ok();
        buf
    });

    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if start.elapsed() >= TIMEOUT {
            child.kill().ok();
            child.wait().ok();
            let err = err_reader.join().unwrap_or_default();
            let stderr = String::from_utf8_lossy(&err);
            return Err(format!(
                "{} timed out after 10s: {}",
                program,
                stderr.trim()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    };

    Ok(Output {
        status,
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
    })
}

const TIMEOUT: Duration = Duration::from_secs(10);
