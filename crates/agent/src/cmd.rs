use std::process::Command;

pub trait CommandRunner {
    fn run(&self, args: &[&str]) -> Result<String, String>;
}

pub struct SystemCtl;

impl CommandRunner for SystemCtl {
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new("systemctl")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("systemctl exited {}", out.status));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}
