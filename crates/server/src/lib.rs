pub mod api;
pub mod api_incidents;
pub mod app;
pub mod auth;
pub mod config;
pub mod correlation;
pub mod db;
pub mod errors;
pub mod events;
pub mod hosts;
pub mod incidents;
pub mod ingest;
pub mod notifier;
pub mod notify;
pub mod probes;
pub mod supervise;
pub mod watchdog;

/// Directory of the static web UI. Resolution order:
/// 1. WATCHTOWER_UI_DIR env var (production installs)
/// 2. the crate's static/ dir (dev / tests — baked at compile time)
/// 3. ./static relative to the working directory (binary deploys)
pub fn ui_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("WATCHTOWER_UI_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");
    if manifest.is_dir() {
        return manifest;
    }
    std::path::PathBuf::from("static")
}
