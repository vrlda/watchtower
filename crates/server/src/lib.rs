pub mod api;
pub mod app;
pub mod auth;
pub mod config;
pub mod db;
pub mod events;
pub mod hosts;
pub mod ingest;
pub mod probes;

/// Directory of the static web UI. Overridable via WATCHTOWER_UI_DIR;
/// defaults to the crate's static/ dir (tests) or ./static (deployed).
pub fn ui_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("WATCHTOWER_UI_DIR") {
        return std::path::PathBuf::from(dir);
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")
}
