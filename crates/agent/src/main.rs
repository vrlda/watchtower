mod cmd;
mod engine;
mod hostid;
mod procfs;
mod sensors;
mod telemetry;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use wt_common::{Config, Heartbeat};

#[derive(Parser)]
#[command(name = "watchtower-agent", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Path to config file.
    #[arg(long, default_value = "/etc/watchtower/agent.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent continuously.
    Run,
    /// One-shot: collect and print events, then exit.
    Check,
}

fn load_config(path: &PathBuf) -> Config {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!("invalid config {}: {}; using defaults", path.display(), e);
            Config::default()
        }),
        Err(_) => Config::default(),
    }
}

fn resolve_host_id(cfg: &Config) -> String {
    if cfg.host_id_valid() {
        cfg.host_id.clone()
    } else {
        hostid::resolve()
    }
}

fn main() {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config);
    let host_id = resolve_host_id(&cfg);
    let procfs = procfs::ProcFs::new(PathBuf::from("/proc"));
    let sys = cmd::SystemCtl;
    let spool = telemetry::Spool::new(PathBuf::from(&cfg.spool_dir));

    match cli.cmd {
        Cmd::Check => {
            let mut cpu = engine::CpuState::new(20, cfg.cpu_spike_ratio, &host_id);
            let evs = engine::run_once(
                &cfg,
                &mut engine::Deduper::new(cfg.dedup_secs),
                &host_id,
                now_ms(),
                &procfs,
                &sys,
                &mut sensors::systemd::CrashTracker::new(120),
                &mut cpu,
            );
            for ev in &evs {
                println!("{}", serde_json::to_string(ev).unwrap());
            }
            if evs.is_empty() {
                println!("no issues detected");
            }
        }
        Cmd::Run => {
            let mut deduper = engine::Deduper::new(cfg.dedup_secs);
            let mut crash = sensors::systemd::CrashTracker::new(120);
            let mut cpu = engine::CpuState::new(20, cfg.cpu_spike_ratio, &host_id);
            let mut last_heartbeat = Instant::now() - Duration::from_secs(cfg.heartbeat_secs + 1);
            loop {
                let evs = engine::run_once(
                    &cfg,
                    &mut deduper,
                    &host_id,
                    now_ms(),
                    &procfs,
                    &sys,
                    &mut crash,
                    &mut cpu,
                );
                if !evs.is_empty() && !cfg.server_url.is_empty() {
                    match telemetry::post_batch(&cfg.server_url, &cfg.token, &evs) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("post failed ({:?}); spooling {} events", e, evs.len());
                            if let Err(se) = spool.append(&evs) {
                                eprintln!("spool append failed: {}", se);
                            }
                        }
                    }
                }
                if last_heartbeat.elapsed() >= Duration::from_secs(cfg.heartbeat_secs)
                    && !cfg.server_url.is_empty()
                {
                    drain_spool(&cfg, &spool);
                    let hb = Heartbeat {
                        host_id: host_id.clone(),
                        ts: now_ms(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        queue_len: spool.count() as u64,
                    };
                    if let Err(e) = telemetry::post_heartbeat(&cfg.server_url, &cfg.token, &hb) {
                        eprintln!("heartbeat failed: {:?}", e);
                    }
                    last_heartbeat = Instant::now();
                }
                std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs));
            }
        }
    }
}

/// Replay spooled events, posting oldest-first. Ack (delete) only what was
/// delivered; permanent 4xx failures are acked too (a bad token or payload
/// will never deliver — avoid unbounded spool growth). Retryable failures
/// (transport, 5xx) stay spooled for the next drain.
fn drain_spool(cfg: &Config, spool: &telemetry::Spool) {
    for file in spool.read_all() {
        match telemetry::post_batch(&cfg.server_url, &cfg.token, &file.events) {
            Ok(()) => spool.ack(&file.path),
            Err(telemetry::PostError::HttpStatus(code)) if (400..500).contains(&code) => {
                eprintln!("permanent failure ({}); dropping {} spooled events", code, file.events.len());
                spool.ack(&file.path);
            }
            Err(e) => {
                eprintln!("drain failed ({:?}); {} events stay spooled", e, file.events.len());
                break;
            }
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
