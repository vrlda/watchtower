mod procfs;
mod sensors;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "watchtower-agent", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent continuously.
    Run,
    /// One-shot: collect and print events, then exit.
    Check,
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => println!("watchtower-agent {} (run mode pending part 2)", env!("CARGO_PKG_VERSION")),
        Cmd::Check => println!("watchtower-agent {} (check mode pending part 2)", env!("CARGO_PKG_VERSION")),
    }
}
