mod client;
mod io;
mod protocol;
mod relay;
mod share_code;
mod tls;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use client::TunnelClient;
use relay::RelayServer;
use share_code::decode_share_code;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::info;

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("Empty duration string"));
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str.parse().context("Invalid number in duration")?;

    match unit {
        "s" => Ok(Duration::from_secs(num)),
        "m" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 3600)),
        "d" => Ok(Duration::from_secs(num * 86400)),
        _ => Err(anyhow!("Invalid duration unit: {unit}. Use s, m, h, or d")),
    }
}

#[derive(Parser)]
#[command(name = "armadillo")]
#[command(about = "Hytale CGNAT/UPnP bypass relay", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to relay and set up tunnel (host machine)
    Tunnel {
        /// Your relay server address (e.g., "1.2.3.4:65472"). Can also be set via ARMADILLO_RELAY env var
        #[arg(short, long, env = "ARMADILLO_RELAY")]
        relay: String,

        /// Original share code (the string Hytale generates when sharing a world) or local server address (e.g., "127.0.0.1:5520")
        share_code: String,

        /// Expiration time (e.g., "1h", "30m", "7d", default: "7d")
        #[arg(short, long, default_value = "7d")]
        expires: String,

        /// Password for relay authentication. Can also be set via ARMADILLO_PASS env var
        #[arg(short, long, env = "ARMADILLO_PASS")]
        password: Option<String>,
    },

    /// Run relay server (relay machine)
    Serve {
        /// Address to bind to (default: 0.0.0.0:65472)
        #[arg(short, long, default_value = "0.0.0.0:65472")]
        bind: SocketAddr,

        /// Starting port for player allocations (default: 60000)
        #[arg(long, default_value = "60000")]
        start_port: u16,

        /// Ending port for player allocations (default: 65535)
        #[arg(long, default_value = "65535")]
        end_port: u16,

        /// Maximum players per host (default: 10)
        #[arg(long, default_value = "10")]
        max_players: usize,

        /// Password required for authentication. Can also be set via ARMADILLO_PASS env var
        #[arg(short, long, env = "ARMADILLO_PASS")]
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    match Cli::parse().command {
        Commands::Tunnel { relay, share_code, expires, password } => {
            let relay_addr = relay.parse().context("Invalid relay address")?;

            let (share_data, local_addr) = if let Ok(addr) = share_code.parse::<SocketAddr>() {
                let expires_duration = parse_duration(&expires)?;
                let share_data = share_code::create_share_code(addr, expires_duration)?;
                (share_data, addr)
            } else {
                let share_data = decode_share_code(&share_code)?;
                let local_addr = {
                    let port = share_data
                        .candidates
                        .iter()
                        .find(|c| matches!(c.type_, share_code::CandidateType::Host))
                        .map(|c| c.port)
                        .expect("share code has no Host candidates");
                    format!("127.0.0.1:{port}").parse()?
                };
                (share_data, local_addr)
            };

            let client = TunnelClient::new(relay_addr, local_addr).await?;
            let new_code = client.setup_tunnel(share_data, password).await?;

            println!();
            println!("Share the new code with your friends:");
            println!();
            println!("{new_code}");
            println!();

            client.run_tunnel().await?;
        }

        Commands::Serve {
            bind,
            start_port,
            end_port,
            max_players,
            password,
        } => {
            if password.is_some() {
                info!("Password authentication enabled");
            } else {
                info!("Running without password authentication (insecure!)");
            }
            let server = RelayServer::new(bind, start_port, end_port, max_players, password);
            server.run().await?;
        }
    }

    Ok(())
}
