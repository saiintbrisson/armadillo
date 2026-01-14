mod client;
mod io;
mod protocol;
mod relay;
mod share_code;
mod tls;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use client::TunnelClient;
use relay::RelayServer;
use share_code::decode_share_code;
use std::net::SocketAddr;

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
        /// Your relay server address (e.g., "1.2.3.4:65472")
        #[arg(short, long)]
        relay: String,

        /// Original share code from your Hytale world
        share_code: String,
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
        Commands::Tunnel { relay, share_code } => {
            let relay_addr = relay.parse().context("Invalid relay address")?;

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

            let client = TunnelClient::new(relay_addr, local_addr).await?;
            let new_code = client.setup_tunnel(&share_code).await?;

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
        } => {
            let server = RelayServer::new(bind, start_port, end_port, max_players);
            server.run().await?;
        }
    }

    Ok(())
}
