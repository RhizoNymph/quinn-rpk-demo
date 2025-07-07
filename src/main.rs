mod client;
mod common;
mod server;

use clap::{Args, Parser, Subcommand};
use std::{
    net::SocketAddr, path::PathBuf
};
use anyhow::Result;

use client::run_client;
use server::run_server;

#[derive(Debug, Args)]
struct ClientArgs {
    #[clap(long, default_value="127.0.0.1:4433")]
    server: SocketAddr
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[clap(long, default_value = "127.0.0.1:4433")]
    listen: SocketAddr
}

#[derive(Debug, Subcommand)]
enum RunMode {
    Client(ClientArgs),
    Server(ServerArgs)
}

#[derive(Debug, clap::Args)]
struct GlobalArgs {
    #[clap(long)]
    key: Option<PathBuf>,
    #[clap(long)]
    cert: Option<PathBuf>
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(flatten)]
    global: GlobalArgs,

    #[clap(subcommand)]
    mode: RunMode
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    
    match args.mode {
        RunMode::Client(client_args) => {
            println!("Client mode");
            run_client(
                client_args.server,
                args.global.key.as_deref(),
                args.global.cert.as_deref()
            ).await?;
        }
        RunMode::Server(server_args) => {
            println!("Server mode");
            run_server(
                server_args.listen,
                args.global.key.as_deref(),
                args.global.cert.as_deref()
            ).await?;
        }
    }
    Ok(())
}