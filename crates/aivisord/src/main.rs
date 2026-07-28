use anyhow::Result;
use aivisord::daemon;
use clap::Parser;

#[derive(Parser)]
#[command(name = "aivisord", about = "AIVisor gRPC daemon")]
struct Cli {
    #[arg(long, default_value = "/run/aivisor/aivisord.sock")]
    socket: String,

    // Accepted now so `--tls-cert`/`--tls-key` aren't a hard CLI error for
    // anyone scripting against the eventual interface; not read yet
    // because the mTLS TCP listener itself is TODO(phase4) — see daemon.rs.
    #[allow(dead_code)]
    #[arg(long)]
    tls_cert: Option<String>,

    #[allow(dead_code)]
    #[arg(long)]
    tls_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    tracing::info!("Starting aivisord on {}", cli.socket);

    let daemon = daemon::Daemon::new()?;
    daemon.run(&cli.socket).await?;

    Ok(())
}
