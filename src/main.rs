mod acl;
mod identity;
mod runtime;
mod sys_net;

use acl::AccessControlList;
use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use identity::{
    generate_x25519_identity, read_private_key_file, read_public_key_arg, write_private_key_file,
    write_public_key_file,
};
use morphvpn_protocol::handshake::Seed;
use runtime::{ClientRuntimeConfig, ServerRuntimeConfig};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use sys_net::NetConfig;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "morphvpn", about = "MorphVPN v1 zero-legacy tunnel runtime")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server(ServerArgs),
    Client(ClientArgs),
    Keygen(KeygenArgs),
    Example,
}

#[derive(Args, Clone, Debug)]
struct PskArgs {
    #[arg(long, env = "MORPHVPN_PSK_FILE")]
    psk_file: Option<PathBuf>,
    #[arg(long, env = "MORPHVPN_PSK", hide_env_values = true)]
    psk_env: Option<String>,
}

#[derive(Args, Clone, Debug)]
struct ServerArgs {
    #[arg(long)]
    bind: SocketAddr,
    #[command(flatten)]
    psk: PskArgs,
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    acl: PathBuf,
    #[arg(long, default_value = "tun0")]
    tun: String,
    #[arg(long, value_enum, default_value = "https")]
    profile: ProfileArg,
    #[arg(long, default_value = "10.8.0.1")]
    tun_ip: String,
    #[arg(long, default_value_t = false)]
    no_auto_net: bool,
}

#[derive(Args, Clone, Debug)]
struct ClientArgs {
    #[arg(long)]
    server: SocketAddr,
    #[command(flatten)]
    psk: PskArgs,
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    server_public_key: String,
    #[arg(long, default_value = "tun1")]
    tun: String,
    #[arg(long, value_enum, default_value = "https")]
    profile: ProfileArg,
    #[arg(long, default_value = "10.8.0.2")]
    tun_ip: String,
    #[arg(long, default_value = "10.8.0.1")]
    gateway: String,
    #[arg(long, default_value_t = false)]
    no_auto_net: bool,
}

#[derive(Args, Clone, Debug)]
struct KeygenArgs {
    #[arg(long)]
    private_out: PathBuf,
    #[arg(long)]
    public_out: PathBuf,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum ProfileArg {
    Https,
    Video,
    Gaming,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("morphvpn=info")),
        )
        .init();

    match Cli::parse().command {
        Commands::Server(args) => run_server(args).await?,
        Commands::Client(args) => run_client(args).await?,
        Commands::Keygen(args) => run_keygen(args)?,
        Commands::Example => print_example(),
    }

    Ok(())
}

async fn run_server(args: ServerArgs) -> Result<()> {
    let psk = load_psk(&args.psk)?;
    let identity = read_private_key_file(&args.private_key)?;
    let acl = AccessControlList::load(&args.acl)?;
    let num_shards = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);

    info!(
        "starting server on {}, tun={}, profile={:?}, shards={}",
        args.bind, args.tun, args.profile, num_shards
    );

    let net_cfg = if args.no_auto_net {
        None
    } else {
        let mut cfg = NetConfig::server(&args.tun);
        cfg.tun_ip = args.tun_ip.clone();
        Some(cfg)
    };
    let _network_guard = if let Some(cfg) = net_cfg {
        Some(sys_net::setup_server(cfg)?)
    } else {
        None
    };

    tokio::select! {
        result = runtime::run_server(ServerRuntimeConfig {
            bind: args.bind,
            tun_name: args.tun,
            psk,
            identity,
            acl,
            num_shards,
        }) => {
            match result {
                Ok(()) => Ok(()),
                Err(err) => {
                    error!("server runtime failed: {err}");
                    Err(err)
                }
            }
        }
        result = shutdown_signal() => {
            result?;
            info!("shutdown signal received");
            Ok(())
        }
    }
}

async fn run_client(args: ClientArgs) -> Result<()> {
    let psk = load_psk(&args.psk)?;
    let identity = read_private_key_file(&args.private_key)?;
    let server_public_key = read_public_key_arg(&args.server_public_key)?;
    let requested_ip: Ipv4Addr = args
        .tun_ip
        .parse()
        .map_err(|err| anyhow!("invalid client tunnel IP '{}': {err}", args.tun_ip))?;

    info!(
        "starting client to {}, tun={}, profile={:?}",
        args.server, args.tun, args.profile
    );

    let net_cfg = if args.no_auto_net {
        None
    } else {
        let mut cfg = NetConfig::client(&args.tun);
        cfg.tun_ip = args.tun_ip.clone();
        cfg.gateway_ip = args.gateway.clone();
        cfg.server_ip = Some(args.server.ip());
        Some(cfg)
    };
    let _network_guard = if let Some(cfg) = net_cfg {
        Some(sys_net::setup_client(cfg)?)
    } else {
        None
    };

    tokio::select! {
        result = runtime::run_client(ClientRuntimeConfig {
            server_addr: args.server,
            tun_name: args.tun,
            psk,
            identity,
            server_public_key,
            requested_ip,
        }) => {
            match result {
                Ok(()) => Ok(()),
                Err(err) => {
                    error!("client runtime failed: {err}");
                    Err(err)
                }
            }
        }
        result = shutdown_signal() => {
            result?;
            info!("shutdown signal received");
            Ok(())
        }
    }
}

fn run_keygen(args: KeygenArgs) -> Result<()> {
    let identity = generate_x25519_identity();
    write_private_key_file(&args.private_out, &identity.private)?;
    write_public_key_file(&args.public_out, &identity.public)?;
    println!("{}", hex::encode(identity.public));
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).context("failed to bind SIGINT")?;
        let mut sigterm = signal(SignalKind::terminate()).context("failed to bind SIGTERM")?;
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to wait for Ctrl-C")?;
    }

    Ok(())
}

fn load_psk(args: &PskArgs) -> Result<Seed> {
    if let Some(path) = args.psk_file.as_deref() {
        return load_psk_from_file(path);
    }

    if let Some(psk_env) = args.psk_env.as_ref() {
        let mut value = psk_env.clone();
        let parsed = parse_seed(&value)?;
        value.zeroize();
        return Ok(parsed);
    }

    Err(anyhow!(
        "PSK is required via --psk-file, MORPHVPN_PSK_FILE, or MORPHVPN_PSK"
    ))
}

fn load_psk_from_file(path: &Path) -> Result<Seed> {
    let mut raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read PSK file '{}'", path.display()))?;
    let parsed = parse_seed(&raw)?;
    raw.zeroize();
    Ok(parsed)
}

fn print_example() {
    println!(
        "\
Key generation:
  morphvpn keygen --private-out server.key --public-out server.pub
  morphvpn keygen --private-out client.key --public-out client.pub

Server:
  set MORPHVPN_PSK_FILE=server.psk
  morphvpn server --bind 0.0.0.0:51820 --private-key server.key --acl acl.toml --tun tun0

Client:
  set MORPHVPN_PSK_FILE=client.psk
  morphvpn client --server 203.0.113.10:51820 --private-key client.key --server-public-key server.pub --tun tun1 --tun-ip 10.8.0.5
"
    );
}

fn parse_seed(hex_str: &str) -> Result<Seed> {
    let bytes = hex::decode(hex_str.trim()).map_err(|err| anyhow!("invalid PSK hex: {err}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "PSK must be exactly 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}
