mod acl;
mod crypto;
mod identity;
mod state_machine;
mod stealth;
mod sys_net;
mod transport;

use acl::AccessControlList;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use crypto::Seed;
use identity::{
    generate_x25519_identity, read_private_key_file, read_public_key_arg, write_private_key_file,
    write_public_key_file,
};
use state_machine::SessionConfig;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use stealth::TrafficProfile;
use sys_net::{NetConfig, NetworkGuard};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "morphvpn", about = "MorphVPN beta-ready tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long, alias = "seed")]
        psk: String,
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
    },
    Client {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long, alias = "seed")]
        psk: String,
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
    },
    Keygen {
        #[arg(long)]
        private_out: PathBuf,
        #[arg(long)]
        public_out: PathBuf,
    },
    Example,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum ProfileArg {
    Https,
    Video,
    Gaming,
}

impl From<ProfileArg> for TrafficProfile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Https => TrafficProfile::HttpsLike,
            ProfileArg::Video => TrafficProfile::VideoCallLike,
            ProfileArg::Gaming => TrafficProfile::GamingLike,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("morphvpn=info")),
        )
        .init();

    match Cli::parse().command {
        Commands::Server {
            bind,
            psk,
            private_key,
            acl,
            tun,
            profile,
            tun_ip,
            no_auto_net,
        } => {
            run_server(
                bind,
                psk,
                private_key,
                acl,
                tun,
                profile,
                tun_ip,
                no_auto_net,
            )
            .await?
        }
        Commands::Client {
            server,
            psk,
            private_key,
            server_public_key,
            tun,
            profile,
            tun_ip,
            gateway,
            no_auto_net,
        } => {
            run_client(
                server,
                psk,
                private_key,
                server_public_key,
                tun,
                profile,
                tun_ip,
                gateway,
                no_auto_net,
            )
            .await?
        }
        Commands::Keygen {
            private_out,
            public_out,
        } => run_keygen(private_out, public_out)?,
        Commands::Example => print_example(),
    }

    Ok(())
}

async fn run_server(
    bind: SocketAddr,
    psk_hex: String,
    private_key_path: PathBuf,
    acl_path: PathBuf,
    tun_name: String,
    profile: ProfileArg,
    tun_ip: String,
    no_auto_net: bool,
) -> Result<()> {
    let psk = parse_seed(&psk_hex)?;
    let identity = read_private_key_file(&private_key_path)?;
    let acl = AccessControlList::load(&acl_path)?;
    let session_cfg = SessionConfig::server(psk, identity, acl, profile.into())?;

    info!("starting server on {bind}, tun={tun_name}, profile={profile:?}");

    let net_cfg = if no_auto_net {
        None
    } else {
        let mut cfg = NetConfig::server(&tun_name);
        cfg.tun_ip = tun_ip.clone();
        Some(cfg)
    };
    let net_guard: Option<Arc<Mutex<NetworkGuard>>> = if let Some(cfg) = net_cfg.clone() {
        Some(Arc::new(Mutex::new(sys_net::setup_server(cfg)?)))
    } else {
        None
    };

    let guard_for_shutdown = net_guard.clone();
    let outcome = tokio::select! {
        result = transport::run_server(session_cfg, bind, &tun_name, net_cfg.clone()) => {
            if let Err(err) = result {
                error!("server tunnel error: {err}");
                Err(err)
            } else {
                Ok(())
            }
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received");
            Ok(())
        }
    };

    if let Some(guard) = guard_for_shutdown {
        if let Ok(mut guard) = guard.lock() {
            guard.cleanup();
        }
    }
    outcome
}

async fn run_client(
    server_addr: SocketAddr,
    psk_hex: String,
    private_key_path: PathBuf,
    server_public_key: String,
    tun_name: String,
    profile: ProfileArg,
    tun_ip: String,
    gateway: String,
    no_auto_net: bool,
) -> Result<()> {
    let psk = parse_seed(&psk_hex)?;
    let identity = read_private_key_file(&private_key_path)?;
    let server_public = read_public_key_arg(&server_public_key)?;
    let expected_tun_ip: Ipv4Addr = tun_ip
        .parse()
        .map_err(|err| anyhow!("invalid client tunnel IP '{tun_ip}': {err}"))?;
    let session_cfg = SessionConfig::client(
        psk,
        identity,
        server_public,
        profile.into(),
        expected_tun_ip,
    )?;

    info!("starting client to {server_addr}, tun={tun_name}, profile={profile:?}");

    let net_cfg = if no_auto_net {
        None
    } else {
        let mut cfg = NetConfig::client(&tun_name);
        cfg.tun_ip = tun_ip.clone();
        cfg.gateway_ip = gateway.clone();
        cfg.server_ip = Some(server_addr.ip());
        Some(cfg)
    };
    let net_guard: Option<Arc<Mutex<NetworkGuard>>> = if let Some(cfg) = net_cfg.clone() {
        Some(Arc::new(Mutex::new(sys_net::setup_client(cfg)?)))
    } else {
        None
    };

    let guard_for_shutdown = net_guard.clone();
    let outcome = tokio::select! {
        result = transport::run_client(session_cfg, server_addr, &tun_name, net_cfg.clone()) => {
            if let Err(err) = result {
                error!("client tunnel error: {err}");
                Err(err)
            } else {
                Ok(())
            }
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received");
            Ok(())
        }
    };

    if let Some(guard) = guard_for_shutdown {
        if let Ok(mut guard) = guard.lock() {
            guard.cleanup();
        }
    }
    outcome
}

fn run_keygen(private_out: PathBuf, public_out: PathBuf) -> Result<()> {
    let identity = generate_x25519_identity();
    write_private_key_file(&private_out, &identity.private)?;
    write_public_key_file(&public_out, &identity.public)?;
    println!("{}", hex::encode(identity.public));
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).expect("failed to bind SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to bind SIGTERM");
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn print_example() {
    println!(
        "\
Key generation:
  morphvpn keygen --private-out server.key --public-out server.pub
  morphvpn keygen --private-out client.key --public-out client.pub

Server:
  morphvpn server --bind 0.0.0.0:51820 --psk <HEX32> --private-key server.key --acl acl.toml --tun tun0

Client:
  morphvpn client --server 203.0.113.10:51820 --psk <HEX32> --private-key client.key --server-public-key server.pub --tun tun1 --tun-ip 10.8.0.5
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
