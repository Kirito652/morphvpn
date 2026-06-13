mod acl;
mod cert;
mod config;
mod health;
mod identity;
mod metrics;
mod peer;
mod runtime;
mod sys_net;
mod transport;

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sys_net::NetConfig;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "morphvpn", about = "MorphVPN v1 zero-legacy tunnel runtime")]
struct Cli {
    #[arg(long, short = 'c', env = "MORPHVPN_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server(ServerArgs),
    Client(ClientArgs),
    Keygen(KeygenArgs),
    Certgen(CertgenArgs),
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
    #[arg(long, value_enum)]
    profile: Option<ProfileArg>,
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
    #[arg(long, value_enum)]
    profile: Option<ProfileArg>,
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

#[derive(Args)]
struct CertgenArgs {
    #[arg(long)]
    cn: String,
    #[arg(long)]
    cert_out: PathBuf,
    #[arg(long)]
    key_out: PathBuf,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum ProfileArg {
    Https,
    Video,
    Gaming,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_config = if let Some(config_path) = &cli.config {
        config::MorphConfig::load(config_path).ok()
    } else {
        None
    }.and_then(|c| c.log);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            let level = log_config.as_ref()
                .map(|c| c.level.as_str())
                .unwrap_or("morphvpn=info");
            EnvFilter::new(level)
        });

    let format = log_config.as_ref()
        .map(|c| c.format.as_str())
        .unwrap_or("pretty");

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .init();
        }
    }

    let (server_cfg, client_cfg, config_profile, health_cfg) = if let Some(config_path) = &cli.config {
        let cfg = config::MorphConfig::load(config_path)?;
        (cfg.server, cfg.client, cfg.profile, cfg.health)
    } else {
        (None, None, None, None)
    };

    match cli.command {
        Commands::Server(args) => run_server(args, server_cfg, config_profile, health_cfg).await?,
        Commands::Client(args) => run_client(args, client_cfg, config_profile).await?,
        Commands::Keygen(args) => run_keygen(args)?,
        Commands::Certgen(args) => run_certgen(args)?,
        Commands::Example => print_example(),
    }

    Ok(())
}

async fn run_server(args: ServerArgs, cfg: Option<config::ServerConfig>, config_profile: Option<String>, health_cfg: Option<config::HealthConfig>) -> Result<()> {
    let (psk, identity, acl, bind, tun_name, tun_ip, no_auto_net, cookie_master_key, tcp_config) = if let Some(cfg) = cfg {
        let psk = if let Some(ref psk_cfg) = cfg.psk {
            load_psk_from_config(psk_cfg)?
        } else {
            load_psk(&args.psk)?
        };
        let identity = read_private_key_file(&cfg.private_key)?;
        let acl = AccessControlList::load(&cfg.acl)?;
        let cookie_master_key = if let Some(ref cookie_cfg) = cfg.cookie {
            if let Some(ref hex_key) = cookie_cfg.master_key {
                config::parse_cookie_key(hex_key)?
            } else {
                config::generate_cookie_key()
            }
        } else {
            config::generate_cookie_key()
        };
        (psk, identity, acl, cfg.bind, cfg.tun, cfg.tun_ip, cfg.no_auto_net, cookie_master_key, cfg.tcp)
    } else {
        let psk = load_psk(&args.psk)?;
        let identity = read_private_key_file(&args.private_key)?;
        let acl = AccessControlList::load(&args.acl)?;
        let cookie_master_key = config::generate_cookie_key();
        (psk, identity, acl, args.bind.to_string(), args.tun.clone(), args.tun_ip.clone(), args.no_auto_net, cookie_master_key, None)
    };

    let bind_addr: SocketAddr = bind.parse()
        .with_context(|| format!("invalid bind address '{bind}'"))?;

    let num_shards = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);

    info!(
        "starting server on {}, tun={}, shards={}",
        bind_addr, tun_name, num_shards
    );

    let net_cfg = if no_auto_net {
        None
    } else {
        let mut cfg = NetConfig::server(&tun_name);
        cfg.tun_ip = tun_ip;
        Some(cfg)
    };
    let _network_guard = if let Some(cfg) = net_cfg {
        Some(sys_net::setup_server(cfg)?)
    } else {
        None
    };

    let profile_name = args.profile
        .map(|p| format!("{:?}", p).to_lowercase())
        .or(config_profile)
        .unwrap_or_else(|| "https".into());
    let profile_params = config::ProfileParams::from_name(&profile_name);

    let running = Arc::new(AtomicBool::new(true));

    if let Some(ref tcp_cfg) = tcp_config {
        if tcp_cfg.enabled {
            let tcp_addr: SocketAddr = format!("{}:{}", bind_addr.ip(), tcp_cfg.port).parse()
                .with_context(|| "invalid TCP address")?;
            let tcp_listener = transport::TcpServer::bind(tcp_addr).await?;
            info!("TCP fallback listening on {}", tcp_listener.local_addr()?);
            let running_clone = running.clone();
            tokio::spawn(async move {
                loop {
                    if !running_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    match tcp_listener.accept().await {
                        Ok((stream, addr)) => {
                            info!("TCP connection from {}", addr);
                            drop(stream);
                        }
                        Err(e) => {
                            tracing::error!("TCP accept error: {}", e);
                        }
                    }
                }
            });
        }
    }

    if let Some(ref hc) = health_cfg {
        let health_addr: SocketAddr = hc.bind.parse()
            .with_context(|| "invalid health bind address")?;
        let health_server = health::HealthServer::bind(health_addr).await?;
        info!("health endpoint on {}", health_server.local_addr()?);
        tokio::spawn(async move {
            let rx = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let tx = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let _ = health_server.run(rx, tx).await;
        });
    }

    tokio::select! {
        result = runtime::run_server(ServerRuntimeConfig {
            bind: bind_addr,
            tun_name,
            psk,
            identity,
            acl,
            num_shards,
            cookie_master_key,
            profile: profile_params,
            running: running.clone(),
        }) => {
            running.store(false, Ordering::Relaxed);
            match result {
                Ok(()) => Ok(()),
                Err(err) => {
                    error!("server runtime failed: {err}");
                    Err(err)
                }
            }
        }
        result = shutdown_signal() => {
            running.store(false, Ordering::Relaxed);
            result?;
            info!("shutdown signal received");
            Ok(())
        }
    }
}

async fn run_client(args: ClientArgs, cfg: Option<config::ClientConfig>, config_profile: Option<String>) -> Result<()> {
    let (psk, identity, server_public_key, tun_name, tun_ip, gateway, server_addr, no_auto_net) = if let Some(cfg) = cfg {
        let psk = if let Some(ref psk_cfg) = cfg.psk {
            load_psk_from_config(psk_cfg)?
        } else {
            load_psk(&args.psk)?
        };
        let identity = read_private_key_file(&cfg.private_key)?;
        let server_public_key = read_public_key_arg(&cfg.server_public_key)?;
        let server_addr: SocketAddr = cfg.server.parse()
            .with_context(|| format!("invalid server address '{}'", cfg.server))?;
        (psk, identity, server_public_key, cfg.tun, cfg.tun_ip, cfg.gateway, server_addr, cfg.no_auto_net)
    } else {
        let psk = load_psk(&args.psk)?;
        let identity = read_private_key_file(&args.private_key)?;
        let server_public_key = read_public_key_arg(&args.server_public_key)?;
        (psk, identity, server_public_key, args.tun.clone(), args.tun_ip.clone(), args.gateway.clone(), args.server, args.no_auto_net)
    };

    let requested_ip: Ipv4Addr = tun_ip
        .parse()
        .map_err(|err| anyhow!("invalid client tunnel IP '{tun_ip}': {err}"))?;

    info!(
        "starting client to {}, tun={}",
        server_addr, tun_name
    );

    let net_cfg = if no_auto_net {
        None
    } else {
        let mut cfg = NetConfig::client(&tun_name);
        cfg.tun_ip = tun_ip;
        cfg.gateway_ip = gateway;
        cfg.server_ip = Some(server_addr.ip());
        Some(cfg)
    };
    let _network_guard = if let Some(cfg) = net_cfg {
        Some(sys_net::setup_client(cfg)?)
    } else {
        None
    };

    let profile_name = args.profile
        .map(|p| format!("{:?}", p).to_lowercase())
        .or(config_profile)
        .unwrap_or_else(|| "https".into());
    let profile_params = config::ProfileParams::from_name(&profile_name);

    let running = Arc::new(AtomicBool::new(true));

    tokio::select! {
        result = runtime::run_client(ClientRuntimeConfig {
            server_addr,
            tun_name,
            psk,
            identity,
            server_public_key,
            requested_ip,
            profile: profile_params,
            running: running.clone(),
        }) => {
            running.store(false, Ordering::Relaxed);
            match result {
                Ok(()) => Ok(()),
                Err(err) => {
                    error!("client runtime failed: {err}");
                    Err(err)
                }
            }
        }
        result = shutdown_signal() => {
            running.store(false, Ordering::Relaxed);
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

fn run_certgen(args: CertgenArgs) -> Result<()> {
    let identity = cert::CertIdentity::generate_cn(&args.cn)?;
    cert::CertIdentity::save_cert(&args.cert_out, &identity.cert_pem)?;
    cert::CertIdentity::save_key(&args.key_out, &identity.key_pem)?;
    println!("certificate: {}", args.cert_out.display());
    println!("key: {}", args.key_out.display());
    println!("fingerprint: {}", hex::encode(identity.fingerprint));
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

    info!("shutdown signal received, draining...");
    tokio::time::sleep(Duration::from_secs(2)).await;
    info!("drain complete, shutting down");
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

fn load_psk_from_config(psk_config: &config::PskConfig) -> Result<Seed> {
    if let Some(path) = &psk_config.file {
        return load_psk_from_file(path);
    }
    if let Some(env_name) = &psk_config.env {
        let value = std::env::var(env_name)
            .with_context(|| format!("env var '{env_name}' not set"))?;
        let mut v = value.clone();
        let parsed = parse_seed(&v)?;
        v.zeroize();
        return Ok(parsed);
    }
    if let Some(value) = &psk_config.value {
        let mut v = value.clone();
        let parsed = parse_seed(&v)?;
        v.zeroize();
        return Ok(parsed);
    }
    Err(anyhow!("PSK is required via file, env, or value in config"))
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
