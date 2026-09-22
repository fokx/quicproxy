use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use quicproxy::client::run_client;
use quicproxy::config::{ClientConfig, ServerConfig, TransportMode};
use quicproxy::server::run_server;
use quicproxy::tls::generate_self_signed;

#[derive(Parser, Debug)]
#[command(
    name = "quicproxy",
    author,
    version,
    about = "High-performance anti-censorship QUIC proxy with SOCKS5 interface"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbose output logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run in server mode
    Server(ServerArgs),
    /// Run in client mode (exposes SOCKS5 proxy)
    Client(ClientArgs),
    /// Generate a self-signed TLS certificate pair
    CertGen(CertGenArgs),
}

#[derive(Args, Debug)]
struct ServerArgs {
    /// Path to server configuration file (TOML)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Listening address and port (e.g. 0.0.0.0:4433)
    #[arg(short, long)]
    listen: Option<SocketAddr>,

    /// Pre-shared authentication key
    #[arg(short = 'k', long)]
    auth_key: Option<String>,

    /// Path to TLS certificate PEM file
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Path to TLS private key PEM file
    #[arg(long)]
    key: Option<PathBuf>,

    /// Domain name for self-signed TLS certificate
    #[arg(long, default_value = "localhost")]
    domain: String,
}

#[derive(Args, Debug)]
struct ClientArgs {
    /// Path to client configuration file (TOML)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// SOCKS5 listening address (e.g. 127.0.0.1:1080)
    #[arg(short = 'l', long)]
    socks5_listen: Option<SocketAddr>,

    /// Remote server address (hostname or IP)
    #[arg(short = 's', long)]
    server_addr: Option<String>,

    /// Remote server port
    #[arg(short = 'p', long)]
    server_port: Option<u16>,

    /// Pre-shared authentication key
    #[arg(short = 'k', long)]
    auth_key: Option<String>,

    /// Pinned SHA-256 certificate fingerprint of the server
    #[arg(long)]
    cert_fingerprint: Option<String>,

    /// Transport mode: auto, quic, or tcp
    #[arg(long)]
    transport: Option<TransportMode>,

    /// Custom CA certificate path
    #[arg(long)]
    ca_cert: Option<PathBuf>,

    /// Skip TLS certificate verification (testing only)
    #[arg(long)]
    insecure: bool,

    /// Override TLS Server Name Indication (SNI)
    #[arg(long)]
    sni: Option<String>,

    /// SOCKS5 username authentication
    #[arg(long)]
    socks5_user: Option<String>,

    /// SOCKS5 password authentication
    #[arg(long)]
    socks5_password: Option<String>,
}

#[derive(Args, Debug)]
struct CertGenArgs {
    /// Domain name for the certificate
    #[arg(short, long, default_value = "localhost")]
    domain: String,

    /// Output path for certificate PEM file
    #[arg(long, default_value = "cert.pem")]
    out_cert: PathBuf,

    /// Output path for private key PEM file
    #[arg(long, default_value = "key.pem")]
    out_key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let env_filter = if cli.verbose {
        EnvFilter::new("quicproxy=debug,quinn=info,warn")
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("quicproxy=info,warn"))
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Server(args) => {
            let mut config = if let Some(config_path) = args.config {
                ServerConfig::from_file(config_path)?
            } else {
                ServerConfig {
                    listen: args
                        .listen
                        .unwrap_or_else(|| "0.0.0.0:4433".parse().unwrap()),
                    auth_key: args
                        .auth_key
                        .clone()
                        .context("Auth key must be provided via --auth-key or config file")?,
                    tls_cert: args.cert.clone(),
                    tls_key: args.key.clone(),
                    auto_cert: true,
                    auto_cert_domain: args.domain,
                }
            };

            if let Some(listen) = args.listen {
                config.listen = listen;
            }
            if let Some(auth_key) = args.auth_key {
                config.auth_key = auth_key;
            }
            if let Some(cert) = args.cert {
                config.tls_cert = Some(cert);
            }
            if let Some(key) = args.key {
                config.tls_key = Some(key);
            }

            run_server(config).await?;
        }
        Commands::Client(args) => {
            let mut config = if let Some(config_path) = args.config {
                ClientConfig::from_file(config_path)?
            } else {
                ClientConfig {
                    socks5_listen: args
                        .socks5_listen
                        .unwrap_or_else(|| "127.0.0.1:1080".parse().unwrap()),
                    server_addr: args
                        .server_addr
                        .clone()
                        .context("Server address must be provided via --server-addr or config file")?,
                    server_port: args.server_port.unwrap_or(4433),
                    auth_key: args
                        .auth_key
                        .clone()
                        .context("Auth key must be provided via --auth-key or config file")?,
                    transport: args.transport.unwrap_or_default(),
                    server_name: args.sni.clone(),
                    insecure: args.insecure,
                    cert_fingerprint: args.cert_fingerprint.clone(),
                    ca_cert: args.ca_cert.clone(),
                    socks5_user: args.socks5_user.clone(),
                    socks5_password: args.socks5_password.clone(),
                }
            };

            if let Some(listen) = args.socks5_listen {
                config.socks5_listen = listen;
            }
            if let Some(addr) = args.server_addr {
                config.server_addr = addr;
            }
            if let Some(port) = args.server_port {
                config.server_port = port;
            }
            if let Some(auth_key) = args.auth_key {
                config.auth_key = auth_key;
            }
            if let Some(transport) = args.transport {
                config.transport = transport;
            }
            if args.insecure {
                config.insecure = true;
            }
            if let Some(cert_fp) = args.cert_fingerprint {
                config.cert_fingerprint = Some(cert_fp);
            }
            if let Some(ca_cert) = args.ca_cert {
                config.ca_cert = Some(ca_cert);
            }
            if let Some(sni) = args.sni {
                config.server_name = Some(sni);
            }

            run_client(config).await?;
        }
        Commands::CertGen(args) => {
            println!("Generating self-signed certificate for '{}'...", args.domain);
            let (cert_pem, key_pem, fingerprint) = generate_self_signed(&args.domain)?;

            std::fs::write(&args.out_cert, &cert_pem)
                .with_context(|| format!("Failed to write cert to {}", args.out_cert.display()))?;
            std::fs::write(&args.out_key, &key_pem)
                .with_context(|| format!("Failed to write key to {}", args.out_key.display()))?;

            println!("Saved certificate to: {}", args.out_cert.display());
            println!("Saved private key to:  {}", args.out_key.display());
            println!("Certificate SHA-256 Fingerprint: {}", fingerprint);
        }
    }

    Ok(())
}
