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

    /// HTTP/3 masquerade mode: off, file_server, or reverse_proxy
    #[arg(long)]
    masquerade_mode: Option<quicproxy::server::masquerade::MasqueradeMode>,

    /// Directory of static files for HTTP/3 file_server masquerade
    #[arg(long)]
    masquerade_dir: Option<PathBuf>,

    /// Upstream URL for HTTP/3 reverse_proxy masquerade
    #[arg(long)]
    masquerade_upstream: Option<String>,

    /// Packet obfuscation key (Salamander)
    #[arg(long)]
    obfs_key: Option<String>,

    /// Anti-probe rate limit: max failed attempts before blocking/diverting
    #[arg(long)]
    rate_limit_max: Option<u32>,

    /// Anti-probe jitter min in ms
    #[arg(long)]
    jitter_min: Option<u64>,

    /// Anti-probe jitter max in ms
    #[arg(long)]
    jitter_max: Option<u64>,

    /// Inactivity timeout in seconds for UDP sessions
    #[arg(long)]
    udp_session_timeout: Option<u64>,

    /// Path to ACL rule file
    #[arg(long)]
    acl_file: Option<PathBuf>,
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

    /// Packet obfuscation key (Salamander)
    #[arg(long)]
    obfs_key: Option<String>,

    /// TLS fingerprint profile: default, chrome, firefox
    #[arg(long)]
    tls_profile: Option<String>,

    /// Comma-separated custom ALPN protocols (e.g. h3,h2)
    #[arg(long)]
    alpn: Option<String>,

    /// Multi-server traffic mode: aggregation or resilient
    #[arg(long)]
    traffic_mode: Option<quicproxy::config::TrafficMode>,

    /// Aggregation strategy: round_robin or random
    #[arg(long)]
    strategy: Option<quicproxy::config::AggregationStrategy>,

    /// Outbound relay server anchor name or address
    #[arg(long)]
    relay_to_server: Option<String>,

    /// Path to ACL rule file
    #[arg(long)]
    acl_file: Option<PathBuf>,
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
                    ..Default::default()
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

            if args.masquerade_mode.is_some() || args.masquerade_dir.is_some() || args.masquerade_upstream.is_some() {
                let mut masq = config.masquerade.unwrap_or_default();
                if let Some(mode) = args.masquerade_mode {
                    masq.mode = mode;
                }
                if let Some(dir) = args.masquerade_dir {
                    masq.static_dir = Some(dir);
                }
                if let Some(up) = args.masquerade_upstream {
                    masq.upstream_url = Some(up);
                }
                config.masquerade = Some(masq);
            }

            if let Some(key) = args.obfs_key {
                config.obfuscation = Some(quicproxy::obfs::ObfuscationConfig {
                    enabled: true,
                    key,
                });
            }

            if args.rate_limit_max.is_some() || args.jitter_min.is_some() || args.jitter_max.is_some() {
                let mut ap = config.anti_probe.unwrap_or_default();
                if let Some(rm) = args.rate_limit_max {
                    ap.rate_limit_max_failures = rm;
                }
                if let Some(jmin) = args.jitter_min {
                    ap.auth_jitter_min_ms = jmin;
                }
                if let Some(jmax) = args.jitter_max {
                    ap.auth_jitter_max_ms = jmax;
                }
                config.anti_probe = Some(ap);
            }

            if let Some(timeout) = args.udp_session_timeout {
                config.udp_session_timeout_secs = timeout;
            }

            if let Some(acl_file) = args.acl_file {
                config.acl = Some(quicproxy::config::AclConfig {
                    file: Some(acl_file),
                    ..Default::default()
                });
            }

            run_server(config).await?;
        }
        Commands::Client(args) => {
            let mut config = if let Some(config_path) = args.config {
                ClientConfig::from_file(config_path)?
            } else {
                let server_addr = args
                    .server_addr
                    .clone()
                    .context("Server address must be provided via --server-addr or config file")?;
                let auth_key = args
                    .auth_key
                    .clone()
                    .context("Auth key must be provided via --auth-key or config file")?;

                let obfuscation = args.obfs_key.map(|key| quicproxy::obfs::ObfuscationConfig {
                    enabled: true,
                    key,
                });

                let tls_fingerprint = if args.tls_profile.is_some() || args.alpn.is_some() {
                    let mut fp = quicproxy::tls_fingerprint::TlsFingerprintConfig::default();
                    if let Some(profile) = args.tls_profile {
                        fp.cipher_profile = profile;
                    }
                    if let Some(alpn_str) = args.alpn {
                        fp.alpn = alpn_str.split(',').map(|s| s.trim().to_string()).collect();
                    }
                    Some(fp)
                } else {
                    None
                };

                let node = quicproxy::config::ServerNodeConfig {
                    name: "default".to_string(),
                    server_addr,
                    server_port: args.server_port.unwrap_or(4433),
                    auth_key,
                    transport: args.transport.unwrap_or_default(),
                    server_name: args.sni,
                    insecure: args.insecure,
                    cert_fingerprint: args.cert_fingerprint,
                    ca_cert: args.ca_cert,
                    weight: 1,
                    priority: 1,
                    obfuscation,
                    tls_fingerprint,
                };

                let socks5_listen = args
                    .socks5_listen
                    .unwrap_or_else(|| "127.0.0.1:1080".parse().unwrap());

                ClientConfig {
                    socks5_listen,
                    servers: vec![node],
                    routing: quicproxy::config::MultiServerRoutingConfig {
                        mode: args.traffic_mode.unwrap_or_default(),
                        strategy: args.strategy.unwrap_or_default(),
                        relay_to_server: args.relay_to_server.clone(),
                        relay_fallback_direct: true,
                    },
                    socks5_user: args.socks5_user,
                    socks5_password: args.socks5_password,
                    acl: None,
                    outbounds: Vec::new(),
                }
            };

            if let Some(listen) = args.socks5_listen {
                config.socks5_listen = listen;
            }
            if let Some(mode) = args.traffic_mode {
                config.routing.mode = mode;
            }
            if let Some(strat) = args.strategy {
                config.routing.strategy = strat;
            }
            if let Some(relay) = args.relay_to_server {
                config.routing.relay_to_server = Some(relay);
            }
            if let Some(acl_file) = args.acl_file {
                config.acl = Some(quicproxy::config::AclConfig {
                    file: Some(acl_file),
                    ..Default::default()
                });
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
