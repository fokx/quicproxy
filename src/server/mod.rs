pub mod antiprobe;
pub mod connection;
pub mod masquerade;
pub mod relay;
pub mod tcp;
pub mod udp_session;

use anyhow::{Context, Result, bail};
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::config::ServerConfig;
use crate::tls::{
    format_sha256_fingerprint, generate_self_signed, load_certs_from_file, load_key_from_file,
    make_server_config, parse_certs_pem, parse_key_pem,
};

pub async fn run_server(config: ServerConfig) -> Result<()> {
    if config.is_realm() {
        run_realm_server(config).await
    } else {
        run_standard_server(config).await
    }
}

async fn run_realm_server(config: ServerConfig) -> Result<()> {
    let realm_uri = config.realm_listen.as_ref().unwrap();
    let realm_addr = crate::realm::parse_realm_addr(realm_uri)?;
    let realm_cfg = config.realm.clone().unwrap_or_default();

    let obfs_enabled = config.obfuscation.as_ref().map_or(false, |o| o.enabled);
    let masq_config = config.masquerade.unwrap_or_default();
    let masq_enabled = masq_config.is_enabled();

    if obfs_enabled && masq_enabled {
        bail!(
            "Packet obfuscation and HTTP/3 masquerade are mutually exclusive. Obfuscation scrambles QUIC packets, making them undetectable as HTTP/3."
        );
    }

    let (certs, key, fingerprint_info) =
        if let (Some(cert_path), Some(key_path)) = (&config.tls_cert, &config.tls_key) {
            tracing::info!(
                "Loading TLS certificates from {} and key from {}",
                cert_path.display(),
                key_path.display()
            );
            let certs = load_certs_from_file(cert_path)?;
            let key = load_key_from_file(key_path)?;
            let fp = if let Some(first_cert) = certs.first() {
                format_sha256_fingerprint(first_cert.as_ref())
            } else {
                "unknown".to_string()
            };
            (certs, key, fp)
        } else {
            tracing::info!(
                "Auto-generating self-signed TLS certificate for domain '{}'",
                config.auto_cert_domain
            );
            let (cert_pem, key_pem, fp) = generate_self_signed(&config.auto_cert_domain)
                .context("Failed to generate auto self-signed certificate")?;
            let certs = parse_certs_pem(&cert_pem)?;
            let key = parse_key_pem(&key_pem)?;
            (certs, key, fp)
        };

    let server_crypto =
        make_server_config(certs, key).context("Failed to configure QUIC server TLS")?;

    let family = realm_cfg.ip_mode_family();
    let bind_port = realm_addr.local_port.unwrap_or(0);
    let bind_addr = match family {
        crate::realm::AddrFamily::IPv6 => SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            bind_port,
        ),
        _ => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bind_port,
        ),
    };

    let std_socket = std::net::UdpSocket::bind(bind_addr)
        .with_context(|| format!("Failed to bind UDP socket on {}", bind_addr))?;

    let local_udp_port = std_socket.local_addr()?.port();

    let port_mapper = if realm_cfg.port_mapping.as_ref().is_some_and(|p| p.enabled) {
        let pm_cfg = realm_cfg.port_mapping.as_ref().unwrap();
        match crate::realm::PortMapper::new(
            local_udp_port,
            pm_cfg.timeout_duration(),
            pm_cfg.lifetime_duration(),
        )
        .await
        {
            Ok(m) => {
                tracing::info!(
                    "UPnP port mapping established for UDP port {}",
                    local_udp_port
                );
                Some(Arc::new(m))
            }
            Err(e) => {
                tracing::warn!("realm port mapping failed; continuing without it: {}", e);
                None
            }
        }
    } else {
        None
    };

    let punch_state = Arc::new(crate::realm::PunchSocketState::new(32));
    let obfs_key = if obfs_enabled {
        Some(config.obfuscation.as_ref().unwrap().key.as_str())
    } else {
        None
    };

    let punch_sock = Arc::new(crate::realm::PunchUdpSocket::new(
        std_socket,
        Arc::clone(&punch_state),
        obfs_key,
    )?);

    let runtime = quinn::default_runtime().context("No default Quinn runtime")?;
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_crypto),
        Arc::clone(&punch_sock) as Arc<dyn quinn::AsyncUdpSocket>,
        runtime,
    )
    .context("Failed to create QUIC endpoint on Realm punch socket")?;

    let puncher = Arc::new(crate::realm::ServerPuncher::new(Arc::clone(&punch_sock)));

    let _realm_runtime = crate::realm::RealmServerRuntime::start(
        realm_addr.clone(),
        Arc::clone(&punch_sock),
        puncher,
        realm_cfg,
        port_mapper,
    )
    .await?;

    println!("================================================================================");
    println!("  QuicProxy Realm Server is active (P2P Hole-Punching Mode):");
    println!("    - Realm ID:         {}", realm_addr.realm_id);
    println!("    - Rendezvous Host:  {}", realm_addr.host_port);
    println!("    - Local UDP Port:   {}", local_udp_port);
    println!("  Certificate SHA-256 Fingerprint: {}", fingerprint_info);
    if masq_enabled {
        println!("  HTTP/3 Camouflage Masquerade Mode: {}", masq_config.mode);
    }
    if obfs_enabled {
        println!("  Salamander Packet Obfuscation: ENABLED");
    }
    println!();
    println!("  Connect command for clients:");
    println!(
        "  quicproxy client --server-addr \"{}\" --auth-key \"{}\" --cert-fingerprint \"{}\"",
        realm_uri, config.auth_key, fingerprint_info
    );
    println!("================================================================================");

    let metrics = Arc::new(crate::metrics::Metrics::new());
    Arc::clone(&metrics).start_periodic_logging();

    let auth_key = Arc::new(config.auth_key);
    let masquerade = Arc::new(masquerade::MasqueradeHandler::new(masq_config));

    let anti_probe_config = config.anti_probe.unwrap_or_default();
    let rate_limiter = Arc::new(antiprobe::RateLimiter::new(
        anti_probe_config.rate_limit_max_failures,
        anti_probe_config.rate_limit_window_secs,
    ));
    let anti_probe = Arc::new(anti_probe_config);
    let udp_timeout = config.udp_session_timeout_secs;

    let geo_loader: Arc<dyn crate::acl::GeoLoader> = if let Some(ref acl_cfg) = config.acl {
        Arc::new(crate::acl::DefaultGeoLoader::new(
            acl_cfg.geoip.clone(),
            acl_cfg.geosite.clone(),
            acl_cfg.parse_geo_update_interval(),
        ))
    } else {
        Arc::new(crate::acl::DefaultGeoLoader::new(None, None, None))
    };

    let rules_str = if let Some(ref acl_cfg) = config.acl {
        acl_cfg.load_rules_string()?
    } else {
        String::new()
    };

    let acl_engine = Arc::new(
        crate::acl::ACLEngine::new_from_string(&rules_str, &config.outbounds, geo_loader.as_ref())
            .await?,
    );

    while let Some(incoming) = endpoint.accept().await {
        let auth_key_clone = Arc::clone(&auth_key);
        let masq_clone = Arc::clone(&masquerade);
        let rate_limiter_clone = Arc::clone(&rate_limiter);
        let anti_probe_clone = Arc::clone(&anti_probe);
        let acl_clone = Arc::clone(&acl_engine);

        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = connection::handle_connection(
                        conn,
                        auth_key_clone,
                        masq_clone,
                        rate_limiter_clone,
                        anti_probe_clone,
                        udp_timeout,
                        acl_clone,
                    )
                    .await
                    {
                        tracing::debug!("QUIC connection ended with: {:#}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to establish incoming QUIC connection: {}", e);
                }
            }
        });
    }

    Ok(())
}

async fn run_standard_server(config: ServerConfig) -> Result<()> {
    let obfs_enabled = config.obfuscation.as_ref().map_or(false, |o| o.enabled);
    let masq_config = config.masquerade.unwrap_or_default();
    let masq_enabled = masq_config.is_enabled();

    if obfs_enabled && masq_enabled {
        bail!(
            "Packet obfuscation and HTTP/3 masquerade are mutually exclusive. Obfuscation scrambles QUIC packets, making them undetectable as HTTP/3."
        );
    }

    let (certs, key, fingerprint_info) =
        if let (Some(cert_path), Some(key_path)) = (&config.tls_cert, &config.tls_key) {
            tracing::info!(
                "Loading TLS certificates from {} and key from {}",
                cert_path.display(),
                key_path.display()
            );
            let certs = load_certs_from_file(cert_path)?;
            let key = load_key_from_file(key_path)?;
            let fp = if let Some(first_cert) = certs.first() {
                format_sha256_fingerprint(first_cert.as_ref())
            } else {
                "unknown".to_string()
            };
            (certs, key, fp)
        } else {
            tracing::info!(
                "Auto-generating self-signed TLS certificate for domain '{}'",
                config.auto_cert_domain
            );
            let (cert_pem, key_pem, fp) = generate_self_signed(&config.auto_cert_domain)
                .context("Failed to generate auto self-signed certificate")?;
            let certs = parse_certs_pem(&cert_pem)?;
            let key = parse_key_pem(&key_pem)?;
            (certs, key, fp)
        };

    let server_crypto =
        make_server_config(certs, key).context("Failed to configure QUIC server TLS")?;

    let endpoint = if obfs_enabled {
        let obfs_cfg = config.obfuscation.as_ref().unwrap();
        tracing::info!("Initializing QUIC server with Salamander packet obfuscation");
        let obfs_sock =
            crate::obfs::salamander::ObfuscatedUdpSocket::bind(config.listen, &obfs_cfg.key)
                .with_context(|| {
                    format!("Failed to bind obfuscated UDP socket on {}", config.listen)
                })?;
        let runtime = quinn::default_runtime().context("No default Quinn runtime")?;
        Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_crypto),
            Arc::new(obfs_sock),
            runtime,
        )
        .with_context(|| {
            format!(
                "Failed to create QUIC endpoint with obfuscated socket on {}",
                config.listen
            )
        })?
    } else {
        Endpoint::server(server_crypto, config.listen).with_context(|| {
            format!(
                "Failed to bind QUIC server endpoint on UDP {}",
                config.listen
            )
        })?
    };

    let tcp_listener = TcpListener::bind(config.listen).await.with_context(|| {
        format!(
            "Failed to bind TCP fallback listener on TCP {}",
            config.listen
        )
    })?;

    let local_addr = endpoint.local_addr()?;
    let tcp_local_addr = tcp_listener.local_addr()?;
    println!("================================================================================");
    println!("  QuicProxy Server is listening:");
    println!("    - Primary QUIC: UDP {}", local_addr);
    println!("    - Fallback TCP: TCP {}", tcp_local_addr);
    println!("  Certificate SHA-256 Fingerprint: {}", fingerprint_info);
    if masq_enabled {
        println!("  HTTP/3 Camouflage Masquerade Mode: {}", masq_config.mode);
    }
    if obfs_enabled {
        println!("  Salamander Packet Obfuscation: ENABLED");
    }
    println!();
    println!("  Quick connect command for clients:");
    println!(
        "  quicproxy client --server-addr 127.0.0.1 --server-port {} --auth-key \"{}\" --cert-fingerprint \"{}\"",
        local_addr.port(),
        config.auth_key,
        fingerprint_info
    );
    println!("================================================================================");

    let metrics = Arc::new(crate::metrics::Metrics::new());
    Arc::clone(&metrics).start_periodic_logging();

    let auth_key = Arc::new(config.auth_key);
    let masquerade = Arc::new(masquerade::MasqueradeHandler::new(masq_config));

    let anti_probe_config = config.anti_probe.unwrap_or_default();
    let rate_limiter = Arc::new(antiprobe::RateLimiter::new(
        anti_probe_config.rate_limit_max_failures,
        anti_probe_config.rate_limit_window_secs,
    ));
    let anti_probe = Arc::new(anti_probe_config);
    let udp_timeout = config.udp_session_timeout_secs;

    let geo_loader: Arc<dyn crate::acl::GeoLoader> = if let Some(ref acl_cfg) = config.acl {
        Arc::new(crate::acl::DefaultGeoLoader::new(
            acl_cfg.geoip.clone(),
            acl_cfg.geosite.clone(),
            acl_cfg.parse_geo_update_interval(),
        ))
    } else {
        Arc::new(crate::acl::DefaultGeoLoader::new(None, None, None))
    };

    let rules_str = if let Some(ref acl_cfg) = config.acl {
        acl_cfg.load_rules_string()?
    } else {
        String::new()
    };

    let acl_engine = Arc::new(
        crate::acl::ACLEngine::new_from_string(&rules_str, &config.outbounds, geo_loader.as_ref())
            .await?,
    );

    let auth_key_quic = Arc::clone(&auth_key);
    let masquerade_quic = Arc::clone(&masquerade);
    let rate_limiter_quic = Arc::clone(&rate_limiter);
    let anti_probe_quic = Arc::clone(&anti_probe);
    let acl_engine_quic = Arc::clone(&acl_engine);

    let quic_task = async move {
        while let Some(incoming) = endpoint.accept().await {
            let auth_key_clone = Arc::clone(&auth_key_quic);
            let masq_clone = Arc::clone(&masquerade_quic);
            let rate_limiter_clone = Arc::clone(&rate_limiter_quic);
            let anti_probe_clone = Arc::clone(&anti_probe_quic);
            let acl_clone = Arc::clone(&acl_engine_quic);

            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = connection::handle_connection(
                            conn,
                            auth_key_clone,
                            masq_clone,
                            rate_limiter_clone,
                            anti_probe_clone,
                            udp_timeout,
                            acl_clone,
                        )
                        .await
                        {
                            tracing::debug!("QUIC connection ended with: {:#}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to establish incoming QUIC connection: {}", e);
                    }
                }
            });
        }
    };

    let auth_key_tcp = Arc::clone(&auth_key);
    let rate_limiter_tcp = Arc::clone(&rate_limiter);
    let anti_probe_tcp = Arc::clone(&anti_probe);
    let udp_timeout_tcp = config.udp_session_timeout_secs;
    let acl_engine_tcp = Arc::clone(&acl_engine);

    let tcp_task = async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, _)) => {
                    let auth_key_clone = Arc::clone(&auth_key_tcp);
                    let rate_limiter_clone = Arc::clone(&rate_limiter_tcp);
                    let anti_probe_clone = Arc::clone(&anti_probe_tcp);
                    let acl_clone = Arc::clone(&acl_engine_tcp);

                    tokio::spawn(async move {
                        if let Err(e) = tcp::handle_tcp_connection(
                            stream,
                            auth_key_clone,
                            rate_limiter_clone,
                            anti_probe_clone,
                            udp_timeout_tcp,
                            acl_clone,
                        )
                        .await
                        {
                            tracing::debug!("TCP fallback connection ended with: {:#}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to accept incoming TCP fallback connection: {}", e);
                }
            }
        }
    };

    tokio::select! {
        _ = quic_task => {},
        _ = tcp_task => {},
    }

    Ok(())
}
