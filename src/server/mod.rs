pub mod connection;
pub mod relay;
pub mod tcp;

use anyhow::{Context, Result};
use quinn::Endpoint;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::config::ServerConfig;
use crate::tls::{
    format_sha256_fingerprint, generate_self_signed, load_certs_from_file, load_key_from_file,
    make_server_config, parse_certs_pem, parse_key_pem,
};

pub async fn run_server(config: ServerConfig) -> Result<()> {
    let (certs, key, fingerprint_info) = if let (Some(cert_path), Some(key_path)) =
        (&config.tls_cert, &config.tls_key)
    {
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

    let server_crypto = make_server_config(certs, key)
        .context("Failed to configure QUIC server TLS")?;

    let endpoint = Endpoint::server(server_crypto, config.listen)
        .with_context(|| format!("Failed to bind QUIC server endpoint on UDP {}", config.listen))?;

    let tcp_listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("Failed to bind TCP fallback listener on TCP {}", config.listen))?;

    let local_addr = endpoint.local_addr()?;
    let tcp_local_addr = tcp_listener.local_addr()?;
    println!("================================================================================");
    println!("  QuicProxy Server is listening:");
    println!("    - Primary QUIC: UDP {}", local_addr);
    println!("    - Fallback TCP: TCP {}", tcp_local_addr);
    println!("  Certificate SHA-256 Fingerprint: {}", fingerprint_info);
    println!();
    println!("  Quick connect command for clients:");
    println!(
        "  quicproxy client --server-addr 127.0.0.1 --server-port {} --auth-key \"{}\" --cert-fingerprint \"{}\"",
        local_addr.port(),
        config.auth_key,
        fingerprint_info
    );
    println!("================================================================================");

    let auth_key = Arc::new(config.auth_key);

    let auth_key_quic = Arc::clone(&auth_key);
    let quic_task = async move {
        while let Some(incoming) = endpoint.accept().await {
            let auth_key_clone = Arc::clone(&auth_key_quic);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = connection::handle_connection(conn, auth_key_clone).await {
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
    let tcp_task = async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, _)) => {
                    let auth_key_clone = Arc::clone(&auth_key_tcp);
                    tokio::spawn(async move {
                        if let Err(e) = tcp::handle_tcp_connection(stream, auth_key_clone).await {
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
