pub mod connection;
pub mod relay;

use anyhow::{Context, Result};
use quinn::Endpoint;
use std::sync::Arc;

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
        .with_context(|| format!("Failed to bind QUIC server endpoint on {}", config.listen))?;

    let local_addr = endpoint.local_addr()?;
    println!("================================================================================");
    println!("  QuicProxy Server is listening on UDP {}", local_addr);
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

    while let Some(incoming) = endpoint.accept().await {
        let auth_key_clone = Arc::clone(&auth_key);
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = connection::handle_connection(conn, auth_key_clone).await {
                        tracing::debug!("Connection ended with: {:#}", e);
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
