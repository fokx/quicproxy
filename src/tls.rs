use anyhow::{Context, Result, bail};
use ring::digest::{SHA256, digest};
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub const ALPN_QUIC: &[u8] = b"h3";

/// Generate a self-signed certificate and private key in PEM format.
/// Returns (cert_pem, key_pem, sha256_fingerprint).
pub fn generate_self_signed(domain: &str) -> Result<(String, String, String)> {
    let subject_alt_names = vec![
        domain.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();
    let cert_der = certified_key.cert.der();
    let fingerprint = format_sha256_fingerprint(cert_der);

    Ok((cert_pem, key_pem, fingerprint))
}

/// Compute formatted SHA-256 fingerprint (e.g. "AA:BB:CC...")
pub fn format_sha256_fingerprint(der_bytes: &[u8]) -> String {
    let hash = digest(&SHA256, der_bytes);
    hex::encode(hash.as_ref())
}

/// Normalize fingerprint string (strip colons, whitespace, lowercase)
pub fn normalize_fingerprint(fp: &str) -> String {
    fp.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Parse certificates from PEM string
pub fn parse_certs_pem(pem_str: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::Cursor::new(pem_str.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse certificates PEM")?;
    if certs.is_empty() {
        bail!("No certificates found in PEM data");
    }
    Ok(certs)
}

/// Parse private key from PEM string
pub fn parse_key_pem(pem_str: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::Cursor::new(pem_str.as_bytes());
    loop {
        match rustls_pemfile::read_one(&mut reader).context("Failed to read PEM entry")? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            None => bail!("No private key found in PEM data"),
            _ => continue,
        }
    }
}

/// Load certificates from file
pub fn load_certs_from_file(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read certificate file at {}", path.display()))?;
    parse_certs_pem(&content)
}

/// Load private key from file
pub fn load_key_from_file(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read private key file at {}", path.display()))?;
    parse_key_pem(&content)
}

static CERT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn atomic_write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let rand_id = rand::random::<u64>();
    let tmp_path = path.with_extension(format!("tmp.{}", rand_id));
    fs::write(&tmp_path, content)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Load existing TLS certificate & key or generate self-signed and persist to disk.
/// Returns (certs, key, fingerprint, cert_path_str).
pub fn load_or_generate_server_certs(
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
    auto_cert_dir: Option<&Path>,
    domain: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String, String)> {
    let _guard = CERT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        if cert_path.exists() && key_path.exists() {
            if let (Ok(certs), Ok(key)) = (load_certs_from_file(cert_path), load_key_from_file(key_path)) {
                let is_valid = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs.clone(), key.clone_key())
                    .is_ok();
                if is_valid {
                    let fp = if let Some(first_cert) = certs.first() {
                        format_sha256_fingerprint(first_cert.as_ref())
                    } else {
                        "unknown".to_string()
                    };
                    tracing::info!(
                        "Loaded TLS certificate from {}",
                        cert_path.display()
                    );
                    return Ok((certs, key, fp, cert_path.display().to_string()));
                }
            }
        }

        tracing::info!(
            "Cert/key files not found or invalid at {} and {}; generating self-signed certificate and persisting to disk...",
            cert_path.display(),
            key_path.display()
        );
        let (cert_pem, key_pem, fp) = generate_self_signed(domain)?;
        atomic_write_file(cert_path, &cert_pem)
            .with_context(|| format!("Failed to write certificate to {}", cert_path.display()))?;
        atomic_write_file(key_path, &key_pem)
            .with_context(|| format!("Failed to write private key to {}", key_path.display()))?;
        let certs = parse_certs_pem(&cert_pem)?;
        let key = parse_key_pem(&key_pem)?;
        return Ok((certs, key, fp, cert_path.display().to_string()));
    }

    // Auto-cert mode: persist in auto_cert_dir or ~/.quicproxy/certs/
    let dir = if let Some(d) = auto_cert_dir {
        d.to_path_buf()
    } else if let Some(home) = std::env::var_os("HOME") {
        std::path::PathBuf::from(home).join(".quicproxy").join("certs")
    } else {
        std::path::PathBuf::from(".quicproxy").join("certs")
    };

    let safe_domain: String = domain
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cert_path = dir.join(format!("cert_{}.pem", safe_domain));
    let key_path = dir.join(format!("key_{}.pem", safe_domain));

    if cert_path.exists() && key_path.exists() {
        if let (Ok(certs), Ok(key)) = (load_certs_from_file(&cert_path), load_key_from_file(&key_path)) {
            let is_valid = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs.clone(), key.clone_key())
                .is_ok();
            if is_valid {
                let fp = if let Some(first_cert) = certs.first() {
                    format_sha256_fingerprint(first_cert.as_ref())
                } else {
                    "unknown".to_string()
                };
                tracing::info!(
                    "Loaded persistent self-signed TLS certificate from {}",
                    cert_path.display()
                );
                return Ok((certs, key, fp, cert_path.display().to_string()));
            }
        }
    }

    tracing::info!(
        "Generating self-signed TLS certificate for domain '{}' and persisting to {}",
        domain,
        cert_path.display()
    );
    let (cert_pem, key_pem, fp) = generate_self_signed(domain)?;
    let _ = fs::create_dir_all(&dir);
    if let Err(e) = atomic_write_file(&cert_path, &cert_pem) {
        tracing::warn!("Failed to persist auto-cert to {}: {}", cert_path.display(), e);
    }
    if let Err(e) = atomic_write_file(&key_path, &key_pem) {
        tracing::warn!("Failed to persist auto-key to {}: {}", key_path.display(), e);
    }

    let certs = parse_certs_pem(&cert_pem)?;
    let key = parse_key_pem(&key_pem)?;
    Ok((certs, key, fp, cert_path.display().to_string()))
}

/// Create Quinn ServerConfig with ALPN h3
pub fn make_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Invalid server certificate or private key")?;
    server_crypto.alpn_protocols = vec![ALPN_QUIC.to_vec()];

    let quinn_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .context("Failed to create QUIC server config")?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(256u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Custom verifier that skips certificate validation (Insecure mode)
#[derive(Debug)]
pub struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Custom verifier that pins the server certificate's SHA-256 fingerprint
#[derive(Debug)]
pub struct FingerprintVerifier {
    expected_fingerprint_hex: String,
}

impl FingerprintVerifier {
    pub fn new(expected_fingerprint: &str) -> Self {
        Self {
            expected_fingerprint_hex: normalize_fingerprint(expected_fingerprint),
        }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual_fp = format_sha256_fingerprint(end_entity.as_ref());
        let actual_normalized = normalize_fingerprint(&actual_fp);

        if actual_normalized == self.expected_fingerprint_hex {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {}, got {}",
                self.expected_fingerprint_hex, actual_normalized
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create Quinn ClientConfig with given verification options
pub fn make_client_config(
    insecure: bool,
    cert_fingerprint: Option<&str>,
    ca_cert_path: Option<&Path>,
) -> Result<quinn::ClientConfig> {
    make_client_config_with_fingerprint(insecure, cert_fingerprint, ca_cert_path, None)
}

/// Create Quinn ClientConfig with given verification options and optional fingerprint config
pub fn make_client_config_with_fingerprint(
    insecure: bool,
    cert_fingerprint: Option<&str>,
    ca_cert_path: Option<&Path>,
    tls_fingerprint: Option<&crate::tls_fingerprint::TlsFingerprintConfig>,
) -> Result<quinn::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client_crypto = if let Some(fp) = cert_fingerprint {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerifier::new(fp)))
            .with_no_client_auth()
    } else if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else if let Some(ca_path) = ca_cert_path {
        let certs = load_certs_from_file(ca_path)?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert)?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        // Use system native certificates
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            let _ = root_store.add(cert);
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let mut client_crypto = client_crypto;
    if let Some(fp_cfg) = tls_fingerprint {
        crate::tls_fingerprint::apply_fingerprint_config(&mut client_crypto, fp_cfg);
    } else {
        client_crypto.alpn_protocols = vec![ALPN_QUIC.to_vec()];
    }

    let quinn_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .context("Failed to create QUIC client config")?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(256u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}
