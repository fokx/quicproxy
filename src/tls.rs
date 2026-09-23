use anyhow::{bail, Context, Result};
use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub const ALPN_QUIC: &[u8] = b"h3";

/// Generate a self-signed certificate and private key in PEM format.
/// Returns (cert_pem, key_pem, sha256_fingerprint).
pub fn generate_self_signed(domain: &str) -> Result<(String, String, String)> {
    let subject_alt_names = vec![domain.to_string(), "localhost".to_string(), "127.0.0.1".to_string()];
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
    fp.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase()
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
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client_crypto = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else if let Some(fp) = cert_fingerprint {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerifier::new(fp)))
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
    client_crypto.alpn_protocols = vec![ALPN_QUIC.to_vec()];

    let quinn_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .context("Failed to create QUIC client config")?;
    
    let mut client_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(256u32.into());
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}
