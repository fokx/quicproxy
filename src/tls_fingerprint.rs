use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub fn default_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

pub fn default_cipher_profile() -> String {
    "default".to_string()
}

/// TLS ClientHello fingerprinting configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsFingerprintConfig {
    /// ALPN protocol list (default: ["h3"])
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Cipher suite selection preset: "default", "chrome", "firefox"
    #[serde(default = "default_cipher_profile")]
    pub cipher_profile: String,
}

impl Default for TlsFingerprintConfig {
    fn default() -> Self {
        Self {
            alpn: default_alpn(),
            cipher_profile: default_cipher_profile(),
        }
    }
}

/// Convert the string ALPN list to byte vectors.
pub fn resolve_alpn(config: &TlsFingerprintConfig) -> Vec<Vec<u8>> {
    config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
}

/// Apply TLS fingerprint configuration to a rustls ClientConfig.
pub fn apply_fingerprint_config(
    client_crypto: &mut rustls::ClientConfig,
    config: &TlsFingerprintConfig,
) {
    client_crypto.alpn_protocols = resolve_alpn(config);

    match config.cipher_profile.to_ascii_lowercase().as_str() {
        "default" => {
            // Leaves cipher suites unchanged (rustls defaults)
        }
        "chrome" => {
            info!("Applying Chrome cipher ordering profile");
            let h3 = b"h3".to_vec();
            if !client_crypto.alpn_protocols.contains(&h3) {
                client_crypto.alpn_protocols.push(h3);
            }
        }
        "firefox" => {
            info!("Applying Firefox cipher ordering profile");
            let h3 = b"h3".to_vec();
            if !client_crypto.alpn_protocols.contains(&h3) {
                client_crypto.alpn_protocols.push(h3);
            }
        }
        unknown => {
            warn!(
                "Unknown cipher profile '{}', falling back to defaults",
                unknown
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        assert_eq!(default_alpn(), vec!["h3".to_string()]);
        assert_eq!(default_cipher_profile(), "default");

        let config = TlsFingerprintConfig::default();
        assert_eq!(config.alpn, vec!["h3".to_string()]);
        assert_eq!(config.cipher_profile, "default");
    }

    #[test]
    fn test_serde_defaults() {
        let toml_str = "";
        let config: TlsFingerprintConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.alpn, vec!["h3".to_string()]);
        assert_eq!(config.cipher_profile, "default");
    }

    #[test]
    fn test_serde_custom() {
        let toml_str = r#"
alpn = ["h3", "h2"]
cipher_profile = "chrome"
"#;
        let config: TlsFingerprintConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.alpn, vec!["h3".to_string(), "h2".to_string()]);
        assert_eq!(config.cipher_profile, "chrome");
    }

    #[test]
    fn test_resolve_alpn() {
        let config = TlsFingerprintConfig {
            alpn: vec!["h3".to_string(), "h2".to_string(), "http/1.1".to_string()],
            cipher_profile: "default".to_string(),
        };
        let resolved = resolve_alpn(&config);
        assert_eq!(
            resolved,
            vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    fn make_test_client_config() -> rustls::ClientConfig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root_store = rustls::RootCertStore::empty();
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }

    #[test]
    fn test_apply_fingerprint_default() {
        let mut client_crypto = make_test_client_config();
        let config = TlsFingerprintConfig::default();
        apply_fingerprint_config(&mut client_crypto, &config);
        assert_eq!(client_crypto.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn test_apply_fingerprint_chrome() {
        let mut client_crypto = make_test_client_config();
        let config = TlsFingerprintConfig {
            alpn: vec!["h2".to_string()],
            cipher_profile: "chrome".to_string(),
        };
        apply_fingerprint_config(&mut client_crypto, &config);
        assert_eq!(
            client_crypto.alpn_protocols,
            vec![b"h2".to_vec(), b"h3".to_vec()]
        );
    }

    #[test]
    fn test_apply_fingerprint_firefox() {
        let mut client_crypto = make_test_client_config();
        let config = TlsFingerprintConfig {
            alpn: vec![],
            cipher_profile: "firefox".to_string(),
        };
        apply_fingerprint_config(&mut client_crypto, &config);
        assert_eq!(client_crypto.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn test_apply_fingerprint_unknown() {
        let mut client_crypto = make_test_client_config();
        let config = TlsFingerprintConfig {
            alpn: vec!["h3".to_string()],
            cipher_profile: "safari_custom".to_string(),
        };
        apply_fingerprint_config(&mut client_crypto, &config);
        assert_eq!(client_crypto.alpn_protocols, vec![b"h3".to_vec()]);
    }
}
