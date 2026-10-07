use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use url::Url;

pub const SCHEME_REALM: &str = "realm";
pub const SCHEME_REALM_HTTP: &str = "realm+http";

pub const DEFAULT_HTTPS_PORT: u16 = 443;
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Parsed Hysteria Realms rendezvous address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmAddr {
    pub scheme: String,
    pub rendezvous_scheme: String,
    pub token: String,
    pub host: String,
    pub port: u16,
    pub host_port: String,
    pub realm_id: String,
    pub local_port: Option<u16>,
    pub stun_servers: Vec<String>,
    pub params: HashMap<String, Vec<String>>,
}

impl RealmAddr {
    /// Base URL for the rendezvous server, e.g. "https://example.com:443" or "http://example.com:8080".
    pub fn base_url(&self) -> String {
        format!("{}://{}", self.rendezvous_scheme, self.host_port)
    }
}

/// Checks whether the string starts with `realm:` or `realm+http:`.
pub fn is_realm_addr(s: &str) -> bool {
    s.starts_with("realm://") || s.starts_with("realm+http://")
}

/// Parse a `realm://` or `realm+http://` address.
pub fn parse_realm_addr(s: &str) -> Result<RealmAddr> {
    if !is_realm_addr(s) {
        bail!("invalid realm address scheme");
    }

    // Workaround for `url::Url` which expects standard hierarchical URL schemes
    let (rendezvous_scheme, default_port, raw_url_for_parse) =
        if let Some(rest) = s.strip_prefix("realm+http://") {
            ("http", DEFAULT_HTTP_PORT, format!("http://{}", rest))
        } else if let Some(rest) = s.strip_prefix("realm://") {
            ("https", DEFAULT_HTTPS_PORT, format!("https://{}", rest))
        } else {
            bail!("invalid realm address scheme");
        };

    let original_scheme = if s.starts_with("realm+http://") {
        SCHEME_REALM_HTTP
    } else {
        SCHEME_REALM
    };

    let u =
        Url::parse(&raw_url_for_parse).with_context(|| format!("invalid realm address: {}", s))?;

    if u.fragment().is_some() {
        bail!("fragment is not supported in realm address");
    }

    let host = match u.host_str() {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => bail!("rendezvous host is required"),
    };

    let token = u.username();
    if token.is_empty() {
        bail!("realm token is required");
    }
    let token = percent_encoding::percent_decode_str(token)
        .decode_utf8()
        .with_context(|| "invalid token encoding")?
        .to_string();

    let port = u.port().unwrap_or(default_port);
    let host_port = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };

    // Realm ID is a single path segment
    let path = u.path().trim_start_matches('/');
    if path.is_empty() {
        bail!("realm id is required");
    }
    if path.contains('/') {
        bail!("realm id must be a single path segment");
    }
    let realm_id = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .with_context(|| "invalid realm id encoding")?
        .to_string();
    if realm_id.is_empty() || realm_id.contains('/') {
        bail!("realm id must be a single path segment");
    }

    // Query parameters
    let mut params: HashMap<String, Vec<String>> = HashMap::new();
    for (k, v) in u.query_pairs() {
        params.entry(k.to_string()).or_default().push(v.to_string());
    }

    let local_port = if let Some(lport_values) = params.get("lport") {
        if lport_values.len() > 1 {
            bail!("lport must be specified at most once");
        }
        let p: u16 = lport_values[0]
            .parse()
            .with_context(|| "lport must be an integer in 1-65535")?;
        if p == 0 {
            bail!("lport must be an integer in 1-65535");
        }
        Some(p)
    } else {
        None
    };

    let stun_servers = params.get("stun").cloned().unwrap_or_default();

    Ok(RealmAddr {
        scheme: original_scheme.to_string(),
        rendezvous_scheme: rendezvous_scheme.to_string(),
        token,
        host,
        port,
        host_port,
        realm_id,
        local_port,
        stun_servers,
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_realm_addr_valid() {
        let addr =
            parse_realm_addr("realm://secret-token@rendezvous.example.com/my-realm").unwrap();
        assert_eq!(addr.scheme, "realm");
        assert_eq!(addr.rendezvous_scheme, "https");
        assert_eq!(addr.token, "secret-token");
        assert_eq!(addr.host, "rendezvous.example.com");
        assert_eq!(addr.port, 443);
        assert_eq!(addr.host_port, "rendezvous.example.com:443");
        assert_eq!(addr.realm_id, "my-realm");
        assert_eq!(addr.local_port, None);
        assert!(addr.stun_servers.is_empty());
        assert_eq!(addr.base_url(), "https://rendezvous.example.com:443");
    }

    #[test]
    fn test_parse_realm_http_with_port_and_params() {
        let addr = parse_realm_addr(
            "realm+http://tok%40en@127.0.0.1:8080/test-realm?lport=54321&stun=stun1.example.com:3478&stun=stun2.example.com:3478"
        ).unwrap();
        assert_eq!(addr.scheme, "realm+http");
        assert_eq!(addr.rendezvous_scheme, "http");
        assert_eq!(addr.token, "tok@en");
        assert_eq!(addr.host, "127.0.0.1");
        assert_eq!(addr.port, 8080);
        assert_eq!(addr.realm_id, "test-realm");
        assert_eq!(addr.local_port, Some(54321));
        assert_eq!(
            addr.stun_servers,
            vec!["stun1.example.com:3478", "stun2.example.com:3478"]
        );
        assert_eq!(addr.base_url(), "http://127.0.0.1:8080");
    }

    #[test]
    fn test_parse_realm_addr_ipv6() {
        let addr = parse_realm_addr("realm://mytoken@[2001:db8::1]:9443/ipv6realm").unwrap();
        assert_eq!(addr.host, "[2001:db8::1]");
        assert_eq!(addr.port, 9443);
        assert_eq!(addr.realm_id, "ipv6realm");
    }

    #[test]
    fn test_parse_realm_addr_errors() {
        assert!(parse_realm_addr("http://token@example.com/realm").is_err());
        assert!(parse_realm_addr("realm://example.com/realm").is_err()); // missing token
        assert!(parse_realm_addr("realm://token@example.com").is_err()); // missing realm id
        assert!(parse_realm_addr("realm://token@example.com/").is_err()); // missing realm id
        assert!(parse_realm_addr("realm://token@example.com/sub/realm").is_err()); // multiple segments
        assert!(parse_realm_addr("realm://token@example.com/realm#frag").is_err()); // fragment
        assert!(parse_realm_addr("realm://token@example.com/realm?lport=0").is_err()); // invalid port
        assert!(parse_realm_addr("realm://token@example.com/realm?lport=99999").is_err()); // overflow
        assert!(parse_realm_addr("realm://token@example.com/realm?lport=10&lport=20").is_err()); // duplicate lport
    }
}
