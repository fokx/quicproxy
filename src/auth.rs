use anyhow::{anyhow, Result};
use ring::hmac::{Key, HMAC_SHA256, sign, verify};

pub const TLS_EXPORTER_LABEL: &[u8] = b"quicproxy-auth-v1";

/// Derive a session-bound 32-byte authentication token for this QUIC connection.
///
/// Because the TLS Keying Material Exporter produces output cryptographically bound to
/// this specific TLS 1.3 session (via the master secret), the resulting token is
/// unique per connection, preventing any replay attacks.
pub fn generate_auth_token(conn: &quinn::Connection, auth_key: &str) -> Result<[u8; 32]> {
    let mut exporter_secret = [0u8; 32];
    conn.export_keying_material(&mut exporter_secret, TLS_EXPORTER_LABEL, b"")
        .map_err(|_| anyhow!("Failed to export TLS keying material from QUIC connection"))?;

    let s_key = Key::new(HMAC_SHA256, auth_key.as_bytes());
    let tag = sign(&s_key, &exporter_secret);
    
    let mut token = [0u8; 32];
    token.copy_from_slice(tag.as_ref());
    Ok(token)
}

/// Verify a received authentication token using constant-time comparison to prevent timing attacks.
pub fn verify_auth_token(
    conn: &quinn::Connection,
    auth_key: &str,
    received_token: &[u8; 32],
) -> Result<bool> {
    let mut exporter_secret = [0u8; 32];
    conn.export_keying_material(&mut exporter_secret, TLS_EXPORTER_LABEL, b"")
        .map_err(|_| anyhow!("Failed to export TLS keying material from QUIC connection"))?;

    let s_key = Key::new(HMAC_SHA256, auth_key.as_bytes());
    let is_valid = verify(&s_key, &exporter_secret, received_token).is_ok();
    Ok(is_valid)
}
