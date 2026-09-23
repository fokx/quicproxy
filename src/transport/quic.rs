use anyhow::Result;
use bytes::Bytes;
use quinn::Connection;
use std::time::Duration;

use super::ProxyStream;

#[derive(Clone)]
pub struct QuicTransport {
    conn: Connection,
}

impl QuicTransport {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub async fn open_stream(&self) -> Result<ProxyStream> {
        let (send, recv) = self.conn.open_bi().await?;
        Ok(ProxyStream::Quic { send, recv })
    }

    pub fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    pub async fn close(&self) -> Result<()> {
        self.conn.close(0u32.into(), b"Closed");
        Ok(())
    }

    /// Send an unreliable datagram over QUIC (RFC 9221).
    pub fn send_datagram(&self, data: &[u8]) -> Result<()> {
        self.conn.send_datagram(Bytes::copy_from_slice(data))?;
        Ok(())
    }

    /// Receive an unreliable datagram from QUIC (RFC 9221).
    pub async fn recv_datagram(&self) -> Result<Vec<u8>> {
        let dgram = self.conn.read_datagram().await?;
        Ok(dgram.to_vec())
    }

    /// Get current round-trip time estimate.
    pub fn rtt(&self) -> Duration {
        self.conn.rtt()
    }

    /// Get connection statistics.
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.conn.stats()
    }
}
