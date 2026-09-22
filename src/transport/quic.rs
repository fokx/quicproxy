use anyhow::Result;
use quinn::Connection;

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
}
