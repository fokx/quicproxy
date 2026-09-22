pub mod quic;
pub mod tcp;

use anyhow::Result;
use quinn::{RecvStream, SendStream};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use self::quic::QuicTransport;
use self::tcp::{TcpTransport, VirtualStream};

/// Unified bidirectional stream abstraction for both QUIC and TCP multiplexed streams.
pub enum ProxyStream {
    Quic {
        send: SendStream,
        recv: RecvStream,
    },
    Tcp(VirtualStream),
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match *self {
            ProxyStream::Quic { ref mut recv, .. } => Pin::new(recv).poll_read(cx, buf),
            ProxyStream::Tcp(ref mut vstream) => Pin::new(vstream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match *self {
            ProxyStream::Quic { ref mut send, .. } => AsyncWrite::poll_write(Pin::new(send), cx, buf),
            ProxyStream::Tcp(ref mut vstream) => AsyncWrite::poll_write(Pin::new(vstream), cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match *self {
            ProxyStream::Quic { ref mut send, .. } => AsyncWrite::poll_flush(Pin::new(send), cx),
            ProxyStream::Tcp(ref mut vstream) => AsyncWrite::poll_flush(Pin::new(vstream), cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match *self {
            ProxyStream::Quic { ref mut send, .. } => AsyncWrite::poll_shutdown(Pin::new(send), cx),
            ProxyStream::Tcp(ref mut vstream) => AsyncWrite::poll_shutdown(Pin::new(vstream), cx),
        }
    }
}

/// Active transport abstraction representing either an established QUIC connection or TCP multiplexer.
#[derive(Clone)]
pub enum ActiveTransport {
    Quic(QuicTransport),
    Tcp(TcpTransport),
}

impl ActiveTransport {
    pub async fn open_stream(&self) -> Result<ProxyStream> {
        match self {
            ActiveTransport::Quic(t) => t.open_stream().await,
            ActiveTransport::Tcp(t) => t.open_stream().await,
        }
    }

    pub fn is_alive(&self) -> bool {
        match self {
            ActiveTransport::Quic(t) => t.is_alive(),
            ActiveTransport::Tcp(t) => t.is_alive(),
        }
    }

    pub async fn close(&self) -> Result<()> {
        match self {
            ActiveTransport::Quic(t) => t.close().await,
            ActiveTransport::Tcp(t) => t.close().await,
        }
    }

    pub fn mode_name(&self) -> &'static str {
        match self {
            ActiveTransport::Quic(_) => "QUIC",
            ActiveTransport::Tcp(_) => "TCP",
        }
    }
}
