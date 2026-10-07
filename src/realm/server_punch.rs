use anyhow::{Result, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout};

use super::punch::{
    PunchConfig, PunchMetadata, PunchPacketType, PunchResult, candidate_punch_addrs,
    encode_punch_packet,
};
use super::punch_socket::{PunchPacketEvent, PunchUdpSocket};

#[derive(Debug, Clone)]
pub struct ServerPuncher {
    socket: Arc<PunchUdpSocket>,
}

impl ServerPuncher {
    pub fn new(socket: Arc<PunchUdpSocket>) -> Self {
        Self { socket }
    }

    /// Responds to a punch attempt initiated by a client.
    /// Sends Hello packets to peer candidates, ACKs inbound Hellos, and returns
    /// as soon as a valid punch packet arrives.
    pub async fn respond(
        &self,
        attempt_id: &str,
        local_addrs: &[SocketAddr],
        peer_addrs: &[SocketAddr],
        meta: &PunchMetadata,
        config: &PunchConfig,
    ) -> Result<PunchResult> {
        let candidates = candidate_punch_addrs(local_addrs, peer_addrs, config.family);
        if candidates.is_empty() {
            bail!("no compatible peer addresses for punch");
        }

        let (tx, mut rx) = mpsc::channel::<PunchPacketEvent>(16);
        self.socket
            .state()
            .add_attempt(attempt_id, meta.clone(), tx);

        struct Cleanup<'a> {
            socket: &'a PunchUdpSocket,
            attempt_id: &'a str,
        }
        impl<'a> Drop for Cleanup<'a> {
            fn drop(&mut self) {
                self.socket.state().remove_attempt(self.attempt_id);
            }
        }
        let _cleanup = Cleanup {
            socket: &self.socket,
            attempt_id,
        };

        let hello_packet = encode_punch_packet(PunchPacketType::Hello, meta)?;
        let ack_packet = encode_punch_packet(PunchPacketType::Ack, meta)?;

        let run_punch = async {
            let mut ticker = interval(config.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        for &candidate in &candidates {
                            let _ = self.socket.send_to(&hello_packet, candidate).await;
                        }
                    }
                    Some(ev) = rx.recv() => {
                        if ev.packet.packet_type == PunchPacketType::Hello {
                            let _ = self.socket.send_to(&ack_packet, ev.from).await;
                        }
                        return Ok(PunchResult {
                            peer_addr: ev.from,
                            packet: ev.packet,
                        });
                    }
                }
            }
        };

        match timeout(config.timeout, run_punch).await {
            Ok(res) => res,
            Err(_) => bail!("punch timed out"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::punch_socket::PunchSocketState;
    use std::time::Duration;

    #[tokio::test]
    async fn test_server_puncher_responds_to_hello() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = std_sock.local_addr().unwrap();

        let state = Arc::new(PunchSocketState::new(16));
        let punch_sock = Arc::new(PunchUdpSocket::new(std_sock, Arc::clone(&state), None).unwrap());
        let puncher = ServerPuncher::new(Arc::clone(&punch_sock));

        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let meta = PunchMetadata::new_random();
        let cfg = PunchConfig {
            timeout: Duration::from_millis(500),
            interval: Duration::from_millis(20),
            family: super::super::punch::AddrFamily::IPv4,
        };

        let meta_clone = meta.clone();
        let puncher_handle = tokio::spawn(async move {
            puncher
                .respond(
                    "attempt-1",
                    &[server_addr],
                    &[client_addr],
                    &meta_clone,
                    &cfg,
                )
                .await
        });

        // Client sends Hello to server
        let _hello = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
        // Give server puncher a moment to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Simulate reading packet on server socket to route into PunchSocketState
        state.emit_punch(PunchPacketEvent {
            attempt_id: "attempt-1".to_string(),
            from: client_addr,
            packet: crate::realm::punch::PunchPacket {
                packet_type: PunchPacketType::Hello,
                padding_length: 0,
            },
        });

        let res = puncher_handle.await.unwrap().unwrap();
        assert_eq!(res.peer_addr, client_addr);
        assert_eq!(res.packet.packet_type, PunchPacketType::Hello);
    }
}
