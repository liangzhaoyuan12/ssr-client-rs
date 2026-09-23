//! SOCKS5 UDP ASSOCIATE relay — Rust port of `ssr-n/src/udp_ssr_client.c`.
//!
//! Wire behavior mirrors C exactly:
//! * request: `[RSV(2)|FRAG(1)|ATYP|ADDR|PORT|DATA]` → strip 3 bytes →
//!   `client_udp_pre_encrypt` → `ss_encrypt_all` → server (per-session socket);
//! * response: `ss_decrypt_all` → `client_udp_post_decrypt` → strip the SS
//!   address header → datagram whose address header is the **app's own
//!   address** (`udp_ssr_client.c:240` builds `s5addr` from `incoming_addr`)
//!   → app;
//! * drops: `FRAG != 0`, port 5353 (mDNS), datagram > 65507 bytes
//!   (`MAX_UDP_PACKET_SIZE`, udp_ssr_client.c:54).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::config::SsrClientConfig;
use crate::crypto::aead::AeadCipher;
use crate::crypto::cipher_env::CipherEnv;
use crate::error::{SsrError, SsrResult};
use crate::protocol::Protocol;
use crate::socks5::{build_udp_datagram, parse_udp_datagram, TargetAddress};

/// C: `MAX_UDP_PACKET_SIZE` (udp_ssr_client.c:54).
const MAX_UDP_PACKET_SIZE: usize = 65507;
/// C: `MAX_UDP_CONN_NUM` (udp_ssr_client.c:52).
const MAX_UDP_CONN_NUM: usize = 512;

type SessionKey = (SocketAddr, Vec<u8>);

struct Session {
    sock: Arc<UdpSocket>,
    last_seen: Arc<AtomicU64>, // ms since UNIX epoch
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn s5_addr_of(sa: SocketAddr) -> (TargetAddress, u16) {
    match sa {
        SocketAddr::V4(a) => (TargetAddress::IPv4(a.ip().octets()), a.port()),
        SocketAddr::V6(a) => (TargetAddress::IPv6(a.ip().octets()), a.port()),
    }
}

/// Parse a bare SS payload `[ATYP|ADDR|PORT|DATA]` (no RSV/FRAG) by reusing
/// the SOCKS5 datagram parser on a prefix-padded copy.
fn parse_ss_payload(payload: &[u8]) -> SsrResult<crate::socks5::UdpDatagram> {
    let mut tmp = Vec::with_capacity(payload.len() + 3);
    tmp.extend_from_slice(&[0, 0, 0]);
    tmp.extend_from_slice(payload);
    parse_udp_datagram(&tmp)
}

/// App-facing UDP relay: receives SOCKS5 UDP ASSOCIATE datagrams on the listen
/// port, encrypts payloads per SSR session and forwards them to the server
/// (Rust port of `ssr-n/src/udp_ssr_client.c`; see the module docs).
pub struct UdpRelay {
    listener: Arc<UdpSocket>,
    server: SocketAddr,
    env: Arc<CipherEnv>,
    protocol: Arc<Mutex<Box<dyn Protocol>>>,
    sessions: Arc<Mutex<HashMap<SessionKey, Session>>>,
    timeout_ms: u64,
}

impl UdpRelay {
    /// Bind the app-facing UDP socket (same port number as the TCP listener —
    /// C replies to UDP ASSOCIATE with `uv_tcp_getsockname`, client.c:653) and
    /// resolve the SSR server address once (C resolves at listener startup).
    pub async fn bind(config: SsrClientConfig) -> SsrResult<Self> {
        let listen = crate::utils::sockaddr::host_port(&config.listen_address, config.listen_port);
        let listener = UdpSocket::bind(&listen).await.map_err(|e| {
            SsrError::Connection(format!("Failed to bind UDP relay on {listen}: {e}"))
        })?;

        let server = tokio::net::lookup_host((config.server.as_str(), config.server_port))
            .await
            .map_err(|e| SsrError::Connection(format!("resolve {}: {e}", config.server)))?
            .next()
            .ok_or_else(|| SsrError::Connection(format!("no address for {}", config.server)))?;

        let env = CipherEnv::with_method(&config.password, config.method)?;
        let method = config.method;
        let is_aead = AeadCipher::is_aead(method);
        let protocol = super::create_protocol(&config, &env, is_aead)?;

        Ok(Self {
            timeout_ms: (config.udp_timeout.max(1) as u64) * 1000,
            listener: Arc::new(listener),
            server,
            env: Arc::new(env),
            protocol: Arc::new(Mutex::new(protocol)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Run the relay until `shutdown` flips to `true` (a `watch` receiver:
    /// value semantics — a stop() that already happened is still seen).
    pub fn spawn(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        tokio::spawn(async move {
            if let Err(e) = self.run(&mut shutdown).await {
                log::error!("[udp] relay stopped: {e}");
            }
            log::debug!("[udp] relay exited");
        });
    }

    async fn run(self, shutdown: &mut tokio::sync::watch::Receiver<bool>) -> SsrResult<()> {
        let mut buf = vec![0u8; 65535];
        loop {
            if *shutdown.borrow_and_update() {
                log::debug!("[udp] shutdown requested");
                break;
            }
            tokio::select! {
                r = self.listener.recv_from(&mut buf) => {
                    let (n, from) = r.map_err(|e| SsrError::Connection(format!("udp recv: {e}")))?;
                    self.handle_request(&buf[..n], from).await;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() {
                        break; // SsrClient dropped
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_request(&self, data: &[u8], from: SocketAddr) {
        // C listener recv: nread > packet_size → drop (udp_ssr_client.c:370).
        if data.len() > MAX_UDP_PACKET_SIZE {
            ssr_debug!("[udp] request too large ({}), dropped", data.len());
            return;
        }
        // Parse `[RSV|FRAG|ATYP|ADDR|PORT|DATA]`; malformed → drop.
        let dg = match parse_udp_datagram(data) {
            Ok(d) => d,
            Err(e) => {
                ssr_debug!("[udp] bad request from {from}: {e}");
                return;
            }
        };
        if dg.frag != 0 {
            ssr_debug!("[udp] drop fragmented datagram (frag={})", dg.frag);
            return;
        }
        if dg.port == 5353 {
            ssr_debug!("[udp] drop mDNS datagram (port 5353)");
            return;
        }

        // SS request = the datagram without RSV/FRAG (C: buffer_shortened_to(3)).
        let ss_payload = &data[3..];
        let framed = {
            let mut proto = self
                .protocol
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match proto.udp_pre_encrypt(ss_payload) {
                Ok(f) => f,
                Err(e) => {
                    ssr_debug!("[udp] pre_encrypt failed: {e}");
                    return;
                }
            }
        };
        let enc = match self.env.encrypt_udp(&framed) {
            Ok(e) => e,
            Err(e) => {
                ssr_debug!("[udp] encrypt failed: {e}");
                return;
            }
        };
        if enc.len() > MAX_UDP_PACKET_SIZE {
            ssr_debug!(
                "[udp] encrypted datagram too large ({}), dropped",
                enc.len()
            );
            return;
        }

        let key: SessionKey = (from, data[3..dg.header_len].to_vec());
        let sock = match self.get_or_create_session(&key, from).await {
            Some(s) => s,
            None => return,
        };
        if let Err(e) = sock.send_to(&enc, self.server).await {
            ssr_debug!("[udp] send to server failed: {e}");
            // Stale session — drop it so the next datagram recreates one.
            self.sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
        }
    }

    async fn get_or_create_session(
        &self,
        key: &SessionKey,
        app: SocketAddr,
    ) -> Option<Arc<UdpSocket>> {
        if let Some(s) = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
        {
            s.last_seen.store(now_ms(), Ordering::Relaxed);
            return Some(s.sock.clone());
        }
        if self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
            >= MAX_UDP_CONN_NUM
        {
            ssr_debug!("[udp] too many sessions, dropping");
            return None;
        }
        let bind_addr = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = match UdpSocket::bind(bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                ssr_debug!("[udp] session bind failed: {e}");
                return None;
            }
        };
        let last_seen = Arc::new(AtomicU64::new(now_ms()));
        {
            let mut map = self
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(s) = map.get(key) {
                // Created concurrently — reuse the winner.
                return Some(s.sock.clone());
            }
            map.insert(
                key.clone(),
                Session {
                    sock: sock.clone(),
                    last_seen: last_seen.clone(),
                },
            );
        }
        spawn_session_task(
            key.clone(),
            app,
            sock.clone(),
            self.listener.clone(),
            self.env.clone(),
            self.protocol.clone(),
            self.sessions.clone(),
            last_seen,
            self.timeout_ms,
        );
        Some(sock)
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_session_task(
    key: SessionKey,
    app: SocketAddr,
    sock: Arc<UdpSocket>,
    listener: Arc<UdpSocket>,
    env: Arc<CipherEnv>,
    protocol: Arc<Mutex<Box<dyn Protocol>>>,
    sessions: Arc<Mutex<HashMap<SessionKey, Session>>>,
    last_seen: Arc<AtomicU64>,
    timeout_ms: u64,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let timeout = Duration::from_millis(timeout_ms);
        loop {
            match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    last_seen.store(now_ms(), Ordering::Relaxed);
                    // C drops a response whose decryption or post-decrypt
                    // fails, or whose SS address header is malformed.
                    let plain = match env.decrypt_udp(&buf[..n]) {
                        Ok(p) => p,
                        Err(e) => {
                            ssr_debug!("[udp] decrypt failed: {e}");
                            continue;
                        }
                    };
                    let payload = {
                        let mut proto = protocol
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        match proto.udp_post_decrypt(&plain) {
                            Ok(p) if !p.is_empty() => p,
                            Ok(_) => {
                                ssr_debug!("[udp] empty response dropped");
                                continue;
                            }
                            Err(e) => {
                                ssr_debug!("[udp] post_decrypt failed: {e}");
                                continue;
                            }
                        }
                    };
                    let inner = match parse_ss_payload(&payload) {
                        Ok(d) => d,
                        Err(e) => {
                            ssr_debug!("[udp] bad response header: {e}");
                            continue;
                        }
                    };
                    // C: response address header = incoming (app) address
                    // (udp_ssr_client.c:240); data = payload after target header.
                    let (addr, port) = s5_addr_of(app);
                    let dgram = build_udp_datagram(&addr, port, &inner.payload);
                    if let Err(e) = listener.send_to(&dgram, app).await {
                        ssr_debug!("[udp] reply to {app} failed: {e}");
                    }
                }
                Ok(Err(e)) => {
                    ssr_debug!("[udp] session recv error: {e}");
                    sessions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&key);
                    break;
                }
                Err(_) => {
                    // Idle: only expire when no activity (either direction)
                    // happened within the timeout — C restarts the session
                    // timer on send and on recv.
                    let idle = now_ms().saturating_sub(last_seen.load(Ordering::Relaxed));
                    if idle < timeout_ms {
                        continue;
                    }
                    ssr_debug!("[udp] session {} idle, removed", key.0);
                    sessions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&key);
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_payload_roundtrip() {
        // [ATYP=1|1.2.3.4|0x0035|DATA]
        let payload = [0x01, 1, 2, 3, 4, 0x00, 0x35, b'h', b'i'];
        let d = parse_ss_payload(&payload).unwrap();
        assert_eq!(d.port, 53);
        assert_eq!(d.header_len, 3 + 7);
        assert_eq!(d.payload, b"hi");
    }

    #[test]
    fn s5_addr_of_v4() {
        let sa: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let (addr, port) = s5_addr_of(sa);
        assert_eq!(addr.atyp(), crate::socks5::ATYP_IPV4);
        assert_eq!(port, 9999);
    }
}
