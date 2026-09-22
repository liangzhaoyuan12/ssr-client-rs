pub mod udp_relay;

/// Local SOCKS5 proxy server and SSR client orchestrator.
///
/// The SsrClient:
/// 1. Starts a local TCP listener (SOCKS5 server)
/// 2. Accepts incoming SOCKS5 connections
/// 3. Performs SOCKS5 handshake (method negotiation + CONNECT)
/// 4. Establishes a tunnel to the remote SSR server
/// 5. Relays traffic through the tunnel

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::config::SsrClientConfig;
use crate::error::{SsrError, SsrResult};
use crate::relay::TcpRelay;
use crate::socks5::{
    self, build_address_package, build_method_response, build_success_reply, parse_connect_request,
    parse_method_negotiation, ATYP_IPV4, AUTH_NONE, CMD_CONNECT,
};

/// Local SOCKS5 proxy server that tunnels connections through SSR.
#[derive(Clone)]
pub struct SsrClient {
    config: SsrClientConfig,
    running: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
}

impl SsrClient {
    /// Create a new SSR client with the given configuration.
    pub fn new(config: SsrClientConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Start the SOCKS5 proxy server.
    ///
    /// Binds to the configured listen address and port, then accepts
    /// connections in a loop. Each connection is handled in a new tokio task.
    ///
    /// This method runs until `stop()` is called.
    pub async fn start(&self) -> SsrResult<()> {
        let addr = format!("{}:{}", self.config.listen_address, self.config.listen_port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            SsrError::Connection(format!("Failed to bind SOCKS5 server on {addr}: {e}"))
        })?;

        self.running.store(true, Ordering::SeqCst);

        log::info!("SOCKS5 server listening on {addr}");

        // UDP relay (SOCKS5 UDP ASSOCIATE) — binds the same port number on UDP.
        // C creates the listener during startup; a bind failure aborts startup.
        if self.config.udp {
            let relay = crate::local::udp_relay::UdpRelay::bind(self.config.clone()).await?;
            relay.spawn(self.shutdown.clone());
            log::info!(
                "UDP relay listening on {}:{}",
                self.config.listen_address,
                self.config.listen_port
            );
        }

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            log::debug!("New connection from {peer_addr}");
                            let config = self.config.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, &config).await {
                                    log::debug!("Connection from {peer_addr} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Accept error: {e}");
                        }
                    }
                }
                _ = self.shutdown.notified() => {
                    log::info!("SOCKS5 server shutting down");
                    break;
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        log::info!("SOCKS5 server stopped");
        Ok(())
    }

    /// Stop the SOCKS5 proxy server.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.shutdown.notify_waiters();
    }

    /// Check if the server is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &SsrClientConfig {
        &self.config
    }
}

/// Obfs-aware TCP relay that handles obfs encode/decode.
///
/// Wraps upstream data with obfs encode before sending to server,
/// and unwraps downstream data with obfs decode before sending to client.
/// Uses a single obfs instance shared between handshake and relay.
/// Also handles protocol framing and cipher encryption/decryption.
struct ObfsRelay {
    local_read: tokio::net::tcp::OwnedReadHalf,
    local_write: tokio::net::tcp::OwnedWriteHalf,
    remote_read: tokio::net::tcp::OwnedReadHalf,
    remote_write: tokio::net::tcp::OwnedWriteHalf,
    obfs: Box<dyn crate::obfs::Obfs>,
    cipher_env: crate::crypto::cipher_env::CipherEnv,
    protocol: Box<dyn crate::protocol::Protocol>,
    encrypt_ctx: crate::crypto::cipher_env::EncryptContext,
    decrypt_ctx: Option<crate::crypto::cipher_env::DecryptContext>,
    cipher_iv: Vec<u8>,
    first_encrypt: bool,
    addr_pkg: Vec<u8>,
    addr_sent: bool,
    buffer_size: usize,
    /// Connection idle timeout in seconds (0 = disabled). C: uv_timer per
    /// socket (tunnel.c:158) restarted on every recv; expiry closes the relay.
    idle_timeout: u32,
}

impl ObfsRelay {
    /// Create a new ObfsRelay with a shared obfs instance.
    fn new(
        local: TcpStream,
        remote: TcpStream,
        obfs: Box<dyn crate::obfs::Obfs>,
        cipher_env: crate::crypto::cipher_env::CipherEnv,
        mut protocol: Box<dyn crate::protocol::Protocol>,
        addr_pkg: Vec<u8>,
        idle_timeout: u32,
    ) -> SsrResult<Self> {
        let (local_read, local_write) = local.into_split();
        let (remote_read, remote_write) = remote.into_split();

        // Create the stateful encrypt context (generates random IV).
        // Propagate failure instead of panicking: this runs inside a spawned
        // per-connection task, so a panic here silently kills the worker and
        // leaves the SOCKS5 client hanging with no diagnostic.
        let (encrypt_ctx, iv) = cipher_env.create_encrypt_ctx()?;

        // The protocol's MAC key prefix must be the cipher IV we transmit
        // (C ssr_executive.c:400 sets server_info.iv = enc_ctx_get_iv()).
        protocol.set_server_iv(iv.clone());
        
        Ok(Self {
            local_read,
            local_write,
            remote_read,
            remote_write,
            obfs,
            cipher_env,
            protocol,
            encrypt_ctx,
            decrypt_ctx: None,
            cipher_iv: iv,
            first_encrypt: true,
            addr_pkg,
            addr_sent: false,
            buffer_size: 8192,
            idle_timeout,
        })
    }

    /// Run the obfs-aware relay.
    ///
    /// First sends the address package (protocol→cipher→obfs),
    /// which triggers the obfs layer to generate CCS+Finished.
    /// Then streams remaining data from client.
    async fn run(mut self) -> SsrResult<(u64, u64)> {
        use crate::protocol::Protocol;

        let mut total_up = 0u64;
        let mut total_down = 0u64;

        let mut local_buf = vec![0u8; self.buffer_size];
        let mut remote_buf = vec![0u8; self.buffer_size];

        // Step 1: Wait for first data from local client, then send
        // address + first data together through protocol layer.
        // This is needed for auth_chain protocols which pack
        // head_size=min(1200, total) into the auth header.
        if !self.addr_pkg.is_empty() {
            ssr_debug!("[relay] Waiting for first client data to combine with address...");
            // C bounds every socket wait by idle_timeout (tunnel.c uv_timer).
            // Keep the historical 10s cap, but honour a tighter idle_timeout.
            let first_wait_s = if self.idle_timeout > 0 {
                10u64.min(self.idle_timeout as u64)
            } else {
                10
            };
            let first_read = tokio::time::timeout(
                std::time::Duration::from_secs(first_wait_s),
                self.local_read.read(&mut local_buf),
            ).await;
            let first_data_len = match first_read {
                Ok(Ok(0)) => {
                    ssr_debug!("[relay] Client closed before sending data");
                    return Ok((total_up, total_down));
                }
                Ok(Ok(n)) => {
                    ssr_debug!("[relay] First client data: {} bytes", n);
                    n
                }
                Ok(Err(e)) => {
                    ssr_debug!("[relay] Client read error: {e}");
                    return Ok((total_up, total_down));
                }
                Err(_) => {
                    ssr_debug!("[relay] Client read timeout");
                    return Ok((total_up, total_down));
                }
            };
            // Combine address + first data for protocol layer
            let mut combined = self.addr_pkg.clone();
            combined.extend_from_slice(&local_buf[..first_data_len]);
            ssr_debug!("[relay] Sending combined address+data: {} bytes", combined.len());
            let framed = self.protocol.client_pre_encrypt(&combined)?;
            ssr_debug!("[relay] Address framed: {} bytes", framed.len());
            let mut encrypted = self.cipher_env.encrypt_ctx(&mut self.encrypt_ctx, &framed, self.first_encrypt)?;
            if self.first_encrypt {
                let mut with_iv = Vec::with_capacity(self.cipher_iv.len() + encrypted.len());
                with_iv.extend_from_slice(&self.cipher_iv);
                with_iv.extend_from_slice(&encrypted);
                encrypted = with_iv;
                self.first_encrypt = false;
            }
            ssr_debug!("[relay] Encrypted: {} bytes, first 48: {}", encrypted.len(), encrypted.iter().take(48).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            let encoded = self.obfs.client_encode(&encrypted)?;
            ssr_debug!("[relay] Address obfs encoded: {} bytes", encoded.len());
            ssr_debug!("[relay] FULL HEX: {}", encoded.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
            self.remote_write.write_all(&encoded).await?;
            self.addr_sent = true;
            total_up += combined.len() as u64;

            // Read server feedback after sending address
            // For origin protocol (AEAD): no feedback needed, skip wait
            if self.protocol.need_feedback() {
                let n = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    self.remote_read.read(&mut remote_buf),
                ).await;
                match n {
                    Ok(Ok(0)) => {
                        ssr_debug!("[relay] Server closed after address");
                    }
                    Ok(Ok(n)) => {
                        ssr_debug!("[relay] Server feedback: {} bytes", n);
                    // Process server feedback (obfs decode, cipher decrypt, protocol post_decrypt)
                    let (decrypted_obfs, _needs_feedback) = self.obfs.client_decode(&remote_buf[..n])?;
                    if !decrypted_obfs.is_empty() {
                        let decrypted_cipher = if let Some(ref mut dctx) = self.decrypt_ctx {
                            self.cipher_env.decrypt_ctx(dctx, &decrypted_obfs)?
                        } else {
                            let (dctx, data) = self.cipher_env.create_decrypt_ctx_from_ciphertext(&decrypted_obfs)?;
                            self.decrypt_ctx = Some(dctx);
                            self.cipher_env.decrypt_ctx(self.decrypt_ctx.as_mut().unwrap(), &data)?
                        };
                        let decoded = self.protocol.client_post_decrypt(&decrypted_cipher)?;
                        if !decoded.is_empty() {
                            self.local_write.write_all(&decoded).await?;
                        }
                    }
                    total_down += n as u64;
                }
                _ => {
                    ssr_debug!("[relay] Server feedback timeout/error");
                }
            }
            } // end if need_feedback
        }

        ssr_debug!("[relay] Starting streaming relay loop");
        // Idle reclamation (C: uv_timer per socket, tunnel.c:158): no traffic
        // in either direction for idle_timeout closes the relay; 0 disables.
        let idle_secs = self.idle_timeout;
        let idle_on = idle_secs > 0;
        let idle = std::time::Duration::from_secs(idle_secs as u64);
        let mut idle_fut = std::pin::pin!(tokio::time::sleep(idle));
        loop {
            tokio::select! {
                _ = &mut idle_fut, if idle_on => {
                    ssr_debug!("[relay] Idle timeout ({idle_secs}s), closing relay");
                    break;
                }
                result = self.local_read.read(&mut local_buf) => {
                    match result {
                        Ok(0) => {
                            ssr_debug!("[relay] EOF from client, draining server...");
                            // Client closed — send FIN to server, then drain remaining server data
                            let _ = self.remote_write.shutdown().await;
                            loop {
                                match self.remote_read.read(&mut remote_buf).await {
                                    Ok(0) => { ssr_debug!("[relay] Server EOF after drain"); break; }
                                    Ok(n) => {
                                        let (decrypted_obfs, _) = self.obfs.client_decode(&remote_buf[..n])?;
                                        if !decrypted_obfs.is_empty() {
                                            let decrypted_cipher = if let Some(ref mut dctx) = self.decrypt_ctx {
                                                self.cipher_env.decrypt_ctx(dctx, &decrypted_obfs)?
                                            } else {
                                                let (dctx, data) = self.cipher_env.create_decrypt_ctx_from_ciphertext(&decrypted_obfs)?;
                                                self.decrypt_ctx = Some(dctx);
                                                self.cipher_env.decrypt_ctx(self.decrypt_ctx.as_mut().unwrap(), &data)?
                                            };
                                            let decoded = self.protocol.client_post_decrypt(&decrypted_cipher)?;
                                            if !decoded.is_empty() {
                                                self.local_write.write_all(&decoded).await?;
                                            }
                                            total_down += n as u64;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            break;
                        }
                        Ok(n) => {
                            idle_fut.as_mut().reset(tokio::time::Instant::now() + idle);
                            ssr_debug!("[relay] Upstream: {} bytes from client", n);
                            // Protocol: frame the data
                            let framed = self.protocol.client_pre_encrypt(&local_buf[..n])?;
                            ssr_debug!("[relay] Protocol framed: {} bytes", framed.len());
                            // Stateful cipher: encrypt with stream state
                            let mut encrypted = self.cipher_env.encrypt_ctx(&mut self.encrypt_ctx, &framed, false)?;
                            ssr_debug!("[relay] Encrypted: {} bytes", encrypted.len());
                            // Obfs: wrap in TLS record
                            let encoded = self.obfs.client_encode(&encrypted)?;
                            ssr_debug!("[relay] Obfs encoded: {} bytes", encoded.len());
                            self.remote_write.write_all(&encoded).await?;
                            total_up += n as u64;
                        }
                        Err(e) => {
                            ssr_debug!("[relay] Upstream read error: {e}");
                            break;
                        }
                    }
                }
                result = self.remote_read.read(&mut remote_buf) => {
                    match result {
                        Ok(0) => {
                            ssr_debug!("[relay] EOF from server");
                            break;
                        }
                        Ok(n) => {
                            idle_fut.as_mut().reset(tokio::time::Instant::now() + idle);
                            ssr_debug!("[relay] Downstream: {} bytes from server", n);
                            // Obfs: unwrap TLS record
                            let (decrypted_obfs, _needs_feedback) = self.obfs.client_decode(&remote_buf[..n])?;
                            ssr_debug!("[relay] Obfs decoded: {} bytes", decrypted_obfs.len());
                            if decrypted_obfs.is_empty() {
                                continue;
                            }
                            // Stateful cipher: decrypt with stream state
                            let decrypted_cipher = if let Some(ref mut dctx) = self.decrypt_ctx {
                                // Subsequent messages: no IV prefix, use existing state
                                self.cipher_env.decrypt_ctx(dctx, &decrypted_obfs)?
                            } else {
                                // First message: read IV from ciphertext, create context
                                let (dctx, data) = self.cipher_env.create_decrypt_ctx_from_ciphertext(&decrypted_obfs)?;
                                self.decrypt_ctx = Some(dctx);
                                self.cipher_env.decrypt_ctx(self.decrypt_ctx.as_mut().unwrap(), &data)?
                            };
                            ssr_debug!("[relay] Decrypted: {} bytes", decrypted_cipher.len());
                            // Protocol: unwrap framing
                            let decoded = self.protocol.client_post_decrypt(&decrypted_cipher)?;
                            ssr_debug!("[relay] Protocol decoded: {} bytes", decoded.len());
                            if !decoded.is_empty() {
                                self.local_write.write_all(&decoded).await?;
                            }
                            total_down += n as u64;
                        }
                        Err(e) => {
                            ssr_debug!("[relay] Downstream read error: {e}");
                            break;
                        }
                    }
                }
            }
        }

        Ok((total_up, total_down))
    }
}

/// Handle a single SOCKS5 connection.
///
/// Performs the full SOCKS5 handshake, establishes a tunnel to the
/// configured SSR server (including the obfs handshake), then relays
/// data through the tunnel.
async fn handle_connection(mut stream: TcpStream, config: &SsrClientConfig) -> SsrResult<()> {
    // Step 1: Method negotiation
    let method_req = read_method_negotiation(&mut stream).await?;
    let selected = select_method(&method_req.methods)?;
    stream
        .write_all(&build_method_response(selected))
        .await?;

    // Step 2: Connect request
    let connect_req = read_connect_request(&mut stream).await?;

    // UDP ASSOCIATE: reply with this connection's local address (C: uv_tcp_
    // getsockname, client.c:653) — the UDP relay binds the same port number.
    if connect_req.cmd == socks5::CMD_UDP_ASSOCIATE {
        let local = stream
            .local_addr()
            .map_err(|e| SsrError::Connection(format!("local_addr: {e}")))?;
        let (atyp, bytes, port) = match local {
            std::net::SocketAddr::V4(a) => (ATYP_IPV4, a.ip().octets().to_vec(), a.port()),
            std::net::SocketAddr::V6(a) => (socks5::ATYP_IPV6, a.ip().octets().to_vec(), a.port()),
        };
        let rep = if config.udp {
            socks5::REP_SUCCESS
        } else {
            socks5::REP_COMMAND_NOT_SUPPORTED
        };
        stream
            .write_all(&socks5::build_connect_reply(rep, atyp, &bytes, port))
            .await?;
        ssr_debug!(
            "[udp] UDP ASSOCIATE {} (relay {})",
            if config.udp { "granted" } else { "refused" },
            if config.udp { "on" } else { "off" }
        );
        if config.udp {
            // Hold the control connection: the association lives as long as
            // this TCP connection (RFC 1928; C stage s5_udp_accoc).
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        return Ok(());
    }

    if connect_req.cmd != CMD_CONNECT {
        stream
            .write_all(&socks5::build_connect_reply(
                socks5::REP_COMMAND_NOT_SUPPORTED,
                ATYP_IPV4,
                &[0, 0, 0, 0],
                0,
            ))
            .await?;
        return Err(SsrError::socks5(format!(
            "Unsupported SOCKS5 command: 0x{:02x}",
            connect_req.cmd
        )));
    }

    // Step 3: Establish tunnel to remote SSR server
    ssr_debug!("[conn] CONNECT {}:{}", connect_req.addr.display(), connect_req.port);

    let mut remote_stream = connect_to_ssr_server(config).await?;
    ssr_debug!("[conn] Connected to SSR server");

    // Create cipher and obfs instances
    use crate::crypto::cipher_env::CipherEnv;
    use crate::crypto::aead::AeadCipher;
    use crate::crypto::types::CipherType;
    let env = CipherEnv::new(&config.password, &config.method)?;
    let method = CipherType::from_name(&config.method)?;
    let is_aead = AeadCipher::is_aead(method);

    // AEAD downgrade (ssr_executive.c:175-179): plain obfs + origin protocol
    let mut obfs_inst = if is_aead {
        Box::new(crate::obfs::plain::PlainObfs::new()) as Box<dyn crate::obfs::Obfs>
    } else {
        crate::obfs::create_obfs(
            &config.obfs,
            &config.server,
            config.server_port,
            &config.obfs_param,
        )
        .ok_or_else(|| SsrError::Obfs(format!("Unsupported obfs: {}", config.obfs)))?
    };
    obfs_inst.set_key(env.key().to_vec());
    ssr_debug!("[conn] Created obfs instance{}", if is_aead { " (AEAD→plain)" } else { "" });

    // Step 4: Perform the obfs handshake, if this obfs uses one.
    // Plain / HTTP obfs carry their framing with the first data packet and send
    // nothing up front, so waiting for a response would just stall for the timeout.
    if obfs_inst.needs_handshake() {
        ssr_debug!("[conn] Starting obfs handshake");
        match perform_obfs_handshake(&mut remote_stream, &mut obfs_inst).await {
            Ok(()) => ssr_debug!("[conn] Obfs handshake completed"),
            Err(e) => {
                ssr_debug!("[conn] Obfs handshake failed: {e}");
                return Err(e);
            }
        }
    }

    // Step 5: Send SOCKS5 success reply to client
    let reply = build_success_reply(connect_req.addr.atyp());
    stream.write_all(&reply).await?;
    ssr_debug!("[conn] Sent SOCKS5 success reply");

    // Step 5.5: Build address package (ATYP + addr + port) for SSR protocol
    // The SSR protocol expects the address as the first data payload
    let addr_pkg = build_address_package(&connect_req.addr, connect_req.port);
    ssr_debug!("[conn] Address package: {} bytes", addr_pkg.len());

    // Step 6: Relay data between client and SSR server (with obfs encode/decode)
    //
    // AEAD downgrade already applied above (obfs=plain, protocol=origin).
    let protocol = create_protocol(config, &env, is_aead)?;

    ssr_debug!("[conn] Starting obfs relay");
    let relay = ObfsRelay::new(stream, remote_stream, obfs_inst, env, protocol, addr_pkg, config.idle_timeout)?;
    let (up, down) = relay.run().await?;

    ssr_debug!("[conn] Relay finished: upstream={up}, downstream={down}");
    Ok(())
}

/// Build the protocol plugin for one connection/datagram stream.
///
/// Shared by the TCP path (`handle_connection`) and the UDP relay — both must
/// construct identical instances (AEAD downgrades to `origin`, auth_chain
/// reports overhead 4, `extra_param` carries `protocol_param` as in C
/// `ssr_executive.c`). Calls `init_user_key()` before returning.
pub(crate) fn create_protocol(
    config: &SsrClientConfig,
    env: &crate::crypto::cipher_env::CipherEnv,
    is_aead: bool,
) -> SsrResult<Box<dyn crate::protocol::Protocol>> {
    use crate::protocol::auth_aes128::AuthAES128;
    use crate::protocol::auth_chain::*;
    use crate::protocol::auth_sha1::AuthSHA1;
    use crate::protocol::auth_sha1_v2::AuthSHA1V2;
    use crate::protocol::auth_sha1_v4::AuthSHA1V4;
    use crate::protocol::auth_simple::AuthSimple;
    use crate::protocol::{Protocol, ServerInfo};

    let mut protocol: Box<dyn Protocol> = if is_aead {
        // AEAD: origin protocol (no framing), matching C ssr_executive.c:178
        Box::new(crate::protocol::origin::Origin)
    } else {
        let srv = ServerInfo {
            key: env.key().to_vec(),
            extra_param: config.protocol_param.clone(),
            ..Default::default()
        };
        let mut srv = srv;
        // Set overhead based on protocol (C: auth_chain_a_get_overhead returns 4)
        if matches!(
            config.protocol.as_str(),
            "auth_chain_a"
                | "auth_chain_b"
                | "auth_chain_c"
                | "auth_chain_d"
                | "auth_chain_e"
                | "auth_chain_f"
        ) {
            srv.overhead = 4;
        }
        match config.protocol.as_str() {
            "auth_aes128_md5" => Box::new(AuthAES128::new_md5(srv)),
            "auth_aes128_sha1" => Box::new(AuthAES128::new_sha1(srv)),
            "auth_sha1_v4" => Box::new(AuthSHA1V4::new(srv)),
            "auth_sha1_v2" => Box::new(AuthSHA1V2::new(srv)),
            "auth_sha1" => Box::new(AuthSHA1::new(srv)),
            "auth_simple" => Box::new(AuthSimple::new()),
            "auth_chain_a" => Box::new(AuthChainA::new(srv, "auth_chain_a")),
            "auth_chain_b" => Box::new(AuthChainB::new(srv)),
            "auth_chain_c" => Box::new(AuthChainC::new(srv)),
            "auth_chain_d" => Box::new(AuthChainD::new(srv)),
            "auth_chain_e" => Box::new(AuthChainE::new(srv)),
            "auth_chain_f" => Box::new(AuthChainF::new(srv, &config.protocol_param)),
            "origin" | "" => Box::new(crate::protocol::origin::Origin),
            other => {
                return Err(SsrError::Protocol(format!(
                    "Unsupported protocol '{other}'"
                )));
            }
        }
    };
    protocol.init_user_key();
    Ok(protocol)
}

/// Read and parse the SOCKS5 method negotiation from the client.
async fn read_method_negotiation(stream: &mut TcpStream) -> SsrResult<socks5::MethodNegotiation> {
    // SOCKS5 greeting: [version, nmethods, methods...]
    // nmethods is at most 255, so we read at most 257 bytes
    let mut buf = vec![0u8; 257];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| SsrError::Socks5(format!("Failed to read method negotiation: {e}")))?;

    if n == 0 {
        return Err(SsrError::socks5("Client closed connection during handshake"));
    }

    parse_method_negotiation(&buf[..n])
}

/// Read and parse the SOCKS5 CONNECT request from the client.
async fn read_connect_request(stream: &mut TcpStream) -> SsrResult<socks5::ConnectRequest> {
    // Max SOCKS5 request: version(1) + cmd(1) + rsv(1) + atyp(1) + domain_len(1) + domain(255) + port(2) = 262
    let mut buf = vec![0u8; 262];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| SsrError::Socks5(format!("Failed to read CONNECT request: {e}")))?;

    if n == 0 {
        return Err(SsrError::socks5("Client closed connection during CONNECT"));
    }

    ssr_debug!("[socks5] Raw CONNECT: {} bytes: {}", n, buf[..n].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));

    parse_connect_request(&buf[..n])
}

/// Select an authentication method from the client's offered methods.
///
/// Currently only supports NO AUTH (0x00).
fn select_method(offered: &[u8]) -> SsrResult<u8> {
    if offered.contains(&AUTH_NONE) {
        Ok(AUTH_NONE)
    } else {
        Err(SsrError::socks5(
            "Client does not support NO AUTH method",
        ))
    }
}

/// Perform the obfs handshake with the SSR server.
///
/// Sends ClientHello, reads server response, processes it.
/// Does NOT send Finished+AppData — the relay will send it with real data.
async fn perform_obfs_handshake(
    remote: &mut TcpStream,
    obfs_inst: &mut Box<dyn crate::obfs::Obfs>,
) -> SsrResult<()> {
    use std::time::Duration;

    // Generate ClientHello (empty buffer call to avoid dummy data)
    let client_hello = obfs_inst.client_encode(&[])?;

    // Send ClientHello
    remote.write_all(&client_hello).await?;
    ssr_debug!("[obfs] Sent ClientHello: {} bytes", client_hello.len());

    // Read server response with timeout
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(
        Duration::from_secs(10),
        remote.read(&mut buf),
    )
    .await
    .map_err(|_| SsrError::Connection("Timeout reading server response".to_string()))?
    ?;
    if n == 0 {
        return Err(SsrError::Connection("Server closed connection during handshake".to_string()));
    }
    ssr_debug!("[obfs] Received server response: {} bytes", n);

    // Process server response
    let (_decoded, needs_feedback) = obfs_inst.client_decode(&buf[..n])?;
    ssr_debug!("[obfs] Needs feedback: {}", needs_feedback);

    // NOTE: We do NOT send the Finished+AppData here.
    // The relay will send it with the first real data from the SOCKS5 client.
    // This ensures the Finished is followed by real Application Data.

    Ok(())
}
async fn connect_to_ssr_server(config: &SsrClientConfig) -> SsrResult<TcpStream> {
    let addr = format!("{}:{}", config.server, config.server_port);

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(config.connect_timeout as u64),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| {
        SsrError::Connection(format!(
            "Timeout connecting to SSR server {addr} ({}s)",
            config.connect_timeout
        ))
    })?
    .map_err(|e| SsrError::Connection(format!("Failed to connect to SSR server {addr}: {e}")))?;

    log::debug!("Connected to SSR server at {addr}");
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SsrClientConfig;

    #[test]
    fn test_ssr_client_new() {
        let config = SsrClientConfig::new(
            "127.0.0.1",
            8388,
            "password",
            "aes-256-cfb",
            "auth_aes128_sha1",
            "tls1.2_ticket_auth",
        );
        let client = SsrClient::new(config);
        assert!(!client.is_running());
        assert_eq!(client.config().server, "127.0.0.1");
        assert_eq!(client.config().server_port, 8388);
    }

    #[test]
    fn test_ssr_client_stop() {
        let config = SsrClientConfig::new(
            "127.0.0.1",
            8388,
            "password",
            "aes-256-cfb",
            "origin",
            "plain",
        );
        let client = SsrClient::new(config);
        assert!(!client.is_running());
        client.stop();
        assert!(!client.is_running());
    }

    #[test]
    fn test_select_method_with_no_auth() {
        let methods = vec![0x00, 0x01, 0x02];
        assert_eq!(select_method(&methods).unwrap(), AUTH_NONE);
    }

    #[test]
    fn test_select_method_no_auth_only() {
        let methods = vec![0x00];
        assert_eq!(select_method(&methods).unwrap(), AUTH_NONE);
    }

    #[test]
    fn test_select_method_rejects_when_no_auth_not_offered() {
        let methods = vec![0x01, 0x02];
        let result = select_method(&methods);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_method_empty_list() {
        let methods: Vec<u8> = vec![];
        let result = select_method(&methods);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ssr_client_start_and_stop() {
        let config = SsrClientConfig::new(
            "127.0.0.1",
            19876,
            "password",
            "aes-256-cfb",
            "origin",
            "plain",
        );
        let client = SsrClient::new(config);

        let client_ref = client.clone();
        let handle = tokio::spawn(async move { client.start().await });

        // Wait briefly for server to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Stop
        client_ref.stop();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Handle should complete without error
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connect_to_ssr_server_refused() {
        let config = SsrClientConfig::new(
            "127.0.0.1",
            19999, // Nothing listening
            "password",
            "none",
            "origin",
            "plain",
        );
        let result = connect_to_ssr_server(&config).await;
        assert!(result.is_err());
    }
}
