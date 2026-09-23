//! U2: data-pipe mode (`SsrClient::open_session`, integration Mode B).
//!
//! Default test: the connect-refused error path (needs no server).
//! Ignored e2e: full HTTP roundtrip through the real C server
//! (`/opt/ssr/ssr-server`) using the production combo
//! `aes-256-cfb` + `auth_aes128_sha1` + `tls1.2_ticket_auth`, covering the
//! obfs handshake inside `open_session`, IPv4 and Domain targets (server-side
//! DNS), session reuse, and graceful `finish()`.
//!
//! ```sh
//! cargo test --test pipe_session               # refused path only
//! cargo test --test pipe_session -- --ignored  # + e2e against /opt/ssr
//! ```
//!
//! Ports are disjoint from the matrix (18388/18903), resilience (185xx) and
//! UDP (199xx) suites: server 18601, HTTP origin 18610.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ssr_client_rs::{CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SERVER_BIN: &str = "/opt/ssr/ssr-server";
const SRV_PORT: u16 = 18601;
const ORIGIN_PORT: u16 = 18610;

fn client_config() -> SsrClientConfig {
    SsrClientConfig {
        server: "127.0.0.1".into(),
        server_port: SRV_PORT,
        password: "pipe_test_pass".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::AuthAES128SHA1,
        obfs: ObfsType::TLS12TicketAuth,
        udp: false,
        idle_timeout: 30,
        connect_timeout: 3,
        ..Default::default()
    }
}

/// Kill the spawned C server on drop (also on panic).
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Minimal HTTP origin on a fixed body so tests can assert on it. Binds
/// synchronously so a bind failure panics the test instead of surfacing as a
/// mysterious "connection refused" from the SSR server.
fn spawn_http_origin(port: u16) {
    // Dual-stack "[::]": the SSR server resolves "localhost" to either
    // 127.0.0.1 or ::1, so an IPv4-only bind makes the Domain session fail
    // with "connection refused" on half the resolver orders.
    let listener = TcpListener::bind(("::", port))
        .or_else(|_| TcpListener::bind(("127.0.0.1", port)))
        .expect("bind HTTP origin (port busy?)");
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut sock) = incoming else { break };
            let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf); // consume the request (best effort)
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            );
            let _ = sock.flush();
            // drop = FIN
        }
    });
}

fn spawn_c_server() -> ServerGuard {
    assert!(
        Path::new(SERVER_BIN).exists(),
        "{SERVER_BIN} not found — the pipe e2e test needs the C server"
    );
    let dir = std::env::temp_dir();
    let cfg = dir.join("pipe_session_srv.json");
    let log = dir.join("pipe_session_srv.log");
    // idle_timeout must not be 0: the C server treats it as an instantly
    // expiring timer (config_json.c) and closes tunnels immediately.
    let text = format!(
        r#"{{
  "server": "127.0.0.1",
  "server_port": {SRV_PORT},
  "password": "pipe_test_pass",
  "method": "aes-256-cfb",
  "protocol": "auth_aes128_sha1",
  "protocol_param": "",
  "obfs": "tls1.2_ticket_auth",
  "obfs_param": "",
  "timeout": 60,
  "udp": false,
  "idle_timeout": 30
}}"#
    );
    std::fs::write(&cfg, text).expect("write server cfg");
    let out = std::fs::File::create(&log).expect("server log file");
    let err = out.try_clone().expect("clone server log");
    let child = Command::new(SERVER_BIN)
        .args(["-c", cfg.to_str().unwrap_or_default()])
        .stdout(out)
        .stderr(err)
        .spawn()
        .expect("spawn ssr-server");
    assert!(
        wait_port(SRV_PORT, Duration::from_secs(5)),
        "ssr-server did not bind {SRV_PORT}"
    );
    ServerGuard(child)
}

/// One HTTP request over a pipe session; returns the raw response bytes.
async fn http_get(mut session: ssr_client_rs::SsrSession, host_header: &str) -> Vec<u8> {
    let req = format!("GET / HTTP/1.1\r\nHost: {host_header}\r\n\r\n");
    tokio::time::timeout(Duration::from_secs(10), session.write_all(req.as_bytes()))
        .await
        .expect("session write timed out")
        .expect("session write failed");

    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.windows(5).any(|w| w == b"hello") {
        let n = tokio::time::timeout(Duration::from_secs(10), session.read(&mut buf))
            .await
            .expect("session read timed out")
            .expect("session read failed");
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
    }
    tokio::time::timeout(Duration::from_secs(10), session.finish())
        .await
        .expect("finish() timed out")
        .expect("relay error on finish");
    resp
}

#[tokio::test]
async fn open_session_refused_without_server() {
    // Port 1 is never listening: open_session must fail at the connect step
    // (no SOCKS5 involved, no listener bound) instead of hanging.
    let client = SsrClient::new(SsrClientConfig {
        server: "127.0.0.1".into(),
        server_port: 1,
        password: "x".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::Origin,
        obfs: ObfsType::Plain,
        connect_timeout: 1,
        ..Default::default()
    });
    let result = client
        .open_session(TargetAddr::IPv4([127, 0, 0, 1], ORIGIN_PORT))
        .await;
    assert!(result.is_err(), "connect to port 1 must fail");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "e2e: spawns /opt/ssr/ssr-server; run with -- --ignored"]
async fn pipe_session_http_roundtrip() {
    spawn_http_origin(ORIGIN_PORT);
    let _server = spawn_c_server();
    let client = SsrClient::new(client_config());

    // Session 1: plain IPv4 target (caller-resolved address = custom-DNS use
    // case: resolve however you like, hand the pipe an IP).
    let session = client
        .open_session(TargetAddr::IPv4([127, 0, 0, 1], ORIGIN_PORT))
        .await
        .expect("open IPv4 session (TLS obfs handshake happens here)");
    let resp = http_get(session, "127.0.0.1").await;
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {text:?}"
    );
    assert!(text.contains("hello"), "missing body: {text:?}");

    // Session 2: Domain target — the SSR server resolves it (remote-DNS use
    // case), and the same client reuses its config for a second tunnel.
    let session = client
        .open_session(TargetAddr::Domain("localhost".into(), ORIGIN_PORT))
        .await
        .expect("open Domain session");
    let resp = http_get(session, "localhost").await;
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {text:?}"
    );
    assert!(text.contains("hello"), "missing body: {text:?}");
}
