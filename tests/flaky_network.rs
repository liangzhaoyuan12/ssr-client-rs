//! Phase 0.4 fault-injection scaffold (GOAL.md): wire-level flakiness.
//!
//! Two layers, both targeting the known weak spots the GOAL snapshot
//! identified; a real C server (`/opt/ssr/ssr-server`) is used wherever a
//! tunnel is needed:
//!
//! * `socks5_greeting_fragmented_gets_reply` (no server needed) — the SOCKS5
//!   greeting is written one byte per 30ms, exactly what a lossy network does
//!   to a small packet. **Expected RED on current code**: `read_method_
//!   negotiation` does one `read()` then parses (`src/local/mod.rs`), so a
//!   1-byte first segment fails (`parse_method_negotiation` errors below 2
//!   bytes). Green after GOAL 1.1.
//! * `flaky_wire_full_chain_roundtrip` (ignored, needs the C server) — a
//!   re-chunking TCP proxy sits between our client and the server and
//!   re-splits every segment into 1–3 byte writes with 1ms gaps in BOTH
//!   directions. Exercises GOAL 1.1 (fragmented CONNECT too), 1.2 (first
//!   server bytes shorter than the cipher IV), 1.3 (obfs handshake response
//!   split) and 1.4 (feedback split) end to end against the production combo
//!   `aes-256-cfb + auth_aes128_sha1 + tls1.2_ticket_auth`.
//!   **Expected RED before those fixes.**
//!
//! Ports: fixed pool 20000..30000 (below Linux ephemeral floor), disjoint per
//! test so the two tests never collide when run in parallel threads:
//! 2011x = greeting test, 2012x = full-chain test.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── greeting test (runs in the default suite) ─────────────────────────────
const GREET_SOCKS: u16 = 20111;
const GREET_DEAD_SERVER: u16 = 20112; // nothing listens here on purpose

// ── full-chain test (ignored e2e) ─────────────────────────────────────────
const FC_SOCKS: u16 = 20121;
const FC_SSR: u16 = 20122;
const FC_PROXY: u16 = 20123;
const FC_ECHO: u16 = 20124;

const SERVER_BIN: &str = "/opt/ssr/ssr-server";

/// One JSON that works for BOTH binaries: the C server binds `server_port`,
/// our client connects to it and binds `listen_port` (same shape the
/// `resilience` suite already proved works).
fn cfg_text(srv_port: u16, cli_port: u16) -> String {
    format!(
        r#"{{
  "server": "127.0.0.1",
  "server_port": {srv_port},
  "local_address": "127.0.0.1",
  "listen_port": {cli_port},
  "password": "flaky_pass_1",
  "method": "aes-256-cfb",
  "protocol": "auth_aes128_sha1",
  "protocol_param": "",
  "obfs": "tls1.2_ticket_auth",
  "obfs_param": "",
  "timeout": 60,
  "udp": false,
  "idle_timeout": 30
}}"#
    )
}

fn wait_port(port: u16, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Kill every spawned child on drop, so a panicking test leaves no
/// ssr-server / ssr_client processes behind (same discipline as `resilience`).
struct Kids(Vec<Child>);

impl Drop for Kids {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn log_tail(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(txt) => txt
            .lines()
            .rev()
            .take(12)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("<unreadable {e}>"),
    }
}

/// Write `bytes` one byte at a time with a gap — models a fragmented packet.
/// Write errors are tolerated: a server that kills the connection on a
/// half-packet is exactly the bug under test, so the failure must surface at
/// the caller's read assertion (with its GOAL reference), not here.
fn send_fragmented(s: &mut TcpStream, bytes: &[u8], gap: Duration) {
    for b in bytes {
        let _ = s.write_all(std::slice::from_ref(b));
        let _ = s.flush();
        std::thread::sleep(gap);
    }
}

/// Detached TCP echo target: echoes each connection's bytes back until EOF.
fn start_echo(port: u16) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).expect("echo bind");
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    assert!(
        wait_port(port, Duration::from_secs(2)),
        "echo not up on {port}"
    );
}

/// Spawn our client binary from a config file; returns the child (guarded).
fn spawn_client(cfg: &Path, log: &Path, tag: &str) -> Child {
    let out = std::fs::File::create(log).unwrap_or_else(|e| panic!("{tag} log create: {e}"));
    let err = out.try_clone().expect("clone log");
    Command::new(env!("CARGO_BIN_EXE_ssr_client"))
        .args(["-c", &cfg.to_string_lossy()])
        .stdout(out)
        .stderr(err)
        .spawn()
        .unwrap_or_else(|e| panic!("{tag} spawn ssr_client: {e}"))
}

// ── Test 1: fragmented SOCKS5 greeting (no server; RED until GOAL 1.1) ────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_greeting_fragmented_gets_reply() {
    let dir = std::env::temp_dir();
    let cfg = dir.join("flaky_greet_cli.json");
    let log = dir.join("flaky_greet_cli.log");
    std::fs::write(&cfg, cfg_text(GREET_DEAD_SERVER, GREET_SOCKS)).expect("write cfg");

    let _kids = Kids(vec![spawn_client(&cfg, &log, "greet")]);
    assert!(
        wait_port(GREET_SOCKS, Duration::from_secs(5)),
        "client did not bind {GREET_SOCKS}\n{}",
        log_tail(&log)
    );

    let mut s = TcpStream::connect(("127.0.0.1", GREET_SOCKS)).expect("socks connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("rto");
    s.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("wto");

    // [version, nmethods, method...] split into single-byte segments.
    send_fragmented(&mut s, &[0x05, 0x01, 0x00], Duration::from_millis(30));

    let mut reply = [0u8; 2];
    let got = s.read_exact(&mut reply);
    assert!(
        got.is_ok(),
        "GOAL 1.1 (SOCKS5 half-packet): fragmented greeting got no \
         2-byte method reply — read_exact err: {:?}\nclient log:\n{}",
        got.err(),
        log_tail(&log)
    );
    assert_eq!(reply, [0x05, 0x00], "method reply must be [05 00]");
}

// ── Test 2: full chain through a re-chunking proxy (RED until GOAL 1.x) ───

/// Re-split every byte stream into 1–3 byte writes with 1ms gaps, both
/// directions. Deterministic cycling (no RNG) so failures reproduce.
async fn flaky_copy(
    mut src: tokio::net::tcp::OwnedReadHalf,
    mut dst: tokio::net::tcp::OwnedWriteHalf,
) {
    let mut buf = vec![0u8; 4096];
    let mut cycle = 0usize;
    loop {
        let n = match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut off = 0usize;
        while off < n {
            let take = 1 + cycle % 3;
            cycle += 1;
            let end = (off + take).min(n);
            if dst.write_all(&buf[off..end]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
            off = end;
        }
    }
    let _ = dst.shutdown().await;
}

/// TCP proxy on `listen` that forwards to `target` with wire re-chunking.
async fn spawn_flaky_proxy(listen: u16, target: u16) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", listen))
        .await
        .expect("proxy bind");
    tokio::spawn(async move {
        loop {
            let Ok((inbound, _)) = listener.accept().await else {
                break;
            };
            let outbound = match tokio::net::TcpStream::connect(("127.0.0.1", target)).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (ir, iw) = inbound.into_split();
            let (or_, ow) = outbound.into_split();
            tokio::spawn(async move {
                let a = tokio::spawn(flaky_copy(ir, ow));
                let b = tokio::spawn(flaky_copy(or_, iw));
                let _ = a.await;
                let _ = b.await;
            });
        }
    });
    assert!(
        wait_port(listen, Duration::from_secs(2)),
        "flaky proxy not listening on {listen}"
    );
}

/// SOCKS5 CONNECT with every client-side byte fragmented, then a roundtrip.
async fn socks_connect_fragmented(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).expect("socks connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("rto");
    s.set_write_timeout(Some(Duration::from_secs(10)))
        .expect("wto");

    send_fragmented(&mut s, &[0x05, 0x01, 0x00], Duration::from_millis(30));
    let mut m = [0u8; 2];
    s.read_exact(&mut m).unwrap_or_else(|e| {
        panic!(
            "GOAL 1.1: fragmented greeting produced no method reply: {e:?}\n{}",
            "see client log"
        )
    });
    assert_eq!(m, [0x05, 0x00], "no acceptable auth method");

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&target_port.to_be_bytes());
    send_fragmented(&mut s, &req, Duration::from_millis(20));

    let mut head = [0u8; 4];
    s.read_exact(&mut head).expect("connect reply head");
    assert_eq!(head[0], 0x05, "socks version in reply");
    assert_eq!(head[1], 0x00, "CONNECT must succeed, got rep={}", head[1]);
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).expect("domain len");
            l[0] as usize
        }
        other => panic!("bad atyp in reply: {other}"),
    };
    let mut tail = vec![0u8; skip + 2];
    s.read_exact(&mut tail).expect("connect reply tail");
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "e2e: spawns /opt/ssr/ssr-server; run with -- --ignored"]
async fn flaky_wire_full_chain_roundtrip() {
    assert!(
        std::path::Path::new(SERVER_BIN).exists(),
        "{SERVER_BIN} not found — this e2e needs the C server"
    );
    start_echo(FC_ECHO);

    let dir = std::env::temp_dir();
    let srv_cfg = dir.join("flaky_fc_srv.json");
    let cli_cfg = dir.join("flaky_fc_cli.json");
    let srv_log = dir.join("flaky_fc_srv.log");
    let cli_log = dir.join("flaky_fc_cli.log");
    // Server binds FC_SSR; our client connects to the FLAKY PROXY (FC_PROXY)
    // which forwards to FC_SSR — so every server byte arrives re-chunked.
    std::fs::write(&srv_cfg, cfg_text(FC_SSR, FC_SOCKS)).expect("write srv cfg");
    std::fs::write(&cli_cfg, cfg_text(FC_PROXY, FC_SOCKS)).expect("write cli cfg");

    let srv_out = std::fs::File::create(&srv_log).expect("srv log");
    let srv_err = srv_out.try_clone().expect("clone srv log");
    let mut kids = Kids(vec![Command::new(SERVER_BIN)
        .args(["-c", &srv_cfg.to_string_lossy()])
        .stdout(srv_out)
        .stderr(srv_err)
        .spawn()
        .expect("spawn ssr-server")]);
    assert!(
        wait_port(FC_SSR, Duration::from_secs(5)),
        "ssr-server did not bind {FC_SSR}\n{}",
        log_tail(&srv_log)
    );

    spawn_flaky_proxy(FC_PROXY, FC_SSR).await;
    kids.0.push(spawn_client(&cli_cfg, &cli_log, "fc"));
    assert!(
        wait_port(FC_SOCKS, Duration::from_secs(5)),
        "client did not bind {FC_SOCKS}\n{}",
        log_tail(&cli_log)
    );

    let mut s = socks_connect_fragmented(FC_SOCKS, FC_ECHO).await;
    let payload = b"flaky-roundtrip";
    s.write_all(payload).expect("payload send");
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).unwrap_or_else(|e| {
        panic!(
            "GOAL 1.2/1.3/1.4 (wire split): no echo through 1–3-byte chunked \
             proxy: {e:?}\nclient log:\n{}\nserver log:\n{}",
            log_tail(&cli_log),
            log_tail(&srv_log)
        )
    });
    assert_eq!(got, payload, "echo mismatch");
}
