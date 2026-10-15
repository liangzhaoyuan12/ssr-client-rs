//! Phase 0.4 fault-injection scaffold (GOAL.md): wire-level flakiness.
//!
//! Two layers, both targeting the known weak spots the GOAL snapshot
//! identified; a real C server (`/opt/ssr/ssr-server`) is used wherever a
//! tunnel is needed:
//!
//! * `socks5_greeting_fragmented_gets_reply` (no server needed) — the SOCKS5
//!   greeting is written one byte per 30ms (lossy-network half-packet).
//!   Was RED before GOAL 1.1 (single `read()` then parse; `parse_method_
//!   negotiation` errors below 2 bytes); green after the framed reads landed.
//! * `flaky_wire_full_chain_roundtrip` (ignored, needs the C server) — a
//!   re-chunking TCP proxy between our client and the server, BOTH
//!   directions. Default models REAL TCP segmentation (≤1400-byte MSS
//!   pieces; separate sender writes surface as separate reads naturally)
//!   over the production combo `aes-256-cfb + auth_aes128_sha1 +
//!   tls1.2_ticket_auth` — the end-to-end regression guard for GOAL 1.1–1.4.
//!   Triage knobs: `FLAKY_TRANSPARENT=1` (byte-verbatim),
//!   `FLAKY_CHUNK=<n>` (sub-MSS stress — control-proven with
//!   `FLAKY_CLIENT=c` that even the reference C client dies when the C
//!   SERVER receives a ClientHello split below MSS: server limitation,
//!   recorded in GOAL 1.1 progress, not our bug),
//!   `FLAKY_SOCKS_GAP_MS=0` (unfragmented SOCKS messages for control runs —
//!   the C client cannot reassemble split SOCKS bytes at all).
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
  "local_port": {cli_port},
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
/// A ZERO gap means unfragmented — one write for the whole message
/// (`FLAKY_SOCKS_GAP_MS=0`, used by control runs that must get past the
/// SOCKS layer to reach the tunnel under test).
fn send_fragmented(s: &mut TcpStream, bytes: &[u8], gap: Duration) {
    if gap.is_zero() {
        let _ = s.write_all(bytes);
        let _ = s.flush();
        return;
    }
    for b in bytes {
        let _ = s.write_all(std::slice::from_ref(b));
        let _ = s.flush();
        std::thread::sleep(gap);
    }
}

/// Inter-byte gap for the fragmented SOCKS5 writes. Override with
/// `FLAKY_SOCKS_GAP_MS` — `0` sends each SOCKS message unfragmented
/// (control mode: the reference C client cannot reassemble split SOCKS
/// bytes at all — GOAL 1.1 is our fix, not its — so a control run skips
/// SOCKS fragmentation to reach the tunnel layer under test).
fn socks_gap(default_ms: u64) -> Duration {
    let ms = std::env::var("FLAKY_SOCKS_GAP_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default_ms);
    Duration::from_millis(ms)
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

/// Spawn the client binary from a config file; returns the child (guarded).
///
/// `FLAKY_CLIENT=c` swaps in the reference C client (`/opt/ssr/ssr-client`)
/// as a control — same config, same flaky wire — to decide whether a failure
/// is our bug or a server-side limitation.
fn spawn_client(cfg: &Path, log: &Path, tag: &str) -> Child {
    let out = std::fs::File::create(log).unwrap_or_else(|e| panic!("{tag} log create: {e}"));
    let err = out.try_clone().expect("clone log");
    let bin = if std::env::var_os("FLAKY_CLIENT").as_deref() == Some(std::ffi::OsStr::new("c")) {
        "/opt/ssr/ssr-client".to_string()
    } else {
        env!("CARGO_BIN_EXE_ssr_client").to_string()
    };
    Command::new(bin)
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
    send_fragmented(&mut s, &[0x05, 0x01, 0x00], socks_gap(30));

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

// ── Test 2: full chain through the re-chunking proxy (regression guard) ──

/// Re-split every byte stream, both directions. Deterministic, no RNG, so
/// failures reproduce.
///
/// Directional piece sizes (per connection, read once via [`piece_size`]):
/// * **up** (client → server): `FLAKY_CHUNK`, default 1400 (MSS) — the C
///   server was control-proven (`FLAKY_CLIENT=c`) to KILL a tunnel whose
///   ClientHello is split below MSS, so the up direction must respect real
///   segmentation or it tests the server's limitation, not our code.
/// * **down** (server → client): `FLAKY_CHUNK_DOWN`, default 64 — small
///   enough that every handshake/feedback/response record splits, which is
///   exactly what GOAL 1.3 (obfs handshake response reassembly), 1.4
///   (feedback) and 1.2 (IV) must survive. Only OUR side ever sees these
///   pieces; the server's own reads are untouched.
///
/// `FLAKY_TRANSPARENT=1` forwards verbatim both ways (infrastructure control).
async fn flaky_copy(
    mut src: tokio::net::tcp::OwnedReadHalf,
    mut dst: tokio::net::tcp::OwnedWriteHalf,
    max_piece: usize,
) {
    let transparent = std::env::var_os("FLAKY_TRANSPARENT").is_some();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if transparent {
            if dst.write_all(&buf[..n]).await.is_err() {
                return;
            }
            continue;
        }
        let mut off = 0usize;
        while off < n {
            let end = (off + max_piece).min(n);
            if dst.write_all(&buf[off..end]).await.is_err() {
                return;
            }
            if end < n {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            off = end;
        }
    }
    let _ = dst.shutdown().await;
}

/// Per-direction max forwarded piece: env override, else the directional
/// default (up 1400 / down 64, see [`flaky_copy`]).
fn piece_size(env_key: &str, default: usize) -> usize {
    std::env::var(env_key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// TCP proxy on `listen` that forwards to `target` with wire re-chunking.
async fn spawn_flaky_proxy(listen: u16, target: u16) {
    let up_piece = piece_size("FLAKY_CHUNK", 1400);
    let down_piece = piece_size("FLAKY_CHUNK_DOWN", 64);
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
                // ir→ow: client→server (up); or_→iw: server→client (down).
                let a = tokio::spawn(flaky_copy(ir, ow, up_piece));
                let b = tokio::spawn(flaky_copy(or_, iw, down_piece));
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

    send_fragmented(&mut s, &[0x05, 0x01, 0x00], socks_gap(30));
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
    send_fragmented(&mut s, &req, socks_gap(20));

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
            "full-chain flaky wire: no echo through the re-chunking proxy \
             (GOAL 1.2/1.3/1.4 coverage): {e:?}\nclient log:\n{}\nserver log:\n{}",
            log_tail(&cli_log),
            log_tail(&srv_log)
        )
    });
    assert_eq!(got, payload, "echo mismatch");
}
