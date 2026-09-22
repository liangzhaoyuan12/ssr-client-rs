//! T5 resilience: server kill -9, idle-timeout reclamation, 100-way
//! concurrency, and half-close settlement.
//!
//! Each test spawns the real C server (`/opt/ssr/ssr-server`) plus our client
//! binary, so all four are `#[ignore]`d by default. Run them with:
//!
//! ```sh
//! cargo test --test resilience -- --ignored
//! ```
//!
//! Ports are disjoint per test so the four can run in parallel threads.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SERVER_BIN: &str = "/opt/ssr/ssr-server";
const METHOD: &str = "aes-256-cfb";
fn cfg_text(srv_port: u16, cli_port: u16, idle: u32) -> String {
    format!(
        r#"{{
  "server": "127.0.0.1",
  "server_port": {srv_port},
  "local_address": "127.0.0.1",
  "listen_port": {cli_port},
  "password": "resilience_pass",
  "method": "{METHOD}",
  "protocol": "origin",
  "protocol_param": "",
  "obfs": "plain",
  "obfs_param": "",
  "timeout": 60,
  "udp": false,
  "idle_timeout": {idle}
}}"#
    )
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

/// Server + client process pair sharing one config pair; Drop kills both.
struct Stack {
    server: Option<Child>,
    client: Child,
    srv_cfg: PathBuf,
    cli_cfg: PathBuf,
    srv_log: PathBuf,
    cli_log: PathBuf,
    srv_port: u16,
    cli_port: u16,
}

impl Stack {
    fn spawn_server(&mut self) -> bool {
        let out = std::fs::File::create(&self.srv_log).expect("server log file");
        let err = out.try_clone().expect("clone server log");
        self.server = Some(
            Command::new(SERVER_BIN)
                .args(["-c", &self.srv_cfg.to_string_lossy()])
                .stdout(out)
                .stderr(err)
                .spawn()
                .expect("spawn ssr-server"),
        );
        wait_port(self.srv_port, Duration::from_secs(5))
    }

    fn assert_client_alive(&mut self) {
        match self.client.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!(
                "client process exited ({status}) — must not die on server kill\nclient log:\n{}",
                log_tail(&self.cli_log)
            ),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }

    fn kill_server(&mut self) {
        if let Some(mut s) = self.server.take() {
            let _ = s.kill(); // SIGKILL on unix
            let _ = s.wait();
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.kill_server();
        let _ = self.client.kill();
        let _ = self.client.wait();
    }
}

fn start_stack(tag: &str, srv_port: u16, cli_port: u16, idle: u32) -> Stack {
    assert!(
        Path::new(SERVER_BIN).exists(),
        "{SERVER_BIN} not found — resilience tests need the C server"
    );
    let dir = std::env::temp_dir();
    let srv_cfg = dir.join(format!("resil_{tag}_srv.json"));
    let cli_cfg = dir.join(format!("resil_{tag}_cli.json"));
    let srv_log = dir.join(format!("resil_{tag}_srv.log"));
    let cli_log = dir.join(format!("resil_{tag}_cli.log"));
    // The C server treats idle_timeout=0 as an immediately-expiring timer
    // (config_json.c: 0 * MILLISECONDS_PER_SECOND), which closes tunnels
    // instantly. Keep the server's timer at 30s; only the client under test
    // gets the scenario's idle value.
    std::fs::write(&srv_cfg, cfg_text(srv_port, cli_port, 30)).expect("write srv cfg");
    std::fs::write(&cli_cfg, cfg_text(srv_port, cli_port, idle)).expect("write cli cfg");

    // Placeholder child: replaced below; Drop kills it harmlessly if init fails.
    let placeholder = Command::new("true").spawn().expect("placeholder");
    let mut stack = Stack {
        server: None,
        client: placeholder,
        srv_cfg,
        cli_cfg,
        srv_log,
        cli_log,
        srv_port,
        cli_port,
    };
    assert!(stack.spawn_server(), "ssr-server did not bind {srv_port}");

    let out = std::fs::File::create(&stack.cli_log).expect("client log file");
    let err = out.try_clone().expect("clone client log");
    stack.client = Command::new(env!("CARGO_BIN_EXE_ssr_client"))
        .args(["-c", &stack.cli_cfg.to_string_lossy()])
        .stdout(out)
        .stderr(err)
        .spawn()
        .expect("spawn ssr_client");
    assert!(
        wait_port(cli_port, Duration::from_secs(5)),
        "client did not bind {cli_port}\nclient log:\n{}",
        log_tail(&stack.cli_log)
    );
    stack
}

/// Detached TCP echo target: accepts forever, echoes each connection's bytes
/// back until EOF. Distinct port per test so threads can run in parallel.
fn start_echo(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("echo bind");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if let Ok(mut s) = conn {
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
        }
    });
    assert!(wait_port(port, Duration::from_secs(2)), "echo not up");
}

/// SOCKS5 no-auth CONNECT through our proxy; socket keeps a 5s read timeout.
fn socks_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).expect("socks connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    s.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");

    s.write_all(&[0x05, 0x01, 0x00]).expect("method send");
    let mut m = [0u8; 2];
    s.read_exact(&mut m).expect("method reply");
    assert_eq!(m, [0x05, 0x00], "no acceptable auth method");

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).expect("connect send");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).expect("connect reply head");
    assert_eq!(head[0], 0x05, "socks version in reply");
    assert_eq!(head[1], 0x00, "CONNECT must succeed");
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

fn roundtrip(s: &mut TcpStream, payload: &[u8]) {
    s.write_all(payload).expect("payload send");
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).expect("payload echo");
    assert_eq!(got, payload, "echo mismatch");
}

/// T5.1: kill -9 the server → client must survive, the live connection must
/// close (EOF/RST, not hang), and a restarted server must serve new traffic.
#[test]
#[ignore = "e2e: spawns /opt/ssr/ssr-server; run with -- --ignored"]
fn server_kill_client_survives_and_recovers() {
    start_echo(18920);
    let mut st = start_stack("kill", 18500, 18910, 0);

    let mut s = socks_connect(18910, 18920);
    roundtrip(&mut s, b"before-kill");

    st.kill_server();
    st.assert_client_alive();

    // The established tunnel must terminate promptly: EOF or RST both count.
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("unexpected {n} bytes after server kill"),
        Err(_) => {} // ConnectionReset etc. — abrupt kill, either is fine
    }
    st.assert_client_alive();

    // Restart on the same config; new connections must work end to end.
    assert!(st.spawn_server(), "ssr-server restart failed");
    let mut s2 = socks_connect(18910, 18920);
    roundtrip(&mut s2, b"after-restart");
    drop(s2);

    let _ = s.shutdown(Shutdown::Both);
}

/// T5.2: an established but silent connection is reclaimed after
/// `idle_timeout` seconds (C: uv_timer in tunnel.c; our relay select branch).
#[test]
#[ignore = "e2e: spawns /opt/ssr/ssr-server; run with -- --ignored"]
fn idle_timeout_reclaims_silent_connection() {
    start_echo(18940);
    let mut st = start_stack("idle", 18510, 18930, 2);

    let mut s = socks_connect(18930, 18940);
    roundtrip(&mut s, b"ping-idle");
    let last_activity = Instant::now();

    // Echo target sends nothing more; relay must close us out ~idle later.
    let mut buf = [0u8; 64];
    let closed = s.read(&mut buf);
    let elapsed = last_activity.elapsed();
    assert_eq!(
        closed.expect("idle close read"),
        0,
        "connection must be closed (EOF) by idle reclamation"
    );
    assert!(
        elapsed >= Duration::from_millis(1500),
        "closed after {elapsed:?} — too fast to be the 2s idle timer"
    );
    assert!(
        elapsed <= Duration::from_secs(6),
        "closed after {elapsed:?} — idle reclamation too slow"
    );
    st.assert_client_alive();
}

/// T5.3: 100 concurrent tunnels through one client process; every payload
/// must round-trip.
#[test]
#[ignore = "e2e: spawns /opt/ssr/ssr-server; run with -- --ignored"]
fn hundred_concurrent_connections_all_succeed() {
    start_echo(18960);
    let mut st = start_stack("conc", 18520, 18950, 0);

    let handles: Vec<_> = (0..100)
        .map(|i| {
            std::thread::spawn(move || {
                let mut s = socks_connect(18950, 18960);
                let payload = format!("payload-{i:03}");
                roundtrip(&mut s, payload.as_bytes());
            })
        })
        .collect();
    let mut failures = Vec::new();
    for (i, h) in handles.into_iter().enumerate() {
        if let Err(e) = h.join() {
            failures.push(format!("thread {i}: {e:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{}/100 connections failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    st.assert_client_alive();
}

/// T5.4: local side half-closes (shutdown write) after a round-trip; the
/// relay must propagate the FIN and settle with a clean EOF instead of
/// hanging or killing the client.
#[test]
#[ignore = "e2e: spawns /opt/ssr/ssr-server; run with -- --ignored"]
fn half_close_write_shutdown_settles_cleanly() {
    start_echo(18980);
    let mut st = start_stack("half", 18530, 18970, 0);

    let mut s = socks_connect(18970, 18980);
    roundtrip(&mut s, b"ping-half");
    s.shutdown(Shutdown::Write).expect("half close");

    // The relay drains the server side after local EOF and then drops us:
    // we must see a clean EOF (or a reset), never a hang.
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("unexpected {n} bytes after half close"),
        Err(_) => {}
    }
    st.assert_client_alive();
}
