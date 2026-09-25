# ssr-client-rs

[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-blue.svg)](https://blog.rust-lang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86__64%20%7C%20loongarch64-lightgrey.svg)](#building)
[![Crates.io](https://img.shields.io/crates/v/ssr-client-rs.svg)](https://crates.io/crates/ssr-client-rs)
[![docs.rs](https://docs.rs/crates/ssr-client-rs/badge.svg)](https://docs.rs/ssr-client-rs)

**English** | [简体中文](README.zh-CN.md)

Full usage documentation: [`docs/USAGE.md`](docs/USAGE.md)
（[中文](docs/USAGE.zh-CN.md)）

A byte-compatible Rust client library for the ShadowsocksR (SSR-N) protocol,
providing the encryption, protocol, obfuscation and transport layers plus a
SOCKS5 local proxy. Verified against the reference `ssr-n` C server.

## Features

- **28 cipher methods, 21 implemented** here (see
  [Support matrix](#support-matrix))
- **14 protocols** — origin, verify_simple, auth_simple, auth_sha1/v2/v4,
  auth_aes128_md5/sha1, auth_chain_a–f
- **6 obfuscation methods** — plain, http_simple/post/mix,
  tls1.2_ticket_auth/fastauth (all six e2e-verified)
- **TCP + UDP relay** (SOCKS5 CONNECT and UDP ASSOCIATE)
- **Tokio-based async I/O**, zero `unsafe`, zero production-path panics
- **ssr-n JSON config compatible** (`server`, `listen_port`, … keys — see
  [Configuration](#configuration))

```
User Data → SOCKS5 → Protocol (pre_encrypt) → Crypto (encrypt) → Obfs (encode) → Server
Server   → Obfs (decode) → Crypto (decrypt) → Protocol (post_decrypt) → User
```

## Support matrix

The latest full matrix run lives in
[`tests/e2e/RESULTS.md`](tests/e2e/RESULTS.md)
(39/51 PASS + 12 SKIP, **0 FAIL** against `/opt/ssr/ssr-server`):

| Axis | Result | SKIP reasons |
|---|---|---|
| cipher (28) | **20 PASS** | camellia×3: client not implemented; cast5/idea/rc2/seed/des-cfb: the server itself rejects them (the C client fails too) |
| protocol (14) | **10 PASS** | verify_simple/auth_simple/auth_sha1/v2 — the server registers no `server_post_decrypt` for them (the C client fails too) |
| obfs (6) | **6 PASS** | — |
| UDP (3 combos) | **3 PASS** | — |

Measured throughput and per-packet overhead live in [`BENCH.md`](BENCH.md)
(head-to-head vs the C client: **106.5% of its throughput at 0.77× its CPU**,
concurrency curve, cipher/protocol/obfs/session-setup tables).

## Quick start

### As a library

```toml
[dependencies]
ssr-client-rs = "0.1"
tokio = { version = "1", features = ["full"] }
```

Or track git: `ssr-client-rs = { git = "https://cnb.cool/liangzhaoyuan12/ssr-client-rs" }`.
See [`docs/USAGE.md`](docs/USAGE.md) §2 for details.

```rust,no_run
use ssr_client_rs::config_json::config_from_json;
use ssr_client_rs::{CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig};

#[tokio::main]
async fn main() {
    // Option A: load an ssr-n style JSON config (keys match the struct fields).
    let json = r#"{
        "server": "example.com", "server_port": 8388,
        "listen_address": "127.0.0.1", "listen_port": 1080,
        "password": "secret", "method": "aes-256-cfb",
        "protocol": "auth_aes128_sha1", "protocol_param": "",
        "obfs": "tls1.2_ticket_auth", "obfs_param": "",
        "udp": true, "idle_timeout": 300,
        "connect_timeout": 6, "udp_timeout": 6
    }"#;
    let config = config_from_json(json).expect("valid config");

    // Option B: build it as a struct literal (all fields are public;
    // fill in what you care about, the rest comes from Default).
    let _config2 = SsrClientConfig {
        server: "example.com".into(),
        server_port: 8388,
        password: "secret".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::AuthAES128SHA1,
        obfs: ObfsType::TLS12TicketAuth,
        ..Default::default()
    };

    let client = SsrClient::new(config);
    client.start().await.expect("SOCKS5 listener + relay");
}
```

### Two integration modes

| | Mode A — system port (default) | Mode B — data pipe |
|---|---|---|
| API | `client.start()` | `client.open_session(target)` |
| Front side | binds `listen_address:listen_port`, speaks SOCKS5 + UDP ASSOCIATE | none — your own front protocol owns it |
| Back side | handled internally | `AsyncRead + AsyncWrite` plaintext stream to `target` |
| Use when | drop-in local proxy for applications | custom DNS, routing rules, direct-vs-proxy choice, in-flight byte middleware |

Both modes share one tunnel builder, so the bytes they put on the wire are
identical. Mode B example:

```rust,no_run
use ssr_client_rs::{CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let client = SsrClient::new(SsrClientConfig {
        server: "example.com".into(),
        server_port: 8388,
        password: "secret".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::AuthAES128SHA1,
        obfs: ObfsType::TLS12TicketAuth,
        ..Default::default()
    });

    // Your front-end decides routing per connection: a `Domain` target is
    // resolved by the SSR server (remote DNS); an `IPv4`/`IPv6` target can
    // be the result of your own resolver. Skip `open_session` entirely for
    // direct (non-proxied) connections.
    let target = TargetAddr::Domain("example.com".into(), 443);
    let mut session = client.open_session(target).await.map_err(std::io::Error::other)?;

    // Bytes here are the target connection's plaintext — wrap the session in
    // any AsyncRead/AsyncWrite middleware to inspect or modify them.
    session.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
    let mut reply = Vec::new();
    session.read_to_end(&mut reply).await?;
    session.finish().await.map_err(std::io::Error::other)?;
    Ok(())
}
```

Mode A (`start()`) binds a port, so `open_session` failure modes and the
SOCKS5 path never overlap; UDP ASSOCIATE is Mode A only.

### Runnable examples

| Example | Shows | Run |
|---|---|---|
| [`examples/socks5.rs`](examples/socks5.rs) | Mode A: SOCKS5 proxy from a JSON config | `cargo run --release --example socks5 -- config.json` |
| [`examples/open_session.rs`](examples/open_session.rs) | Mode B: tunneled connection as a plaintext stream | `cargo run --release --example open_session -- config.json example.com 80` |
| [`examples/config_builder.rs`](examples/config_builder.rs) | Build config both ways, parse names, show errors (offline) | `cargo run --example config_builder` |

The `socks5` entry point also ships as a binary: `ssr-client -c <config.json>`
(`src/bin/ssr_client.rs`).

## Configuration

Full field-by-field reference (plus FAQ and error handling):
[`docs/USAGE.md`](docs/USAGE.md) §5 — 中文版 [`docs/USAGE.zh-CN.md`](docs/USAGE.zh-CN.md).

JSON keys are identical to the `SsrClientConfig` fields
(`config_from_json`, cf. `ssr-n/src/config_json.c`); an optional
`client_settings` object can override the `server*` / `listen*` entries.

| Field / JSON key | Type | Default (`new`) | Meaning |
|---|---|---|---|
| `server` | string | — | remote SSR server host/IP |
| `server_port` | u16 | — | remote SSR server port |
| `listen_address` | string | `127.0.0.1` | local SOCKS5 bind address (`::` = dual-stack IPv6) |
| `listen_port` | u16 | `1080` | local SOCKS5 bind port |
| `password` | string | — | cipher password |
| `method` | `CipherType` | — | cipher name, e.g. `aes-256-cfb` (JSON holds the name; parsed via `from_name`) |
| `protocol` | `ProtocolType` | — | protocol name, e.g. `auth_aes128_sha1` (absent → `Origin`) |
| `protocol_param` | string | `""` | protocol params (`uid:key…`) |
| `obfs` | `ObfsType` | `Plain` | obfs name, e.g. `tls1.2_ticket_auth` (JSON holds the name) |
| `obfs_param` | string | `""` | obfs params (host…); empty = auto |
| `udp` | bool | `false` | enable UDP ASSOCIATE relay |
| `idle_timeout` | u32 | `300` | seconds before an idle TCP tunnel is reclaimed (`0` disables) |
| `connect_timeout` | u32 | `6` | SSR server connect timeout (seconds) |
| `udp_timeout` | u32 | `6` | UDP session idle timeout (seconds) |

All fallible entry points return the single `SsrError` type (`SsrResult<T>`);
the library never panics on the production path (enforced by
`tools/check_panic_paths.sh`).

## Building

```bash
cargo build --release     # [lints.rust] warnings = "deny": any warning fails the build
```

- **MSRV: 1.82** (`rust-version` in `Cargo.toml`)
- Tested on **linux x86_64** (CI) and **linux loongarch64** (Loongson 3A5000)
- CI runs the four gates — fmt / clippy / test / release —
  in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

For the last few percent of cipher throughput, downstream binaries may be
built with `RUSTFLAGS="-C target-cpu=native"` — the library itself does not
pin CPU features.

## Testing

```bash
cargo test                                            # unit + integration (238 tests)
python3 tools/matrix_test.py                          # e2e matrix (needs a local ssr-server)
bash tools/e2e_udp.sh --all                           # UDP e2e
cargo test --test resilience -- --ignored             # interruption/timeout/half-close suite
bash tools/soak_test.sh                               # 10 min stability soak
cargo bench                                           # criterion baselines (see BENCH.md)
```

## Project structure

```
src/
├── lib.rs              # Public API entry (module map, re-exports)
├── config.rs           # SsrClientConfig
├── config_json.rs      # ssr-n JSON config parser
├── error.rs            # SsrError unified error type
├── crypto/             # Encryption (cipher_env, stream, aead, table, bytes_to_key)
├── protocol/           # Protocols (origin … auth_chain_a~f)
├── obfs/               # Obfuscation (plain, http_simple, tls_ticket)
├── socks5/             # SOCKS5 protocol parser
├── relay/              # TCP relay
├── local/              # Local proxy server + UDP relay
└── utils/              # hash, base64, crc32, adler32, sockaddr
benches/                # criterion: cipher throughput, protocol/obfs overhead
examples/socks5.rs      # minimal runnable SOCKS5 proxy example
tools/                  # e2e matrix, soak, fd probes, benchmarks vs the C client
tests/                  # full coverage, proptest, resilience, e2e assets
```

## Performance

See [`BENCH.md`](BENCH.md) ([中文](BENCH.zh-CN.md)) for cipher throughput, per-packet protocol/obfs
overhead, the concurrency curve (1/8/64/100 streams) and the head-to-head
comparison against the C client — every table records date, machine, clock
and methodology.

## License

[GPL-3.0-or-later](LICENSE) — this crate is a port of the `ssr-n` C client
(GPLv3, “version 3 or any later version”); the upstream license applies.
See [CHANGELOG.md](CHANGELOG.md) for release notes and known limitations,
and [docs/USAGE.md](docs/USAGE.md) ([中文](docs/USAGE.zh-CN.md)) for the
full usage guide.
