# Usage Guide — ssr-client-rs

Full usage documentation for the crate. Quick reference lives in
[README.md](../README.md); this page covers everything in depth.
Chinese version: [USAGE.zh-CN.md](USAGE.zh-CN.md).

- [1. Overview](#1-overview)
- [2. Installation](#2-installation)
- [3. Quick start](#3-quick-start)
- [4. Integration modes](#4-integration-modes)
- [5. Configuration reference](#5-configuration-reference)
- [6. Supported algorithms](#6-supported-algorithms)
- [7. Error handling and timeouts](#7-error-handling-and-timeouts)
- [8. UDP relay](#8-udp-relay)
- [9. Examples](#9-examples)
- [10. Performance](#10-performance)
- [11. Testing](#11-testing)
- [12. FAQ](#12-faq)

## 1. Overview

`ssr-client-rs` is a byte-compatible Rust port of the `ssr-n` C
ShadowsocksR client library. Every packet traverses this pipeline:

```
User Data → SOCKS5 → Protocol (pre_encrypt) → Crypto (encrypt) → Obfs (encode) → Server
Server   → Obfs (decode) → Crypto (decrypt) → Protocol (post_decrypt) → User
```

Design guarantees:

- **Zero `unsafe`** in the whole crate.
- **No panics on the production path** — every fallible operation returns
  `SsrResult<T>` (enforced by `tools/check_panic_paths.sh` in CI).
- **Tokio-based async I/O**; `Send` futures throughout, safe to use with
  `rt-multi-thread`.
- **ssr-n JSON config compatible** — the same keys the C client reads.

## 2. Installation

From crates.io (MSRV **1.82**):

```toml
[dependencies]
ssr-client-rs = "0.1"
tokio = { version = "1", features = ["net", "rt-multi-thread", "macros", "io-util", "time", "sync", "signal"] }
```

Or with `cargo add`:

```bash
cargo add ssr-client-rs
```

Bleeding edge (git):

```toml
[dependencies]
ssr-client-rs = { git = "https://cnb.cool/liangzhaoyuan12/ssr-client-rs" }
```

The crate has no default features to configure. Platform support: linux
x86_64 (CI) and linux loongarch64. It is expected to build anywhere Rust +
tokio build, but only those two are tested.

## 3. Quick start

```rust,no_run
use ssr_client_rs::config_json::config_from_json;
use ssr_client_rs::{CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig};

#[tokio::main]
async fn main() {
    // Way 1: ssr-n style JSON config (keys match the struct fields — see §5).
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

    // Way 2: struct literal — all fields public, rest from `Default`.
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

`SsrClient::new` only stores the config: nothing is bound or connected
until you call `start()` (Mode A) or `open_session()` (Mode B).

## 4. Integration modes

| | Mode A — system port (default) | Mode B — data pipe |
|---|---|---|
| API | `client.start()` | `client.open_session(target)` |
| Front side | binds `listen_address:listen_port`, speaks SOCKS5 + UDP ASSOCIATE | none — your own front protocol owns it |
| Back side | handled internally | `AsyncRead + AsyncWrite` plaintext stream to `target` |
| Use when | drop-in local proxy for applications | custom DNS, routing rules, direct-vs-proxy choice, in-flight byte middleware |

Both modes share one tunnel builder, so the bytes they put on the wire are
identical.

### Mode A — SOCKS5 local proxy

`start()` binds the local port and serves SOCKS5 `CONNECT` plus (when
`udp: true`) `UDP ASSOCIATE` until `stop()` is called or the process exits.
Point any SOCKS5-aware application at `127.0.0.1:1080`.

```rust,no_run
# use ssr_client_rs::{SsrClient, SsrClientConfig};
# async fn demo(client: SsrClient) -> ssr_client_rs::SsrResult<()> {
client.start().await?; // binds + serves until stop()
// client.stop();      // from another task/handle
# Ok(())
# }
```

Helper accessors: `client.is_running()` and `client.config()`.

### Mode B — data pipe

`open_session` returns one tunneled TCP connection as a plain plaintext
stream — no local port is bound:

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

    // A `Domain` target is resolved by the SSR server (remote DNS); an
    // `IPv4`/`IPv6` target can be the result of your own resolver.
    let target = TargetAddr::Domain("example.com".into(), 443);
    let mut session = client.open_session(target).await.map_err(std::io::Error::other)?;

    // Plaintext bytes — wrap the session in any AsyncRead/AsyncWrite middleware.
    session.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
    let mut reply = Vec::new();
    session.read_to_end(&mut reply).await?;
    session.finish().await.map_err(std::io::Error::other)?;
    Ok(())
}
```

Session lifecycle:

- Reads/writes carry the target connection's **plaintext**; framing,
  encryption and obfuscation run in a background pump.
- Split it with `tokio::io::split`, or wrap it in any
  `AsyncRead + AsyncWrite` middleware (logging, metering, TLS, …).
- Call `finish()` for a graceful close (drains the server side and
  returns any mid-stream relay error). Dropping the session aborts instead.
- `open_session` failure modes: unreachable server / handshake timeout
  (`connect_timeout`), or cipher/protocol/obfs construction failure — all
  surfaced as `SsrError`.

Mode A's SOCKS5 parsing and UDP ASSOCIATE never overlap with Mode B.

## 5. Configuration reference

JSON keys are identical to the `SsrClientConfig` fields
(`config_from_json`, cf. upstream `ssr-n` `src/config_json.c`); an optional
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

Notes:

- `config_from_json` returns `Result<SsrClientConfig, String>` (JSON parse /
  key errors are plain strings); everything else returns `SsrResult<T>`.
- Enum-valued fields accept the ssr-n wire names — parse them yourself with
  `CipherType::from_name` / `ProtocolType::from_name` / `ObfsType::from_name`
  when building configs programmatically (see
  [examples/config_builder.rs](../examples/config_builder.rs)).
- `SsrClientConfig` implements `Debug + Clone`; use `{:?}` to log the
  effective configuration.

## 6. Supported algorithms

Latest full e2e matrix: [`tests/e2e/RESULTS.md`](../tests/e2e/RESULTS.md)
— **39/51 PASS + 12 SKIP, 0 FAIL** against the reference `ssr-n` server.

### Ciphers (28 names parsed, 21 implemented)

| Group | Methods |
|---|---|
| AES stream | `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb`, `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr` |
| AES AEAD | `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm` |
| ChaCha/Salsa | `chacha20`, `chacha20-ietf`, `salsa20` |
| ChaCha AEAD | `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305` |
| Classic | `rc4`, `rc4-md5`, `rc4-md5-6`, `bf-cfb`, `des-cfb` |
| Misc | `table`, `none` |
| parsed, not implemented | `camellia-128/192/256-cfb`, `cast5-cfb`, `idea-cfb`, `rc2-cfb`, `seed-cfb` |

Not-implemented names fail fast with `SsrError::InvalidCipherMethod` at
environment construction — never silently downgraded. Several of them
(`cast5`, `idea`, `rc2`, `seed`, `des-cfb`) are also rejected by the
reference server itself.

### Protocols (14)

`origin`, `verify_simple`, `auth_simple`, `auth_sha1`, `auth_sha1_v2`,
`auth_sha1_v4`, `auth_aes128_md5`, `auth_aes128_sha1`, `auth_chain_a`,
`auth_chain_b`, `auth_chain_c`, `auth_chain_d`, `auth_chain_e`,
`auth_chain_f`.

The four `verify_simple`/`auth_simple`/`auth_sha1`/`auth_sha1_v2` variants
skip in e2e only because the reference server registers no
`server_post_decrypt` for them (the C client fails the same way); the
client-side implementation is present.

### Obfuscation (6, all e2e-verified)

`plain`, `http_simple`, `http_post`, `http_mix`, `tls1.2_ticket_auth`,
`tls1.2_ticket_fastauth`.

### AEAD downgrade rule

When `method` is an AEAD cipher, the tunnel is forced to `plain` obfs +
`origin` protocol on the wire (mirroring `ssr_executive.c:175-179`); your
`protocol`/`obfs` settings are then irrelevant for that connection. This is
by design, not a bug.

## 7. Error handling and timeouts

All fallible entry points return the single `SsrError` type
(`SsrResult<T> = Result<T, SsrError>`), which implements `Display` +
`std::error::Error` (via `thiserror`):

| Variant | Raised when |
|---|---|
| `Io` | underlying socket/file IO failed (wraps `std::io::Error`, `#[from]`) |
| `InvalidCipherMethod` / `InvalidProtocol` / `InvalidObfs` | unknown or unimplemented algorithm name |
| `Crypto` | encrypt/decrypt/key-derivation failed |
| `Protocol` | SSR protocol handshake or frame encode/decode failed |
| `Obfs` | obfuscation encode/decode or handshake failed |
| `Connection` | listen/connect/send/recv/relay-pump failure |
| `Socks5` | malformed SOCKS5 input or unsupported command/address type |
| `Timeout` | `connect_timeout` / `idle_timeout` / handshake deadline exceeded |
| `InvalidArgument` | caller-supplied value out of range or unknown |
| `Other` | everything else |

Timeout semantics:

- `connect_timeout` (default 6 s): dialing the SSR server and the obfs
  handshake deadline.
- `idle_timeout` (default 300 s): an idle TCP tunnel is reclaimed after
  this many seconds; `0` disables reclamation.
- `udp_timeout` (default 6 s): per-session UDP state expiry.

Match on the variant when you need to react differently (e.g. retry on
`Timeout`/`Connection`, treat `InvalidCipherMethod` as a config bug):

```rust,no_run
use ssr_client_rs::{CipherType, SsrError};

match CipherType::from_name("nope") {
    Ok(_) => unreachable!(),
    Err(e @ SsrError::InvalidCipherMethod(_)) => eprintln!("config bug: {e}"),
    Err(e) => eprintln!("other: {e}"),
}
```

## 8. UDP relay

SOCKS5 `UDP ASSOCIATE` is **Mode A only** and requires `"udp": true`:

1. Enable it in the config (`udp: true`, plus `udp_timeout` if the default
   6 s does not fit).
2. Start the proxy (`client.start()`).
3. Configure the application's SOCKS5 proxy with UDP support; datagrams are
   encapsulated through the SSR server and demultiplexed per session, with
   idle state dropped after `udp_timeout`.

UDP e2e coverage: `bash tools/e2e_udp.sh --all` (3/3 combos PASS).

## 9. Examples

| Example | What it shows | Run |
|---|---|---|
| [examples/socks5.rs](../examples/socks5.rs) | Mode A: full SOCKS5 local proxy from a JSON config, graceful `stop()` on Ctrl-C | `cargo run --release --example socks5 -- config.json` |
| [examples/open_session.rs](../examples/open_session.rs) | Mode B: one tunneled connection as a plaintext stream — HTTP GET through the tunnel, graceful `finish()` | `cargo run --release --example open_session -- config.json example.com 80` |
| [examples/config_builder.rs](../examples/config_builder.rs) | Building config both ways, name↔enum parsing, `SsrError` Display — runs offline, no server needed | `cargo run --example config_builder` |

The same entry point as `socks5.rs` ships as a binary:

```bash
cargo run --release --bin ssr_client -- -c config.json
```

## 10. Performance

- For the last few percent of cipher throughput, downstream binaries may be
  built with `RUSTFLAGS="-C target-cpu=native"` — the library itself does
  not pin CPU features.
- Micro-benchmarks (4 criterion targets):

```bash
cargo bench -- --noplot
# individually, e.g.:
cargo bench --bench cipher_throughput -- --noplot
cargo bench --bench protocol_overhead -- --noplot
cargo bench --bench obfs_overhead -- --noplot
cargo bench --bench session_setup -- --noplot   # per-connection setup cost
```

- Measured numbers — cipher throughput, per-packet protocol/obfs overhead,
  session-setup cost, head-to-head vs the C client and the concurrency
  curve — all live in [`BENCH.md`](../BENCH.md) ([中文](../BENCH.zh-CN.md)),
  each table recording date, machine, clock and methodology.

Release profile used for benches: `opt-level = 3`, `lto = "thin"`,
`codegen-units = 1`.

## 11. Testing

```bash
cargo test                                            # unit + integration
python3 tools/matrix_test.py                          # e2e matrix (needs a local ssr-server)
bash tools/e2e_udp.sh --all                           # UDP e2e
cargo test --test resilience -- --ignored             # interruption/timeout/half-close suite
bash tools/soak_test.sh                               # 10 min stability soak
bash tools/fd_leak_test.sh                            # fd leak probe
cargo doc --no-deps                                   # API docs locally (docs.rs-compatible)
```

CI (`.github/workflows/ci.yml`) runs four gates: fmt / clippy / test /
release build, with `[lints.rust] warnings = "deny"` — any warning fails.

## 12. FAQ

**Q: How do I connect?** Same three values as the C client: `method`,
`protocol` (+ `protocol_param`), `obfs` (+ `obfs_param`) must match the
server. Start from the server's config and copy them.

**Q: AEAD cipher (`aes-256-gcm`…) ignores my protocol/obfs setting?**
Not a bug — see [§6 AEAD downgrade rule](#aead-downgrade-rule).

**Q: Can I run without a local SOCKS5 port?** Yes — Mode B,
`open_session()` (§4).

**Q: Who resolves the hostname?** `TargetAddr::Domain` → the SSR server
(remote DNS, hides DNS from the local network). `TargetAddr::IPv4/IPv6`
→ whatever your resolver already produced.

**Q: Does it panic?** Not on the production path; every failure is an
`SsrError`. `unwrap`/`panic!` exist only in tests, benches and examples.

**Q: `start()` fails with "Address already in use"?** Something else owns
`listen_address:listen_port`. Change `listen_port` or stop the other proxy.

**Q: Connection succeeds locally but the server drops it?** Password /
method / protocol / obfs mismatch with the server, or the server rejects
that cipher (some names are rejected server-side too — see §6).

**Q: Where does the license come from?** GPL-3.0-or-later: the crate is a
port of the `ssr-n` C client (GPLv3+), and the upstream license applies.

## See also

- [README.md](../README.md) — quick reference / [中文](../README.zh-CN.md)
- [BENCH.md](../BENCH.md) — performance report / [中文](../BENCH.zh-CN.md)
- [CHANGELOG.md](../CHANGELOG.md) — release notes, compatibility promise
- [tests/e2e/RESULTS.md](../tests/e2e/RESULTS.md) — full e2e matrix results
- API documentation on docs.rs (once published)
