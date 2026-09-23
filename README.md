# ssr-client-rs

[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-blue.svg)](https://blog.rust-lang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86__64%20%7C%20loongarch64-lightgrey.svg)](#building)

A byte-compatible Rust client library for the ShadowsocksR (SSR-N) protocol,
providing the encryption, protocol, obfuscation and transport layers plus a
SOCKS5 local proxy. Verified against the reference `ssr-n` C server
(including the production server behind `hk.json`).

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
(head-to-head vs the C client: **103% of its throughput at 0.80× its CPU**,
concurrency curve, cipher/protocol/obfs tables).

## Quick start

### As a library

```toml
[dependencies]
ssr-client-rs = { git = "https://cnb.cool/liangzhaoyuan12/ssr-client-rs" }
tokio = { version = "1", features = ["full"] }
```

```rust,no_run
use ssr_client_rs::config_json::config_from_json;
use ssr_client_rs::{SsrClient, SsrClientConfig};

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

    // Option B: build it programmatically.
    let _config2 = SsrClientConfig::new(
        "example.com", 8388, "secret",
        "aes-256-cfb", "auth_aes128_sha1", "tls1.2_ticket_auth",
    );

    let client = SsrClient::new(config);
    client.start().await.expect("SOCKS5 listener + relay");
}
```

### Runnable example

[`examples/socks5.rs`](examples/socks5.rs) starts a SOCKS5 proxy from a JSON
config path:

```bash
cargo run --release --example socks5 hk.json   # point clients at 127.0.0.1:1080
```

The same entry point ships as a binary: `ssr-client -c <config.json>`
(`src/bin/ssr_client.rs`).

## Configuration

JSON keys are identical to the `SsrClientConfig` fields
(`config_from_json`, cf. `ssr-n/src/config_json.c`); an optional
`client_settings` object can override the `server*` / `listen*` entries.

| Field / JSON key | Type | Default (`new`) | Meaning |
|---|---|---|---|
| `server` | string | — | remote SSR server host/IP |
| `server_port` | u16 | — | remote SSR server port |
| `listen_address` | string | `127.0.0.1` | local SOCKS5 bind address |
| `listen_port` | u16 | `1080` | local SOCKS5 bind port |
| `password` | string | — | cipher password |
| `method` | string | — | cipher name, e.g. `aes-256-cfb` |
| `protocol` | string | — | protocol name, e.g. `auth_aes128_sha1` |
| `protocol_param` | string | `""` | protocol params (`uid:key…`) |
| `obfs` | string | — | obfs name, e.g. `tls1.2_ticket_auth` |
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

See [`BENCH.md`](BENCH.md) for cipher throughput, per-packet protocol/obfs
overhead, the concurrency curve (1/8/64/100 streams) and the head-to-head
comparison against the C client — every table records date, machine, clock
and methodology.

## License

[GPL-3.0-or-later](LICENSE) — this crate is a port of the `ssr-n` C client
(GPLv3, “version 3 or any later version”); the upstream license applies.
See [CHANGELOG.md](CHANGELOG.md) for release notes and known limitations.
