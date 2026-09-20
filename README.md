# ssr-client-rs

A Rust client library for ShadowsocksR (SSR-N) protocol, providing encryption, protocol, obfuscation, and transport layers.

## Features

- **28 encryption methods**: AES, ChaCha20, Salsa20, Blowfish, DES, RC4, etc.
- **14 protocols**: origin, verify_simple, auth_simple, auth_sha1/v2/v4, auth_aes128, auth_chain_a~f
- **6 obfuscation methods**: plain, http_simple/post/mix, tls1.2_ticket_auth/fastauth
- **Async I/O**: tokio-based TCP/UDP relay
- **SOCKS5 proxy**: local SOCKS5 server for transparent proxying

## Architecture

```
User Data → SOCKS5 → Protocol (pre_encrypt) → Crypto (encrypt) → Obfs (encode) → Server
Server   → Obfs (decode) → Crypto (decrypt) → Protocol (post_decrypt) → User
```

## Usage

```rust
use ssr_client_rs::{SsrClientConfig, SsrClient};

let config = SsrClientConfig {
    server: "example.com".into(),
    server_port: 8388,
    listen_address: "127.0.0.1".into(),
    listen_port: 1080,
    password: "mypassword".into(),
    method: "aes-256-cfb".into(),
    protocol: "auth_aes128_sha1".into(),
    protocol_param: "".into(),
    obfs: "tls1.2_ticket_auth".into(),
    obfs_param: "".into(),
    udp: false,
    idle_timeout: 600,
    connect_timeout: 600,
    udp_timeout: 600,
};

let client = SsrClient::new(config).unwrap();
// client.start().await.unwrap();
```

## Project Structure

```
src/
├── lib.rs              # Public API entry
├── config.rs           # SsrClientConfig
├── error.rs            # SsrError unified error type
├── crypto/             # Encryption layer
│   ├── cipher_env.rs   # CipherEnv - unified cipher environment
│   ├── stream.rs       # Stream ciphers (CFB/CTR/RC4/Salsa20/ChaCha20)
│   ├── aead.rs         # AEAD ciphers (GCM/Poly1305)
│   ├── table.rs        # Table cipher
│   └── bytes_to_key.rs # EVP_BytesToKey key derivation
├── protocol/           # Protocol layer
│   ├── mod.rs          # Protocol trait + utilities
│   ├── origin.rs       # Origin (pass-through)
│   ├── verify_simple.rs
│   ├── auth_simple.rs
│   ├── auth_sha1.rs
│   ├── auth_sha1_v2.rs
│   ├── auth_sha1_v4.rs
│   ├── auth_aes128.rs
│   └── auth_chain.rs   # auth_chain_a~f
├── obfs/               # Obfuscation layer
│   ├── mod.rs          # Obfs trait
│   ├── plain.rs
│   ├── http_simple.rs
│   └── tls_ticket.rs
├── socks5/             # SOCKS5 protocol parser
├── relay/              # TCP/UDP relay
├── local/              # Local proxy server
└── utils/              # Utilities (hash, base64, crc32, adler32, buffer)
```

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## License

MIT
