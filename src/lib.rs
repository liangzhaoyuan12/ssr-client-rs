//! Byte-compatible Rust port of the ssr-n C ShadowsocksR client library.
//!
//! Module layout: `protocol` (SSR protocol obfuscation), `obfs` (transport
//! obfuscation), `crypto` (ciphers/AEAD), `local` (client entry points and
//! relays), with `socks5`, `config`, `config_json`, `relay`, `error`, `log`
//! and `utils` in support. Configuration is read from ssr-n-style JSON
//! files (see `config_json`, mirroring `ssr-n/src/config_json.c`).
#![warn(missing_docs)]
/// Client configuration: `SsrClientConfig` and its builders/defaults.
pub mod config;
/// Minimal JSON parser and ssr-n config loader (mirrors `ssr-n/src/config_json.c`).
pub mod config_json;
#[macro_use]
/// Logging macros used throughout the crate (`log_info!`, `log_debug!`, ...).
pub mod log;
/// Ciphers and key derivation: stream ciphers, AEAD, cipher/protocol/obfs types.
pub mod crypto;
/// Unified error type `SsrError` and the `SsrResult` alias.
pub mod error;
/// Client-side entry points: the SSR client, TCP relay and UDP relay.
pub mod local;
/// Transport obfuscation: plain, HTTP simple variants and TLS 1.2 tickets.
pub mod obfs;
/// SSR protocol plugins (auth_simple, auth_sha1*, auth_chain*, verify_simple).
pub mod protocol;
/// TCP relay loop between the local SOCKS5 listener and the SSR server.
pub mod relay;
/// SOCKS5 (RFC 1928) request parsing, reply building and UDP datagram framing.
pub mod socks5;
/// Small utilities: Adler-32, base64, byte buffers, CRC32, hashing, sockaddr.
pub mod utils;

// Re-export key types
/// The main client configuration struct.
pub use config::SsrClientConfig;
/// Cipher, protocol, obfs and target-address enums.
pub use crypto::{CipherType, ObfsType, ProtocolType, TargetAddr};
/// The crate-wide error type and result alias.
pub use error::{SsrError, SsrResult};
/// The top-level SSR client facade.
pub use local::{SsrClient, SsrSession};
/// The TCP relay that drives one accepted connection.
pub use relay::TcpRelay;
/// SOCKS5 wire types and RFC 1928 command/address constants.
pub use socks5::{
    ConnectRequest, MethodNegotiation, TargetAddress, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_BIND,
    CMD_CONNECT, CMD_UDP_ASSOCIATE,
};
