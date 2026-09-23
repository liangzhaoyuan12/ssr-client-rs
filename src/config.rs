use crate::crypto::{CipherType, ObfsType, ProtocolType};

/// SSR client configuration.
///
/// Construct directly, or load from an ssr-n style JSON file via
/// [`crate::config_json::config_from_json`].
#[derive(Debug, Clone)]
pub struct SsrClientConfig {
    /// Remote server address
    pub server: String,
    /// Remote server port
    pub server_port: u16,
    /// Local listen address
    pub listen_address: String,
    /// Local SOCKS5 listen port
    pub listen_port: u16,
    /// Encryption password
    pub password: String,
    /// Encryption method (e.g. `CipherType::AES256CFB` for `aes-256-cfb`)
    pub method: CipherType,
    /// Protocol (e.g. `ProtocolType::AuthAES128SHA1`)
    pub protocol: ProtocolType,
    /// Protocol parameters
    pub protocol_param: String,
    /// Obfuscation (e.g. `ObfsType::TLS12TicketAuth`)
    pub obfs: ObfsType,
    /// Obfuscation parameters
    pub obfs_param: String,
    /// Whether to enable UDP relay
    pub udp: bool,
    /// Connection idle timeout in seconds
    pub idle_timeout: u32,
    /// Connection timeout in seconds
    pub connect_timeout: u32,
    /// UDP timeout in seconds
    pub udp_timeout: u32,
}

/// Sensible defaults for every field: loopback SOCKS5 on 1080, empty
/// credentials, 300s idle / 6s connect / 6s UDP timeouts.
///
/// Build a config as a struct literal with `..Default::default()`:
///
/// ```ignore
/// SsrClientConfig { server: "srv".into(), server_port: 8388, ..Default::default() }
/// ```
impl Default for SsrClientConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            server_port: 0,
            listen_address: "127.0.0.1".to_string(),
            listen_port: 1080,
            password: String::new(),
            method: CipherType::None,
            protocol: ProtocolType::Origin,
            protocol_param: String::new(),
            obfs: ObfsType::Plain,
            obfs_param: String::new(),
            udp: false,
            idle_timeout: 300,
            connect_timeout: 6,
            udp_timeout: 6,
        }
    }
}

impl SsrClientConfig {
    /// Create a default config for testing (from hk.json values).
    pub fn default_test() -> Self {
        Self {
            server: "192.0.2.1".to_string(),
            server_port: 2800,
            listen_address: "0.0.0.0".to_string(),
            listen_port: 1080,
            password: "test-password".to_string(),
            method: CipherType::AES256CFB,
            protocol: ProtocolType::AuthAES128SHA1,
            protocol_param: String::new(),
            obfs: ObfsType::TLS12TicketAuth,
            obfs_param: String::new(),
            udp: true,
            idle_timeout: 300,
            connect_timeout: 6,
            udp_timeout: 6,
        }
    }
}
