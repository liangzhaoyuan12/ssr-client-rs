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
    /// Encryption method name (e.g. "aes-256-cfb")
    pub method: String,
    /// Protocol name (e.g. "auth_aes128_sha1")
    pub protocol: String,
    /// Protocol parameters
    pub protocol_param: String,
    /// Obfuscation name (e.g. "tls1.2_ticket_auth")
    pub obfs: String,
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

impl SsrClientConfig {
    /// Create a new config with the given server address, port, password, method, protocol, and obfs.
    pub fn new(
        server: impl Into<String>,
        server_port: u16,
        password: impl Into<String>,
        method: impl Into<String>,
        protocol: impl Into<String>,
        obfs: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            server_port,
            listen_address: "127.0.0.1".to_string(),
            listen_port: 1080,
            password: password.into(),
            method: method.into(),
            protocol: protocol.into(),
            protocol_param: String::new(),
            obfs: obfs.into(),
            obfs_param: String::new(),
            udp: false,
            idle_timeout: 300,
            connect_timeout: 6,
            udp_timeout: 6,
        }
    }

    /// Create a default config for testing (from hk.json values).
    pub fn default_test() -> Self {
        Self {
            server: "192.0.2.1".to_string(),
            server_port: 2800,
            listen_address: "0.0.0.0".to_string(),
            listen_port: 1080,
            password: "test-password".to_string(),
            method: "aes-256-cfb".to_string(),
            protocol: "auth_aes128_sha1".to_string(),
            protocol_param: String::new(),
            obfs: "tls1.2_ticket_auth".to_string(),
            obfs_param: String::new(),
            udp: true,
            idle_timeout: 300,
            connect_timeout: 6,
            udp_timeout: 6,
        }
    }
}
