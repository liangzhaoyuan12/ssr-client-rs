pub mod config;
pub mod crypto;
pub mod error;
pub mod local;
pub mod obfs;
pub mod protocol;
pub mod relay;
pub mod socks5;
pub mod utils;

// Re-export key types
pub use config::SsrClientConfig;
pub use crypto::{CipherType, ObfsType, ProtocolType, TargetAddr};
pub use error::{SsrError, SsrResult};
pub use local::SsrClient;
pub use relay::TcpRelay;
pub use socks5::{
    ConnectRequest, MethodNegotiation, TargetAddress, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6,
    CMD_BIND, CMD_CONNECT, CMD_UDP_ASSOCIATE,
};
