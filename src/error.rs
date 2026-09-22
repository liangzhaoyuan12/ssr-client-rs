/// SSR client unified error type
#[derive(Debug, thiserror::Error)]
pub enum SsrError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid cipher method
    #[error("Invalid cipher method: {0}")]
    InvalidCipherMethod(String),

    /// Invalid protocol name
    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),

    /// Invalid obfs name
    #[error("Invalid obfs: {0}")]
    InvalidObfs(String),

    /// Encryption/decryption error
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Protocol handshake error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// SOCKS5 error
    #[error("SOCKS5 error: {0}")]
    Socks5(String),

    /// Timeout
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Invalid data/argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Obfs error
    #[error("Obfs error: {0}")]
    Obfs(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl SsrError {
    /// Build [`SsrError::Crypto`]: encryption, decryption or key derivation failed.
    pub fn crypto(msg: impl Into<String>) -> Self {
        SsrError::Crypto(msg.into())
    }

    /// Build [`SsrError::Protocol`]: an SSR protocol handshake or encode/decode step failed.
    pub fn protocol(msg: impl Into<String>) -> Self {
        SsrError::Protocol(msg.into())
    }

    /// Build [`SsrError::Connection`]: listen, connect, send/recv or address resolution failed.
    pub fn connection(msg: impl Into<String>) -> Self {
        SsrError::Connection(msg.into())
    }

    /// Build [`SsrError::Socks5`]: malformed SOCKS5 input or an unsupported command/address type.
    pub fn socks5(msg: impl Into<String>) -> Self {
        SsrError::Socks5(msg.into())
    }

    /// Build [`SsrError::InvalidArgument`]: a caller-supplied value is out of range or unknown.
    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        SsrError::InvalidArgument(msg.into())
    }

    /// Build [`SsrError::Other`]: a failure that fits no other variant.
    pub fn other(msg: impl Into<String>) -> Self {
        SsrError::Other(msg.into())
    }
}

/// Result type alias for SSR operations
pub type SsrResult<T> = Result<T, SsrError>;
