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

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl SsrError {
    pub fn crypto(msg: impl Into<String>) -> Self {
        SsrError::Crypto(msg.into())
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        SsrError::Protocol(msg.into())
    }

    pub fn connection(msg: impl Into<String>) -> Self {
        SsrError::Connection(msg.into())
    }

    pub fn socks5(msg: impl Into<String>) -> Self {
        SsrError::Socks5(msg.into())
    }

    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        SsrError::InvalidArgument(msg.into())
    }

    pub fn other(msg: impl Into<String>) -> Self {
        SsrError::Other(msg.into())
    }
}

/// Result type alias for SSR operations
pub type SsrResult<T> = Result<T, SsrError>;
