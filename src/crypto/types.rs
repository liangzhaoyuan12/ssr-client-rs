use crate::error::{SsrError, SsrResult};

/// Encryption method type (28 methods)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherType {
    None,           // 0
    Table,          // 1
    RC4,            // 2
    RC4Md56,        // 3: rc4-md5-6
    RC4Md5,         // 4: rc4-md5
    AES128CFB,      // 5
    AES192CFB,      // 6
    AES256CFB,      // 7
    AES128CTR,      // 8
    AES192CTR,      // 9
    AES256CTR,      // 10
    BFCFB,          // 11: bf-cfb (Blowfish)
    Camellia128CFB, // 12
    Camellia192CFB, // 13
    Camellia256CFB, // 14
    CAST5CFB,       // 15
    DESCFB,         // 16
    IDEACFB,        // 17
    RC2CFB,         // 18
    SeedCFB,        // 19
    Salsa20,        // 20
    ChaCha20,       // 21
    ChaCha20IETF,   // 22
    AES128GCM,      // 23
    AES192GCM,      // 24
    AES256GCM,      // 25
    ChaCha20Poly1305IETF, // 26
    XChaCha20Poly1305IETF, // 27
}

impl CipherType {
    /// Parse cipher method name string to CipherType
    pub fn from_name(name: &str) -> SsrResult<Self> {
        match name {
            "none" => Ok(Self::None),
            "table" => Ok(Self::Table),
            "rc4" => Ok(Self::RC4),
            "rc4-md5-6" => Ok(Self::RC4Md56),
            "rc4-md5" => Ok(Self::RC4Md5),
            "aes-128-cfb" => Ok(Self::AES128CFB),
            "aes-192-cfb" => Ok(Self::AES192CFB),
            "aes-256-cfb" => Ok(Self::AES256CFB),
            "aes-128-ctr" => Ok(Self::AES128CTR),
            "aes-192-ctr" => Ok(Self::AES192CTR),
            "aes-256-ctr" => Ok(Self::AES256CTR),
            "bf-cfb" => Ok(Self::BFCFB),
            "camellia-128-cfb" => Ok(Self::Camellia128CFB),
            "camellia-192-cfb" => Ok(Self::Camellia192CFB),
            "camellia-256-cfb" => Ok(Self::Camellia256CFB),
            "cast5-cfb" => Ok(Self::CAST5CFB),
            "des-cfb" => Ok(Self::DESCFB),
            "idea-cfb" => Ok(Self::IDEACFB),
            "rc2-cfb" => Ok(Self::RC2CFB),
            "seed-cfb" => Ok(Self::SeedCFB),
            "salsa20" => Ok(Self::Salsa20),
            "chacha20" => Ok(Self::ChaCha20),
            "chacha20-ietf" => Ok(Self::ChaCha20IETF),
            "aes-128-gcm" => Ok(Self::AES128GCM),
            "aes-192-gcm" => Ok(Self::AES192GCM),
            "aes-256-gcm" => Ok(Self::AES256GCM),
            "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305IETF),
            "xchacha20-ietf-poly1305" => Ok(Self::XChaCha20Poly1305IETF),
            _ => Err(SsrError::InvalidCipherMethod(name.to_string())),
        }
    }

    /// Get the name of the cipher method
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Table => "table",
            Self::RC4 => "rc4",
            Self::RC4Md56 => "rc4-md5-6",
            Self::RC4Md5 => "rc4-md5",
            Self::AES128CFB => "aes-128-cfb",
            Self::AES192CFB => "aes-192-cfb",
            Self::AES256CFB => "aes-256-cfb",
            Self::AES128CTR => "aes-128-ctr",
            Self::AES192CTR => "aes-192-ctr",
            Self::AES256CTR => "aes-256-ctr",
            Self::BFCFB => "bf-cfb",
            Self::Camellia128CFB => "camellia-128-cfb",
            Self::Camellia192CFB => "camellia-192-cfb",
            Self::Camellia256CFB => "camellia-256-cfb",
            Self::CAST5CFB => "cast5-cfb",
            Self::DESCFB => "des-cfb",
            Self::IDEACFB => "idea-cfb",
            Self::RC2CFB => "rc2-cfb",
            Self::SeedCFB => "seed-cfb",
            Self::Salsa20 => "salsa20",
            Self::ChaCha20 => "chacha20",
            Self::ChaCha20IETF => "chacha20-ietf",
            Self::AES128GCM => "aes-128-gcm",
            Self::AES192GCM => "aes-192-gcm",
            Self::AES256GCM => "aes-256-gcm",
            Self::ChaCha20Poly1305IETF => "chacha20-ietf-poly1305",
            Self::XChaCha20Poly1305IETF => "xchacha20-ietf-poly1305",
        }
    }

    /// Get IV size for this cipher
    pub fn iv_size(&self) -> usize {
        match self {
            Self::None | Self::RC4 | Self::RC4Md56 | Self::RC4Md5 => 0,
            Self::Table => 0,
            Self::AES128CFB | Self::AES128CTR => 16,
            Self::AES192CFB | Self::AES192CTR => 16,
            Self::AES256CFB | Self::AES256CTR => 16,
            Self::BFCFB => 8,
            Self::Camellia128CFB => 16,
            Self::Camellia192CFB => 16,
            Self::Camellia256CFB => 16,
            Self::CAST5CFB => 8,
            Self::DESCFB => 8,
            Self::IDEACFB => 8,
            Self::RC2CFB => 8,
            Self::SeedCFB => 16,
            Self::Salsa20 => 8,
            Self::ChaCha20 => 8, // SSR original ChaCha20 uses 8-byte IV; padded to 12 for crate
            Self::ChaCha20IETF => 12,
            // AEAD: IV is handled differently (nonce)
            Self::AES128GCM | Self::AES192GCM | Self::AES256GCM => 0,
            Self::ChaCha20Poly1305IETF => 0,
            Self::XChaCha20Poly1305IETF => 0,
        }
    }

    /// Get key size for this cipher
    pub fn key_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Table => 16,
            Self::RC4 | Self::RC4Md56 | Self::RC4Md5 => 16,
            Self::AES128CFB | Self::AES128CTR => 16,
            Self::AES192CFB | Self::AES192CTR => 24,
            Self::AES256CFB | Self::AES256CTR => 32,
            Self::BFCFB => 16,
            Self::Camellia128CFB => 16,
            Self::Camellia192CFB => 24,
            Self::Camellia256CFB => 32,
            Self::CAST5CFB => 16,
            Self::DESCFB => 8,
            Self::IDEACFB => 16,
            Self::RC2CFB => 16,
            Self::SeedCFB => 16,
            Self::Salsa20 => 32,
            Self::ChaCha20 => 32,
            Self::ChaCha20IETF => 32,
            // AEAD: key derivation is different
            Self::AES128GCM => 16,
            Self::AES192GCM => 24,
            Self::AES256GCM => 32,
            Self::ChaCha20Poly1305IETF => 32,
            Self::XChaCha20Poly1305IETF => 32,
        }
    }

    /// Get tag size for AEAD ciphers (0 for stream ciphers)
    pub fn tag_size(&self) -> usize {
        match self {
            Self::AES128GCM | Self::AES192GCM | Self::AES256GCM => 16,
            Self::ChaCha20Poly1305IETF => 16,
            Self::XChaCha20Poly1305IETF => 16,
            _ => 0,
        }
    }

    /// Get nonce size for AEAD ciphers
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::AES128GCM | Self::AES192GCM | Self::AES256GCM => 12,
            Self::ChaCha20Poly1305IETF => 12,
            Self::XChaCha20Poly1305IETF => 24,
            _ => 0,
        }
    }

    /// Whether this is an AEAD cipher
    pub fn is_aead(&self) -> bool {
        matches!(
            self,
            Self::AES128GCM
                | Self::AES192GCM
                | Self::AES256GCM
                | Self::ChaCha20Poly1305IETF
                | Self::XChaCha20Poly1305IETF
        )
    }

    /// Whether this cipher needs the IV mixed into key derivation
    pub fn need_iv(&self) -> bool {
        self.iv_size() > 0 && !self.is_aead()
    }
}

/// Protocol type (14 methods)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Origin,         // 0
    VerifySimple,   // 1
    AuthSimple,     // 3
    AuthSHA1,       // 4
    AuthSHA1V2,     // 5
    AuthSHA1V4,     // 6
    AuthAES128MD5,  // 7
    AuthAES128SHA1, // 8
    AuthChainA,     // 9
    AuthChainB,     // 10
    AuthChainC,     // 11
    AuthChainD,     // 12
    AuthChainE,     // 13
    AuthChainF,     // 14
}

impl ProtocolType {
    /// Parse protocol name string to ProtocolType
    pub fn from_name(name: &str) -> SsrResult<Self> {
        match name {
            "origin" => Ok(Self::Origin),
            "verify_simple" => Ok(Self::VerifySimple),
            "auth_simple" => Ok(Self::AuthSimple),
            "auth_sha1" => Ok(Self::AuthSHA1),
            "auth_sha1_v2" => Ok(Self::AuthSHA1V2),
            "auth_sha1_v4" => Ok(Self::AuthSHA1V4),
            "auth_aes128_md5" => Ok(Self::AuthAES128MD5),
            "auth_aes128_sha1" => Ok(Self::AuthAES128SHA1),
            "auth_chain_a" => Ok(Self::AuthChainA),
            "auth_chain_b" => Ok(Self::AuthChainB),
            "auth_chain_c" => Ok(Self::AuthChainC),
            "auth_chain_d" => Ok(Self::AuthChainD),
            "auth_chain_e" => Ok(Self::AuthChainE),
            "auth_chain_f" => Ok(Self::AuthChainF),
            _ => Err(SsrError::InvalidProtocol(name.to_string())),
        }
    }

    /// Get the name of the protocol
    pub fn name(&self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::VerifySimple => "verify_simple",
            Self::AuthSimple => "auth_simple",
            Self::AuthSHA1 => "auth_sha1",
            Self::AuthSHA1V2 => "auth_sha1_v2",
            Self::AuthSHA1V4 => "auth_sha1_v4",
            Self::AuthAES128MD5 => "auth_aes128_md5",
            Self::AuthAES128SHA1 => "auth_aes128_sha1",
            Self::AuthChainA => "auth_chain_a",
            Self::AuthChainB => "auth_chain_b",
            Self::AuthChainC => "auth_chain_c",
            Self::AuthChainD => "auth_chain_d",
            Self::AuthChainE => "auth_chain_e",
            Self::AuthChainF => "auth_chain_f",
        }
    }
}

/// Obfuscation type (6 methods)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObfsType {
    Plain,              // 0
    HTTPSimple,         // 1
    HTTPPost,           // 2
    HTTPMix,            // 3
    TLS12TicketAuth,    // 4
    TLS12TicketFastAuth, // 5
}

impl ObfsType {
    /// Parse obfs name string to ObfsType
    pub fn from_name(name: &str) -> SsrResult<Self> {
        match name {
            "plain" => Ok(Self::Plain),
            "http_simple" => Ok(Self::HTTPSimple),
            "http_post" => Ok(Self::HTTPPost),
            "http_mix" => Ok(Self::HTTPMix),
            "tls1.2_ticket_auth" => Ok(Self::TLS12TicketAuth),
            "tls1.2_ticket_fastauth" => Ok(Self::TLS12TicketFastAuth),
            _ => Err(SsrError::InvalidObfs(name.to_string())),
        }
    }

    /// Get the name of the obfuscation
    pub fn name(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::HTTPSimple => "http_simple",
            Self::HTTPPost => "http_post",
            Self::HTTPMix => "http_mix",
            Self::TLS12TicketAuth => "tls1.2_ticket_auth",
            Self::TLS12TicketFastAuth => "tls1.2_ticket_fastauth",
        }
    }
}

/// Target address for SOCKS5 connections
#[derive(Debug, Clone)]
pub enum TargetAddr {
    IPv4([u8; 4], u16),
    IPv6([u8; 16], u16),
    Domain(String, u16),
}

impl TargetAddr {
    /// Parse from SOCKS5 address bytes
    pub fn from_socks5(atyp: u8, addr: &[u8], port: u16) -> SsrResult<Self> {
        match atyp {
            0x01 => {
                if addr.len() < 4 {
                    return Err(SsrError::Socks5("IPv4 address too short".into()));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&addr[..4]);
                Ok(Self::IPv4(ip, port))
            }
            0x03 => {
                let domain = String::from_utf8(addr.to_vec())
                    .map_err(|e| SsrError::Socks5(format!("Invalid domain: {e}")))?;
                Ok(Self::Domain(domain, port))
            }
            0x04 => {
                if addr.len() < 16 {
                    return Err(SsrError::Socks5("IPv6 address too short".into()));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&addr[..16]);
                Ok(Self::IPv6(ip, port))
            }
            _ => Err(SsrError::Socks5(format!("Unknown address type: {atyp}"))),
        }
    }

    /// Get the address type byte for SOCKS5
    pub fn atyp(&self) -> u8 {
        match self {
            Self::IPv4(_, _) => 0x01,
            Self::Domain(_, _) => 0x03,
            Self::IPv6(_, _) => 0x04,
        }
    }

    /// Get the address bytes
    pub fn addr_bytes(&self) -> Vec<u8> {
        match self {
            Self::IPv4(ip, _) => ip.to_vec(),
            Self::Domain(domain, _) => {
                let mut bytes = Vec::with_capacity(1 + domain.len());
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
            Self::IPv6(ip, _) => ip.to_vec(),
        }
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        match self {
            Self::IPv4(_, p) | Self::IPv6(_, p) | Self::Domain(_, p) => *p,
        }
    }

    /// Convert to tokio SocketAddr (for IPv4/IPv6 only, Domain needs resolution)
    pub fn to_socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::IPv4(ip, port) => Some(std::net::SocketAddr::new(
                std::net::Ipv4Addr::from(*ip).into(),
                *port,
            )),
            Self::IPv6(ip, port) => Some(std::net::SocketAddr::new(
                std::net::Ipv6Addr::from(*ip).into(),
                *port,
            )),
            Self::Domain(_, _) => None,
        }
    }
}
