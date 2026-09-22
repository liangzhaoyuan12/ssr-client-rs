use crate::error::{SsrError, SsrResult};

/// Encryption method type (28 methods)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherType {
    /// `none`: no encryption, bytes pass through unchanged (C: `ss_cipher_none`).
    None, // 0
    /// `table`: password-derived byte substitution cipher (C: `ss_cipher_table`).
    Table, // 1
    /// `rc4` stream cipher, key only, zero-length IV (C: `ss_cipher_rc4`).
    RC4, // 2
    /// `rc4-md5-6` RC4 variant, true key = md5(key || iv), 6-byte IV.
    /// C: `ss_cipher_rc4_md5_6` (ssr-n/src/ssr_cipher_names.h).
    RC4Md56, // 3: rc4-md5-6
    /// `rc4-md5` RC4 variant, true key = md5(key || iv), 16-byte IV.
    /// C: `ss_cipher_rc4_md5` (ssr-n/src/ssr_cipher_names.h).
    RC4Md5, // 4: rc4-md5
    /// `aes-128-cfb` stream cipher (C: `ss_cipher_aes_128_cfb`, ssr_cipher_names.h).
    AES128CFB, // 5
    /// `aes-192-cfb` stream cipher (C: `ss_cipher_aes_192_cfb`, ssr_cipher_names.h).
    AES192CFB, // 6
    /// `aes-256-cfb` stream cipher (C: `ss_cipher_aes_256_cfb`, ssr_cipher_names.h).
    AES256CFB, // 7
    /// `aes-128-ctr` stream cipher (C: `ss_cipher_aes_128_ctr`, ssr_cipher_names.h).
    AES128CTR, // 8
    /// `aes-192-ctr` stream cipher (C: `ss_cipher_aes_192_ctr`, ssr_cipher_names.h).
    AES192CTR, // 9
    /// `aes-256-ctr` stream cipher (C: `ss_cipher_aes_256_ctr`, ssr_cipher_names.h).
    AES256CTR, // 10
    /// `bf-cfb` Blowfish-CFB stream cipher (C: `ss_cipher_bf_cfb`, ssr_cipher_names.h).
    BFCFB, // 11: bf-cfb (Blowfish)
    /// `camellia-128-cfb` stream cipher (C: `ss_cipher_camellia_128_cfb`, ssr_cipher_names.h).
    Camellia128CFB, // 12
    /// `camellia-192-cfb` stream cipher (C: `ss_cipher_camellia_192_cfb`, ssr_cipher_names.h).
    Camellia192CFB, // 13
    /// `camellia-256-cfb` stream cipher (C: `ss_cipher_camellia_256_cfb`, ssr_cipher_names.h).
    Camellia256CFB, // 14
    /// `cast5-cfb` CAST5-CFB stream cipher (C: `ss_cipher_cast5_cfb`, ssr_cipher_names.h).
    CAST5CFB, // 15
    /// `des-cfb` DES-CFB stream cipher (C: `ss_cipher_des_cfb`, ssr_cipher_names.h).
    DESCFB, // 16
    /// `idea-cfb` IDEA-CFB stream cipher (C: `ss_cipher_idea_cfb`, ssr_cipher_names.h).
    IDEACFB, // 17
    /// `rc2-cfb` RC2-CFB stream cipher (C: `ss_cipher_rc2_cfb`, ssr_cipher_names.h).
    RC2CFB, // 18
    /// `seed-cfb` SEED-CFB stream cipher (C: `ss_cipher_seed_cfb`, ssr_cipher_names.h).
    SeedCFB, // 19
    /// `salsa20` stream cipher, 8-byte IV (C: `ss_cipher_salsa20`, ssr_cipher_names.h).
    Salsa20, // 20
    /// `chacha20` stream cipher, original 8-byte nonce (C: `ss_cipher_chacha20`, ssr_cipher_names.h).
    ChaCha20, // 21
    /// `chacha20-ietf` stream cipher, 12-byte nonce (C: `ss_cipher_chacha20ietf`, ssr_cipher_names.h).
    ChaCha20IETF, // 22
    /// `aes-128-gcm` AEAD cipher, 12-byte nonce (C: `ss_cipher_aes_128_gcm`, ssr_cipher_names.h).
    AES128GCM, // 23
    /// `aes-192-gcm` AEAD cipher, 12-byte nonce (C: `ss_cipher_aes_192_gcm`, ssr_cipher_names.h).
    AES192GCM, // 24
    /// `aes-256-gcm` AEAD cipher, 12-byte nonce (C: `ss_cipher_aes_256_gcm`, ssr_cipher_names.h).
    AES256GCM, // 25
    /// `chacha20-ietf-poly1305` AEAD cipher, 12-byte nonce (C: ssr_cipher_names.h).
    ChaCha20Poly1305IETF, // 26
    /// `xchacha20-ietf-poly1305` AEAD cipher, 24-byte nonce (C: ssr_cipher_names.h).
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
            // C table (ssr_cipher_names.h: iv_size, key_size): rc4=0/16,
            // rc4-md5=16/16, rc4-md5-6=6/16. enc_iv_len uses ss_cipher_iv_size
            // for both md5 variants (encrypt.c:1317-1321), so BOTH transmit
            // their IV on the wire.
            Self::None | Self::RC4 => 0,
            Self::RC4Md56 => 6,
            Self::RC4Md5 => 16,
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
    /// `origin` protocol: no protocol layer, the payload is untouched.
    /// C: `ssr_protocol_origin` (ssr-n/src/ssr_cipher_names.h).
    Origin, // 0
    /// `verify_simple` protocol: length-prefixed units with random padding and CRC32.
    /// C: `verify_simple_new_obfs` (ssr-n/src/obfs/verify.c).
    VerifySimple, // 1
    /// `auth_simple` protocol: unit packing with a one-time auth header.
    /// C: `auth_simple_new_obfs` (ssr-n/src/obfs/auth.c).
    AuthSimple, // 3
    /// `auth_sha1` protocol: unit packing with a SHA1-based auth tag.
    /// C: `auth_sha1_new_obfs` (ssr-n/src/obfs/auth.c).
    AuthSHA1, // 4
    /// `auth_sha1_v2` protocol: SHA1 auth variant built on auth_simple.
    /// C: `auth_sha1_v2_new_obfs` (ssr-n/src/obfs/auth.c).
    AuthSHA1V2, // 5
    /// `auth_sha1_v4` protocol: SHA1 auth variant with salt `auth_sha1_v4`.
    /// C: `auth_sha1_v4_new_obfs` (ssr-n/src/obfs/auth.c).
    AuthSHA1V4, // 6
    /// `auth_aes128_md5` protocol: auth_aes128 variant hashed with MD5.
    /// C: `auth_aes128_md5_new_obfs` (ssr-n/src/obfs/auth.c).
    AuthAES128MD5, // 7
    /// `auth_aes128_sha1` protocol: auth_aes128 variant hashed with SHA1.
    /// C: `auth_aes128_sha1_new_obfs` (ssr-n/src/obfs/auth.c).
    AuthAES128SHA1, // 8
    /// `auth_chain_a` protocol: chained packet auth, base of the chain family.
    /// C: `auth_chain_a_new_obfs` (ssr-n/src/obfs/auth_chain.c).
    AuthChainA, // 9
    /// `auth_chain_b` protocol: auth_chain_a with its own random-length rule and
    /// subclass context. C: `auth_chain_b_new_obfs` (ssr-n/src/obfs/auth_chain.c).
    AuthChainB, // 10
    /// `auth_chain_c` protocol: auth_chain_a with its own random-length rule and
    /// subclass context. C: `auth_chain_c_new_obfs` (ssr-n/src/obfs/auth_chain.c).
    AuthChainC, // 11
    /// `auth_chain_d` protocol: auth_chain_c with a different random-length rule.
    /// C: `auth_chain_d_new_obfs` (ssr-n/src/obfs/auth_chain.c).
    AuthChainD, // 12
    /// `auth_chain_e` protocol: auth_chain_d with its own random-length rule.
    /// C: `auth_chain_e_new_obfs` (ssr-n/src/obfs/auth_chain.c).
    AuthChainE, // 13
    /// `auth_chain_f` protocol: final chain variant, built on auth_chain_e.
    /// C: `auth_chain_f_new_obfs` (ssr-n/src/obfs/auth_chain.c).
    AuthChainF, // 14
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
    /// `plain` obfs: no transport obfuscation at all.
    /// C: `ssr_obfs_plain` (ssr-n/src/ssr_cipher_names.h); the factory builds no obfs object.
    Plain, // 0
    /// `http_simple` obfs: payload hidden inside an HTTP request.
    /// C: `http_simple_new_obfs` (ssr-n/src/obfs/http_simple.c).
    HTTPSimple, // 1
    /// `http_post` obfs: payload hidden inside an HTTP POST body.
    /// C: `http_post_new_obfs` (ssr-n/src/obfs/http_simple.c).
    HTTPPost, // 2
    /// `http_mix` obfs: randomly picks http_post (1 in 3..7) else http_simple.
    /// C: `http_mix_new_obfs` (ssr-n/src/obfs/http_simple.c).
    HTTPMix, // 3
    /// `tls1.2_ticket_auth` obfs: TLS 1.2 session-ticket handshake.
    /// C: `tls12_ticket_auth_new_obfs` (ssr-n/src/obfs/tls1.2_ticket.c).
    TLS12TicketAuth, // 4
    /// `tls1.2_ticket_fastauth` obfs: ticket auth variant built on ticket_auth.
    /// C: `tls12_ticket_fastauth_new_obfs` (ssr-n/src/obfs/tls1.2_ticket.c).
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
    /// IPv4 address and port (SOCKS5 ATYP `0x01`).
    IPv4([u8; 4], u16),
    /// IPv6 address and port (SOCKS5 ATYP `0x04`).
    IPv6([u8; 16], u16),
    /// Domain name and port (SOCKS5 ATYP `0x03`, length-prefixed on the wire).
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
