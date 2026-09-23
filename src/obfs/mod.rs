/// HTTP-based obfuscation (GET/POST/mix); mirrors `ssr-n/src/obfs/http_simple.c`.
pub mod http_simple;
/// Pass-through obfuscation (no framing); mirrors `ssr-n/src/obfs/obfs.c`.
pub mod plain;
/// TLS 1.2 session-ticket obfuscation; mirrors `ssr-n/src/obfs/tls1.2_ticket.c`.
pub mod tls_ticket;

use crate::crypto::ObfsType;
use crate::error::SsrResult;

/// Obfuscation trait — each obfs implements:
/// - `client_encode`: wrap data before sending (client side)
/// - `client_decode`: unwrap data after receiving (client side)
/// - `get_overhead`: how many bytes this obfs adds
/// - `need_feedback`: whether this obfs needs empty feedback data
pub trait Obfs: Send {
    /// Set the encryption key for this obfs instance.
    fn set_key(&mut self, key: Vec<u8>);

    /// Encode data before sending (client side).
    fn client_encode(&mut self, buf: &[u8]) -> SsrResult<Vec<u8>>;

    /// Decode data after receiving (client side).
    /// Returns the decoded data and whether an empty feedback packet is needed.
    fn client_decode(&mut self, buf: &[u8]) -> SsrResult<(Vec<u8>, bool)>;

    /// Get the overhead bytes this obfs adds to each packet.
    fn get_overhead(&self) -> usize;

    /// Whether this obfs needs feedback (send empty data back).
    fn need_feedback(&self) -> bool;

    /// Whether this obfs performs an explicit handshake before any relayed data.
    ///
    /// Only `tls1.2_ticket_auth` does (ClientHello → server response → CCS+Finished).
    /// Plain and HTTP obfs send their framing with the first data packet, so the
    /// client must NOT block waiting for a server response that never comes.
    fn needs_handshake(&self) -> bool {
        false
    }
}

/// Create an obfs instance for `obfs`.
///
/// Every `ObfsType` variant has an implementation, so construction is
/// infallible. Name strings are parsed by [`ObfsType::from_name`] at the
/// config boundary instead.
pub fn create_obfs(
    obfs: ObfsType,
    server_host: &str,
    server_port: u16,
    extra_param: &str,
) -> Box<dyn Obfs> {
    match obfs {
        ObfsType::Plain => Box::new(plain::PlainObfs::new()),
        ObfsType::HTTPSimple => Box::new(http_simple::HttpSimpleObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
        )),
        ObfsType::HTTPPost => Box::new(http_simple::HttpPostObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
        )),
        ObfsType::HTTPMix => Box::new(http_simple::HttpMixObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
        )),
        ObfsType::TLS12TicketAuth => Box::new(tls_ticket::Tls12TicketAuthObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
            false,
        )),
        ObfsType::TLS12TicketFastAuth => Box::new(tls_ticket::Tls12TicketAuthObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
            true,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_obfs_plain() {
        let obfs = create_obfs(ObfsType::Plain, "example.com", 80, "");
        assert_eq!(obfs.get_overhead(), 0);
        assert!(!obfs.need_feedback());
        assert!(!obfs.needs_handshake());
    }

    #[test]
    fn test_create_obfs_http_simple() {
        let obfs = create_obfs(ObfsType::HTTPSimple, "example.com", 80, "");
        assert_eq!(obfs.get_overhead(), 0);
        assert!(!obfs.need_feedback());
        assert!(!obfs.needs_handshake());
    }

    #[test]
    fn test_create_obfs_tls_ticket() {
        let obfs = create_obfs(ObfsType::TLS12TicketAuth, "example.com", 443, "");
        assert_eq!(obfs.get_overhead(), 5);
        assert!(obfs.need_feedback());
        assert!(obfs.needs_handshake());
    }

    #[test]
    fn test_only_tls_ticket_needs_handshake() {
        // Any obfs that does NOT handshake must be safe to relay into immediately;
        // guard against a future variant silently opting into the TLS path.
        for obfs_type in [
            ObfsType::Plain,
            ObfsType::HTTPSimple,
            ObfsType::HTTPPost,
            ObfsType::HTTPMix,
        ] {
            let obfs = create_obfs(obfs_type, "example.com", 80, "");
            assert!(
                !obfs.needs_handshake(),
                "{obfs_type:?} should not handshake"
            );
        }
        let obfs = create_obfs(ObfsType::TLS12TicketAuth, "example.com", 443, "");
        assert!(obfs.needs_handshake());
    }

    #[test]
    fn test_create_obfs_unknown() {
        // Unknown names are rejected when the config is parsed, not by the
        // factory — the enum has no hole to fall through.
        assert!(ObfsType::from_name("unknown_obfs").is_err());
    }
}
