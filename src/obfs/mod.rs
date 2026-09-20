pub mod plain;
pub mod http_simple;
pub mod tls_ticket;

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
}

/// Create an obfs instance by name.
/// Returns None for "plain" (no obfuscation needed).
pub fn create_obfs(name: &str, server_host: &str, server_port: u16, extra_param: &str) -> Option<Box<dyn Obfs>> {
    match name {
        "plain" => None,
        "http_simple" => Some(Box::new(http_simple::HttpSimpleObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
        ))),
        "http_post" => Some(Box::new(http_simple::HttpPostObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
        ))),
        "http_mix" => Some(Box::new(http_simple::HttpMixObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
        ))),
        "tls1.2_ticket_auth" => Some(Box::new(tls_ticket::Tls12TicketAuthObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
            false,
        ))),
        "tls1.2_ticket_fastauth" => Some(Box::new(tls_ticket::Tls12TicketAuthObfs::new(
            server_host.to_string(),
            server_port,
            extra_param.to_string(),
            true,
        ))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_obfs_plain() {
        let obfs = create_obfs("plain", "example.com", 80, "");
        assert!(obfs.is_none());
    }

    #[test]
    fn test_create_obfs_http_simple() {
        let obfs = create_obfs("http_simple", "example.com", 80, "");
        assert!(obfs.is_some());
        let obfs = obfs.unwrap();
        assert_eq!(obfs.get_overhead(), 0);
        assert!(!obfs.need_feedback());
    }

    #[test]
    fn test_create_obfs_tls_ticket() {
        let obfs = create_obfs("tls1.2_ticket_auth", "example.com", 443, "");
        assert!(obfs.is_some());
        let obfs = obfs.unwrap();
        assert_eq!(obfs.get_overhead(), 5);
        assert!(obfs.need_feedback());
    }

    #[test]
    fn test_create_obfs_unknown() {
        let obfs = create_obfs("unknown_obfs", "example.com", 80, "");
        assert!(obfs.is_none());
    }
}
