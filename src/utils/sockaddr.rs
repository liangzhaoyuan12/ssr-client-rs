use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;

/// Format `host:port` for `connect`/`bind`.
///
/// IPv6 literals must be bracketed (`[::1]:8388`), otherwise the string is
/// ambiguous and `to_socket_addrs` fails to resolve it ("::1:8388" parses as
/// neither a `SocketAddr` nor a hostname). Domains and IPv4 literals are
/// formatted as-is; an already-bracketed literal is not double-bracketed.
pub fn host_port(host: &str, port: u16) -> String {
    if host.starts_with('[') {
        format!("{host}:{port}")
    } else if host.contains(':') {
        // Only IPv6 literals contain ':' — domains and IPv4 never do.
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Universal sockaddr type for SSR
#[derive(Debug, Clone)]
pub enum SockAddr {
    /// IPv4 address with port.
    IPv4(std::net::Ipv4Addr, u16),
    /// IPv6 address with port.
    IPv6(std::net::Ipv6Addr, u16),
}

impl SockAddr {
    /// Create from SocketAddr
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(a) => Self::IPv4(*a.ip(), a.port()),
            SocketAddr::V6(a) => Self::IPv6(*a.ip(), a.port()),
        }
    }

    /// Create from host string and port
    pub fn from_host_port(host: &str, port: u16) -> Option<Self> {
        if let Ok(ip) = std::net::Ipv4Addr::from_str(host) {
            return Some(Self::IPv4(ip, port));
        }
        if let Ok(ip) = std::net::Ipv6Addr::from_str(host) {
            return Some(Self::IPv6(ip, port));
        }
        None
    }

    /// Resolve host (domain, IPv4 or IPv6 literal) to SocketAddr
    pub fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
        host_port(host, port).to_socket_addrs().ok()?.next()
    }

    /// Get port
    pub fn port(&self) -> u16 {
        match self {
            Self::IPv4(_, p) | Self::IPv6(_, p) => *p,
        }
    }

    /// Convert to SocketAddr
    pub fn to_socket_addr(&self) -> SocketAddr {
        match self {
            Self::IPv4(ip, port) => SocketAddr::new((*ip).into(), *port),
            Self::IPv6(ip, port) => SocketAddr::new((*ip).into(), *port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_formats_each_family() {
        assert_eq!(host_port("example.com", 8388), "example.com:8388");
        assert_eq!(host_port("127.0.0.1", 80), "127.0.0.1:80");
        assert_eq!(host_port("::1", 8388), "[::1]:8388");
        assert_eq!(host_port("2001:db8::1", 443), "[2001:db8::1]:443");
        // Already-bracketed input is not double-bracketed.
        assert_eq!(host_port("[::1]", 8388), "[::1]:8388");
    }

    #[test]
    fn resolve_handles_ipv6_literals() {
        // std resolves the bare form to the same address as the bracketed one
        // (it splits at the last ':'), and host_port() normalises to the
        // bracketed, documented form — all three must agree.
        let bracketed = "[::1]:8388".to_socket_addrs().unwrap().next().unwrap();
        let bare = "::1:8388".to_socket_addrs().unwrap().next().unwrap();
        let ours = host_port("::1", 8388)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        assert_eq!(bare, bracketed);
        assert_eq!(ours, bracketed);
        assert!(bracketed.is_ipv6());
        assert_eq!(bracketed.port(), 8388);
        // bind form agrees too (regression: dual-stack "[::]" wildcard).
        let bind_bare = ":::0".to_socket_addrs().unwrap().next().unwrap();
        let bind_bracketed = "[::]:0".to_socket_addrs().unwrap().next().unwrap();
        assert_eq!(bind_bare, bind_bracketed);
    }
}
