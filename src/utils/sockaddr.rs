use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;

/// Universal sockaddr type for SSR
#[derive(Debug, Clone)]
pub enum SockAddr {
    IPv4(std::net::Ipv4Addr, u16),
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

    /// Resolve domain name to SocketAddr
    pub fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
        format!("{host}:{port}").to_socket_addrs().ok()?.next()
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
