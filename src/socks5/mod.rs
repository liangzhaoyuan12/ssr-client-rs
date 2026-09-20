/// SOCKS5 protocol parser and responder.
///
/// Implements the server-side of SOCKS5 (RFC 1928):
/// - Method negotiation (supports NO AUTH only)
/// - CONNECT request parsing with IPv4/IPv6/domain address types
/// - Reply generation

use crate::error::{SsrError, SsrResult};

/// SOCKS5 version
const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 commands
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 address types
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 authentication methods
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_REQUIRED: u8 = 0xFF;

/// Parsed SOCKS5 method negotiation request from client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodNegotiation {
    /// Client version (should be 0x05)
    pub version: u8,
    /// List of authentication methods the client supports
    pub methods: Vec<u8>,
}

/// Parsed SOCKS5 CONNECT request from client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// Client version (should be 0x05)
    pub version: u8,
    /// Command (CMD_CONNECT, CMD_BIND, CMD_UDP_ASSOCIATE)
    pub cmd: u8,
    /// Reserved field (should be 0x00)
    pub rsv: u8,
    /// Target address (IPv4, IPv6, or domain)
    pub addr: TargetAddress,
    /// Target port
    pub port: u16,
}

/// Target address in a SOCKS5 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddress {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
    Domain(Vec<u8>),
}

impl TargetAddress {
    /// Get the address type byte
    pub fn atyp(&self) -> u8 {
        match self {
            TargetAddress::IPv4(_) => ATYP_IPV4,
            TargetAddress::Domain(_) => ATYP_DOMAIN,
            TargetAddress::IPv6(_) => ATYP_IPV6,
        }
    }

    /// Encode to SOCKS5 wire format (atyp + addr bytes)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.atyp());
        match self {
            TargetAddress::IPv4(ip) => buf.extend_from_slice(ip),
            TargetAddress::Domain(domain) => {
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain);
            }
            TargetAddress::IPv6(ip) => buf.extend_from_slice(ip),
        }
        buf.extend_from_slice(&0u16.to_be_bytes()); // port placeholder, caller sets
        buf
    }

    /// Get the human-readable address string
    pub fn display(&self) -> String {
        match self {
            TargetAddress::IPv4(ip) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            TargetAddress::IPv6(ip) => {
                let segments: Vec<String> = ip
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                format!("[{}]", segments.join(":"))
            }
            TargetAddress::Domain(d) => String::from_utf8_lossy(d).to_string(),
        }
    }
}

/// SOCKS5 method negotiation request parser.
///
/// Format: [version, nmethods, method1, method2, ...]
pub fn parse_method_negotiation(data: &[u8]) -> SsrResult<MethodNegotiation> {
    if data.len() < 2 {
        return Err(SsrError::socks5("Method negotiation too short"));
    }
    if data[0] != SOCKS5_VERSION {
        return Err(SsrError::socks5(format!(
            "Invalid SOCKS5 version: {}",
            data[0]
        )));
    }
    let nmethods = data[1] as usize;
    if data.len() < 2 + nmethods {
        return Err(SsrError::socks5(format!(
            "Method list truncated: expected {} methods in {} bytes",
            nmethods,
            data.len() - 2
        )));
    }
    Ok(MethodNegotiation {
        version: data[0],
        methods: data[2..2 + nmethods].to_vec(),
    })
}

/// SOCKS5 CONNECT request parser.
///
/// Format: [version, cmd, rsv, atyp, addr..., port]
pub fn parse_connect_request(data: &[u8]) -> SsrResult<ConnectRequest> {
    if data.len() < 4 {
        return Err(SsrError::socks5("Connect request too short"));
    }
    if data[0] != SOCKS5_VERSION {
        return Err(SsrError::socks5(format!(
            "Invalid SOCKS5 version: {}",
            data[0]
        )));
    }

    let cmd = data[1];
    let rsv = data[2];
    let atyp = data[3];

    match atyp {
        ATYP_IPV4 => {
            if data.len() < 10 {
                return Err(SsrError::socks5("IPv4 request too short"));
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[4..8]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            Ok(ConnectRequest {
                version: data[0],
                cmd,
                rsv,
                addr: TargetAddress::IPv4(ip),
                port,
            })
        }
        ATYP_DOMAIN => {
            if data.len() < 5 {
                return Err(SsrError::socks5("Domain request too short"));
            }
            let domain_len = data[4] as usize;
            if data.len() < 5 + domain_len + 2 {
                return Err(SsrError::socks5("Domain request truncated"));
            }
            let domain = data[5..5 + domain_len].to_vec();
            let port = u16::from_be_bytes([data[5 + domain_len], data[5 + domain_len + 1]]);
            Ok(ConnectRequest {
                version: data[0],
                cmd,
                rsv,
                addr: TargetAddress::Domain(domain),
                port,
            })
        }
        ATYP_IPV6 => {
            if data.len() < 22 {
                return Err(SsrError::socks5("IPv6 request too short"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[4..20]);
            let port = u16::from_be_bytes([data[20], data[21]]);
            Ok(ConnectRequest {
                version: data[0],
                cmd,
                rsv,
                addr: TargetAddress::IPv6(ip),
                port,
            })
        }
        _ => Err(SsrError::socks5(format!(
            "Unknown address type: 0x{:02x}",
            atyp
        ))),
    }
}

/// Build a SOCKS5 method negotiation response.
///
/// Format: [version, selected_method]
pub fn build_method_response(method: u8) -> [u8; 2] {
    [SOCKS5_VERSION, method]
}

/// Build a SOCKS5 CONNECT reply.
///
/// Format: [version, rep, rsv, atyp, bind_addr, bind_port]
pub fn build_connect_reply(rep: u8, atyp: u8, bind_addr: &[u8], bind_port: u16) -> Vec<u8> {
    let mut reply = vec![SOCKS5_VERSION, rep, 0x00, atyp];
    reply.extend_from_slice(bind_addr);
    reply.extend_from_slice(&bind_port.to_be_bytes());
    reply
}

/// Build a successful CONNECT reply with zero bind address.
pub fn build_success_reply(atyp: u8) -> Vec<u8> {
    match atyp {
        ATYP_IPV4 => build_connect_reply(REP_SUCCESS, ATYP_IPV4, &[0, 0, 0, 0], 0),
        ATYP_IPV6 => {
            let zeros = [0u8; 16];
            build_connect_reply(REP_SUCCESS, ATYP_IPV6, &zeros, 0)
        }
        ATYP_DOMAIN => {
            // For domain reply, use IPv4 bind address as placeholder
            build_connect_reply(REP_SUCCESS, ATYP_IPV4, &[0, 0, 0, 0], 0)
        }
        _ => build_connect_reply(REP_SUCCESS, ATYP_IPV4, &[0, 0, 0, 0], 0),
    }
}

/// Read exact bytes from a buffer (blocking parse helper).
/// Returns the consumed bytes and remaining slice.
pub fn take_bytes<'a>(
    data: &'a [u8],
    n: usize,
) -> SsrResult<(&'a [u8], &'a [u8])> {
    if data.len() < n {
        return Err(SsrError::socks5(format!(
            "Need {} bytes, have {}",
            n,
            data.len()
        )));
    }
    Ok((&data[..n], &data[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Method negotiation tests ──────────────────────────────────────

    #[test]
    fn test_parse_method_negotiation_valid() {
        // version=5, nmethods=2, methods=[0x00, 0x02]
        let data = [0x05, 0x02, 0x00, 0x02];
        let parsed = parse_method_negotiation(&data).unwrap();
        assert_eq!(parsed.version, 0x05);
        assert_eq!(parsed.methods, vec![0x00, 0x02]);
    }

    #[test]
    fn test_parse_method_negotiation_no_auth_only() {
        let data = [0x05, 0x01, 0x00];
        let parsed = parse_method_negotiation(&data).unwrap();
        assert_eq!(parsed.methods, vec![0x00]);
    }

    #[test]
    fn test_parse_method_negotiation_zero_methods() {
        let data = [0x05, 0x00];
        let parsed = parse_method_negotiation(&data).unwrap();
        assert_eq!(parsed.methods, vec![]);
    }

    #[test]
    fn test_parse_method_negotiation_bad_version() {
        let data = [0x04, 0x01, 0x00];
        let err = parse_method_negotiation(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_method_negotiation_too_short() {
        let data = [0x05];
        let err = parse_method_negotiation(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_method_negotiation_truncated_methods() {
        // nmethods=3 but only 2 method bytes
        let data = [0x05, 0x03, 0x00, 0x01];
        let err = parse_method_negotiation(&data);
        assert!(err.is_err());
    }

    // ── Connect request tests ─────────────────────────────────────────

    #[test]
    fn test_parse_connect_ipv4() {
        // version=5, cmd=CONNECT(1), rsv=0, atyp=IPv4(1),
        // addr=93.184.216.34, port=80
        let mut data = vec![0x05, 0x01, 0x00, 0x01];
        data.extend_from_slice(&[93, 184, 216, 34]);
        data.extend_from_slice(&80u16.to_be_bytes());
        let parsed = parse_connect_request(&data).unwrap();
        assert_eq!(parsed.version, 5);
        assert_eq!(parsed.cmd, CMD_CONNECT);
        assert_eq!(parsed.rsv, 0);
        assert_eq!(
            parsed.addr,
            TargetAddress::IPv4([93, 184, 216, 34])
        );
        assert_eq!(parsed.port, 80);
    }

    #[test]
    fn test_parse_connect_ipv4_port_443() {
        let mut data = vec![0x05, 0x01, 0x00, 0x01];
        data.extend_from_slice(&[10, 0, 0, 1]);
        data.extend_from_slice(&443u16.to_be_bytes());
        let parsed = parse_connect_request(&data).unwrap();
        assert_eq!(parsed.addr, TargetAddress::IPv4([10, 0, 0, 1]));
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn test_parse_connect_ipv4_too_short() {
        // Only 4 bytes header, no address/port
        let data = [0x05, 0x01, 0x00, 0x01];
        let err = parse_connect_request(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_connect_domain() {
        // version=5, cmd=CONNECT, rsv=0, atyp=Domain(3), domain_len=10, "google.com", port=443
        let mut data = vec![0x05, 0x01, 0x00, 0x03];
        data.push(10); // domain length (google.com = 10 bytes)
        data.extend_from_slice(b"google.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let parsed = parse_connect_request(&data).unwrap();
        assert_eq!(parsed.addr, TargetAddress::Domain(b"google.com".to_vec()));
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn test_parse_connect_domain_short_domain() {
        let mut data = vec![0x05, 0x01, 0x00, 0x03];
        data.push(11); // claims 11 bytes but only 3 provided
        data.extend_from_slice(b"goo");
        data.extend_from_slice(&443u16.to_be_bytes());
        let err = parse_connect_request(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_connect_domain_truncated_port() {
        let mut data = vec![0x05, 0x01, 0x00, 0x03];
        data.push(5);
        data.extend_from_slice(b"hello");
        // Missing 2 port bytes
        let err = parse_connect_request(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_connect_ipv6() {
        // version=5, cmd=CONNECT, rsv=0, atyp=IPv6(4),
        // addr=2001:db8::1, port=8080
        let mut data = vec![0x05, 0x01, 0x00, 0x04];
        data.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        data.extend_from_slice(&8080u16.to_be_bytes());
        let parsed = parse_connect_request(&data).unwrap();
        assert_eq!(
            parsed.addr,
            TargetAddress::IPv6([
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01
            ])
        );
        assert_eq!(parsed.port, 8080);
    }

    #[test]
    fn test_parse_connect_ipv6_too_short() {
        let mut data = vec![0x05, 0x01, 0x00, 0x04];
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]); // only 4 bytes of IPv6
        let err = parse_connect_request(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_connect_bad_version() {
        let data = [0x04, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0, 80];
        let err = parse_connect_request(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_connect_unknown_atyp() {
        let data = [0x05, 0x01, 0x00, 0x99, 0, 0, 0, 0, 0, 80];
        let err = parse_connect_request(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_connect_too_short_overall() {
        let data = [0x05, 0x01];
        let err = parse_connect_request(&data);
        assert!(err.is_err());
    }

    #[test]
    fn test_parse_connect_udp_associate() {
        let mut data = vec![0x05, 0x03, 0x00, 0x01];
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&0u16.to_be_bytes());
        let parsed = parse_connect_request(&data).unwrap();
        assert_eq!(parsed.cmd, CMD_UDP_ASSOCIATE);
    }

    // ── Response builder tests ────────────────────────────────────────

    #[test]
    fn test_build_method_response() {
        let resp = build_method_response(AUTH_NONE);
        assert_eq!(resp, [0x05, 0x00]);
    }

    #[test]
    fn test_build_method_response_no_acceptable() {
        let resp = build_method_response(AUTH_REQUIRED);
        assert_eq!(resp, [0x05, 0xFF]);
    }

    #[test]
    fn test_build_connect_reply_success_ipv4() {
        let reply = build_success_reply(ATYP_IPV4);
        assert_eq!(reply[0], 0x05); // version
        assert_eq!(reply[1], REP_SUCCESS);
        assert_eq!(reply[2], 0x00); // rsv
        assert_eq!(reply[3], ATYP_IPV4);
        assert_eq!(reply.len(), 10);
    }

    #[test]
    fn test_build_connect_reply_success_ipv6() {
        let reply = build_success_reply(ATYP_IPV6);
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], REP_SUCCESS);
        assert_eq!(reply[3], ATYP_IPV6);
        assert_eq!(reply.len(), 22);
    }

    #[test]
    fn test_build_connect_reply_failure() {
        let reply = build_connect_reply(REP_HOST_UNREACHABLE, ATYP_IPV4, &[0, 0, 0, 0], 0);
        assert_eq!(reply[1], REP_HOST_UNREACHABLE);
    }

    // ── TargetAddress tests ───────────────────────────────────────────

    #[test]
    fn test_target_address_display_ipv4() {
        let addr = TargetAddress::IPv4([192, 168, 1, 1]);
        assert_eq!(addr.display(), "192.168.1.1");
    }

    #[test]
    fn test_target_address_display_domain() {
        let addr = TargetAddress::Domain(b"example.com".to_vec());
        assert_eq!(addr.display(), "example.com");
    }

    #[test]
    fn test_target_address_atyp() {
        assert_eq!(TargetAddress::IPv4([0; 4]).atyp(), ATYP_IPV4);
        assert_eq!(
            TargetAddress::Domain(vec![]).atyp(),
            ATYP_DOMAIN
        );
        assert_eq!(TargetAddress::IPv6([0; 16]).atyp(), ATYP_IPV6);
    }

    #[test]
    fn test_target_address_encode_ipv4() {
        let addr = TargetAddress::IPv4([10, 0, 0, 1]);
        let encoded = addr.encode();
        // atyp(1) + addr(4) + port_placeholder(2) = 7
        assert_eq!(encoded, vec![0x01, 10, 0, 0, 1, 0, 0]);
    }

    // ── Full handshake round-trip test ────────────────────────────────

    #[test]
    fn test_full_handshake_roundtrip() {
        // Client sends method negotiation: version=5, methods=[0x00]
        let client_greeting = [0x05, 0x01, 0x00];
        let neg = parse_method_negotiation(&client_greeting).unwrap();
        assert!(neg.methods.contains(&AUTH_NONE));

        // Server responds with NO AUTH
        let server_response = build_method_response(AUTH_NONE);
        assert_eq!(server_response, [0x05, 0x00]);

        // Client sends CONNECT to 8.8.8.8:53
        let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
        connect_req.extend_from_slice(&[8, 8, 8, 8]);
        connect_req.extend_from_slice(&53u16.to_be_bytes());
        let req = parse_connect_request(&connect_req).unwrap();
        assert_eq!(req.cmd, CMD_CONNECT);
        assert_eq!(req.addr, TargetAddress::IPv4([8, 8, 8, 8]));
        assert_eq!(req.port, 53);

        // Server responds with success
        let reply = build_success_reply(req.addr.atyp());
        assert_eq!(reply[1], REP_SUCCESS);
    }

    // ── take_bytes test ───────────────────────────────────────────────

    #[test]
    fn test_take_bytes_ok() {
        let data = [1, 2, 3, 4, 5];
        let (taken, rest) = take_bytes(&data, 3).unwrap();
        assert_eq!(taken, &[1, 2, 3]);
        assert_eq!(rest, &[4, 5]);
    }

    #[test]
    fn test_take_bytes_exact() {
        let data = [1, 2, 3];
        let (taken, rest) = take_bytes(&data, 3).unwrap();
        assert_eq!(taken, &[1, 2, 3]);
        assert_eq!(rest, &[]);
    }

    #[test]
    fn test_take_bytes_insufficient() {
        let data = [1, 2];
        let err = take_bytes(&data, 3);
        assert!(err.is_err());
    }
}

/// Build SSR address package from SOCKS5 target address.
/// Format: ATYP(1) + address(variable) + port(2, big-endian)
pub fn build_address_package(addr: &TargetAddress, port: u16) -> Vec<u8> {
    let mut pkg = Vec::new();
    match addr {
        TargetAddress::IPv4(ip) => {
            pkg.push(ATYP_IPV4);
            pkg.extend_from_slice(ip);
        }
        TargetAddress::IPv6(ip) => {
            pkg.push(ATYP_IPV6);
            pkg.extend_from_slice(ip);
        }
        TargetAddress::Domain(domain) => {
            pkg.push(ATYP_DOMAIN);
            pkg.push(domain.len() as u8);
            pkg.extend_from_slice(domain);
        }
    }
    pkg.extend_from_slice(&port.to_be_bytes());
    pkg
}
