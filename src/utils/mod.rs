/// Adler-32 checksum (RFC 1950); used by the auth_sha1 protocols.
pub mod adler32;
/// Base64 encode/decode helpers (standard alphabet, SSR URL parameters).
pub mod base64;
/// CRC-32 checksum (IEEE polynomial) helpers; mirrors `ssr-n/src/obfs/crc32.c`.
pub mod crc32;
/// Hash primitives shared by protocols: MD5, HMAC-MD5, HMAC-SHA1.
pub mod hash;
/// Address helpers: the universal `SockAddr` enum (IPv4/IPv6 + port).
pub mod sockaddr;
