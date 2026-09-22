/// `auth_aes128` — AES128 stream cipher plus user auth (wire names
/// `auth_aes128_md5` / `auth_aes128_sha1`).
pub mod auth_aes128;
/// `auth_chain_a`..`auth_chain_f` — HMAC-SHA1 chained protocols whose
/// random padding length comes from a XORShift128+ stream.
pub mod auth_chain;
/// `auth_sha1` — Adler32-framed packets with an HMAC-SHA1 auth header.
pub mod auth_sha1;
/// `auth_sha1_v2` — like `auth_sha1` with 1- or 3-byte rand_len fields.
pub mod auth_sha1_v2;
/// `auth_sha1_v4` — like `auth_sha1_v2`, but data packets carry a CRC32
/// instead of an Adler32 and the receive path skips the auth header.
pub mod auth_sha1_v4;
/// `auth_simple` — CRC32-framed packets preceded by an auth header.
pub mod auth_simple;
/// `origin` — pass-through protocol that adds no framing.
pub mod origin;
/// `verify_simple` — CRC32 framing with random padding, no auth header.
pub mod verify_simple;

use crate::error::SsrResult;

/// Protocol trait — each protocol implements two core functions:
/// - `client_pre_encrypt`: wrap data before sending
/// - `client_post_decrypt`: unwrap data after receiving
pub trait Protocol: Send {
    /// Set the salt for this protocol instance
    fn set_salt(&mut self, salt: &str);

    /// Get the overhead bytes this protocol adds
    fn get_overhead(&self) -> usize;

    /// Whether this protocol needs feedback (send empty data back)
    fn need_feedback(&self) -> bool;

    /// Initialize the user key (for auth_aes128; no-op for origin/plain).
    fn init_user_key(&mut self) {}

    /// Set the server IV (cipher IV) for the protocol's MAC computation.
    /// Only relevant for auth_aes128; origin/plain protocols ignore this.
    fn set_server_iv(&mut self, _iv: Vec<u8>) {}

    /// Wrap data before encryption (client side)
    /// Returns the framed data ready for encryption
    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>>;

    /// Unwrap data after decryption (client side)
    /// Returns the original plain data
    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>>;

    /// C: client_udp_pre_encrypt hook (per-datagram, SSR framing before the
    /// SS cipher layer). Default identity matches C protocols that leave
    /// `client_udp_pre_encrypt = NULL` (auth_simple/sha1 family, origin).
    /// Implemented by auth_aes128 and auth_chain_a~f.
    fn udp_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        Ok(plaindata.to_vec())
    }

    /// C: client_udp_post_decrypt hook (per-datagram, after SS cipher
    /// decrypt). Returns the stripped payload; Err means the datagram fails
    /// the protocol MAC and must be dropped (C returns 0 → drop).
    fn udp_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        Ok(data.to_vec())
    }
}

/// Global data shared across protocol instances (client_id, connection_id)
#[derive(Debug, Clone)]
pub struct GlobalData {
    /// 8-byte client id generated once at startup; C: `local_client_id`
    /// (auth_simple_global_data, ssr-n/src/obfs/auth.c:27).
    pub local_client_id: [u8; 8],
    /// Per-connection counter, only its low 24 bits are random; C:
    /// `connection_id` (auth_simple_global_data, ssr-n/src/obfs/auth.c:28).
    pub connection_id: u32,
}

impl Default for GlobalData {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalData {
    /// Random client id plus a random 24-bit connection id. C:
    /// auth_simple_generate_global_init_data (ssr-n/src/obfs/auth.c:76-81).
    pub fn new() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut local_client_id = [0u8; 8];
        let mut connection_id = [0u8; 4];
        rng.fill_bytes(&mut local_client_id);
        rng.fill_bytes(&mut connection_id);
        Self {
            local_client_id,
            connection_id: u32::from_le_bytes(connection_id) & 0xFFFFFF,
        }
    }

    /// Increment connection_id, reset if overflow
    pub fn increment(&mut self) {
        self.connection_id += 1;
        if self.connection_id > 0xFF000000 {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut self.local_client_id);
            let mut buf = [0u8; 4];
            rng.fill_bytes(&mut buf);
            self.connection_id = u32::from_le_bytes(buf) & 0xFFFFFF;
        }
    }
}

/// Server information needed by protocols
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// Server host name or IP. C: `server_info_t.host` (ssr-n/src/obfs/obfs.h:29).
    pub host: String,
    /// Server port. C: `server_info_t.port` (ssr-n/src/obfs/obfs.h:30).
    pub port: u16,
    /// Per-user extra parameter from the SSR link (e.g. `uid:key` for
    /// auth_aes128). C: `server_info_t.extra_param` (ssr-n/src/obfs/obfs.h:31).
    pub extra_param: String,
    /// Encrypt-direction IV, mixed into protocol HMAC keys. C:
    /// `server_info_t.iv` (ssr-n/src/obfs/obfs.h:33).
    pub iv: Vec<u8>,
    /// Receive-direction IV. C: `server_info_t.recv_iv` (ssr-n/src/obfs/obfs.h:35).
    pub recv_iv: Vec<u8>,
    /// Stream-cipher key. C: `server_info_t.key` (ssr-n/src/obfs/obfs.h:37).
    pub key: Vec<u8>,
    /// SOCKS5 header size once known, 0 before the first packet. C:
    /// `server_info_t.head_len` (ssr-n/src/obfs/obfs.h:39).
    pub head_len: usize,
    /// TCP MSS, caps how much data one protocol pack may carry. C:
    /// `server_info_t.tcp_mss` (ssr-n/src/obfs/obfs.h:40).
    pub tcp_mss: u16,
    /// Bytes this protocol adds on top of the payload. C:
    /// `server_info_t.overhead` (ssr-n/src/obfs/obfs.h:41).
    pub overhead: u16,
    /// I/O buffer size (default 16384). C: `server_info_t.buffer_size`
    /// (ssr-n/src/obfs/obfs.h:42).
    pub buffer_size: u32,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 0,
            extra_param: String::new(),
            iv: Vec::new(),
            recv_iv: Vec::new(),
            key: Vec::new(),
            head_len: 0,
            tcp_mss: 1460,
            overhead: 0,
            buffer_size: 16384,
        }
    }
}

/// XORShift128+ PRNG (used by SSR protocols for random padding)
pub struct XorShift128Plus {
    s: [u64; 2],
}

impl XorShift128Plus {
    /// Seed both 64-bit states from a u64 the way C seeds from time.
    /// C: init_shift128plus (ssr-n/src/obfs/obfsutil.c:26-33).
    pub fn new(seed: u64) -> Self {
        let mut s = [0u64; 2];
        s[0] = seed | 0x100000000;
        s[1] = (seed << 32) | 0x1;
        Self { s }
    }

    /// Load the state from 16 little-endian bytes; panics when `data`
    /// is shorter than 16 bytes. C: shift128plus_init_from_bin
    /// (ssr-n/src/obfs/auth_chain.c:131).
    pub fn from_bytes(data: &[u8]) -> Self {
        assert!(data.len() >= 16);
        let mut s = [0u64; 2];
        // Little-endian read
        s[0] = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        s[1] = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        Self { s }
    }

    /// Advance the state and return the next value (wrapping add).
    /// C: xorshift128plus (ssr-n/src/obfs/obfsutil.c:35-44).
    pub fn next_u64(&mut self) -> u64 {
        let x = self.s[0];
        let y = self.s[1];
        self.s[0] = y;
        let mut x = x;
        x ^= x << 23;
        x ^= x >> 17;
        x ^= y ^ (y >> 26);
        self.s[1] = x;
        x.wrapping_add(y)
    }

    /// Initialize from bin with datalen mixed in, then run 4 rounds
    pub fn from_bin_with_datalen(data: &[u8], datalen: usize) -> Self {
        assert!(data.len() >= 16);
        let mut filled = [0u8; 16];
        filled[..data.len().min(16)].copy_from_slice(&data[..data.len().min(16)]);
        filled[0] = datalen as u8;
        filled[1] = (datalen >> 8) as u8;
        let mut ctx = Self::from_bytes(&filled);
        for _ in 0..4 {
            ctx.next_u64();
        }
        ctx
    }
}

/// Get SOCKS5 header size from plain data
pub fn get_s5_head_size(plaindata: &[u8], def_size: usize) -> usize {
    if plaindata.is_empty() {
        return def_size;
    }
    match plaindata[0] & 0x7 {
        1 => 7,  // IPv4
        4 => 19, // IPv6
        3 => {
            // Domain
            if plaindata.len() < 2 {
                return def_size;
            }
            4 + plaindata[1] as usize
        }
        _ => def_size,
    }
}

/// Build HMAC-SHA1 key matching C's ss_sha1_hmac: iv + key + zeros padded to MAX_IV_LENGTH + MAX_KEY_LENGTH (80 bytes)
pub fn ss_hmac_key(iv: &[u8], key: &[u8]) -> Vec<u8> {
    const MAX_IV_LENGTH: usize = 16;
    const MAX_KEY_LENGTH: usize = 64;
    let iv_len = iv.len().min(MAX_IV_LENGTH);
    let key_len = key.len().min(MAX_KEY_LENGTH);
    // C code: auth_key = calloc(80), then buffer_create_from(auth_key, iv_len + key_len)
    // Only iv_len + key_len bytes are used for HMAC, not the full 80
    let mut hmac_key = vec![0u8; iv_len + key_len];
    hmac_key[..iv_len].copy_from_slice(&iv[..iv_len]);
    hmac_key[iv_len..iv_len + key_len].copy_from_slice(&key[..key_len]);
    hmac_key
}

/// Little-endian u32 write
pub fn memintcopy_lt(buf: &mut [u8], val: u32) {
    buf[0] = val as u8;
    buf[1] = (val >> 8) as u8;
    buf[2] = (val >> 16) as u8;
    buf[3] = (val >> 24) as u8;
}

/// Little-endian u32 read
pub fn memintread_lt(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xorshift128plus() {
        let mut rng = XorShift128Plus::new(12345);
        let val = rng.next_u64();
        assert!(val != 0);
    }

    #[test]
    fn test_get_s5_head_size() {
        // IPv4
        assert_eq!(get_s5_head_size(&[0x01, 0, 0, 0, 0, 0, 80], 30), 7);
        // IPv6
        assert_eq!(
            get_s5_head_size(
                &[0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                30
            ),
            19
        );
        // Domain
        assert_eq!(
            get_s5_head_size(
                &[0x03, 11, b'g', b'o', b'o', b'g', b'l', b'e', b'.', b'c', b'o', b'm', 0, 80],
                30
            ),
            15
        );
        // Empty
        assert_eq!(get_s5_head_size(&[], 30), 30);
    }

    #[test]
    fn test_memintcopy_lt() {
        let mut buf = [0u8; 4];
        memintcopy_lt(&mut buf, 0x01020304);
        assert_eq!(buf, [0x04, 0x03, 0x02, 0x01]);
    }
}
