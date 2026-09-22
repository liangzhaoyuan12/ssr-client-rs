pub mod origin;
pub mod auth_chain;
pub mod verify_simple;
pub mod auth_simple;
pub mod auth_sha1;
pub mod auth_sha1_v2;
pub mod auth_sha1_v4;
pub mod auth_aes128;

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
    pub local_client_id: [u8; 8],
    pub connection_id: u32,
}

impl GlobalData {
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
    pub host: String,
    pub port: u16,
    pub extra_param: String,
    pub iv: Vec<u8>,
    pub recv_iv: Vec<u8>,
    pub key: Vec<u8>,
    pub head_len: usize,
    pub tcp_mss: u16,
    pub overhead: u16,
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
    pub fn new(seed: u64) -> Self {
        let mut s = [0u64; 2];
        s[0] = seed | 0x100000000;
        s[1] = ((seed as u64) << 32) | 0x1;
        Self { s }
    }

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

    pub fn next(&mut self) -> u64 {
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
            ctx.next();
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
        let val = rng.next();
        assert!(val != 0);
    }

    #[test]
    fn test_get_s5_head_size() {
        // IPv4
        assert_eq!(get_s5_head_size(&[0x01, 0, 0, 0, 0, 0, 80], 30), 7);
        // IPv6
        assert_eq!(get_s5_head_size(&[0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 30), 19);
        // Domain
        assert_eq!(get_s5_head_size(&[0x03, 11, b'g', b'o', b'o', b'g', b'l', b'e', b'.', b'c', b'o', b'm', 0, 80], 30), 15);
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
