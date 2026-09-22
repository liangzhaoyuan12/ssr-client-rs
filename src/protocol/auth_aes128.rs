use crate::error::SsrResult;
use crate::utils::base64::b64encode;
use crate::utils::hash::{hmac_md5, hmac_sha1, md5, sha1};
use crate::crypto::bytes_to_key::bytes_to_key;
use super::{Protocol, GlobalData, ServerInfo, get_s5_head_size, memintcopy_lt, XorShift128Plus};

const PACK_UNIT_SIZE: usize = 2000;

/// Auth AES128 protocol — AES128 + MD5/SHA1 authentication
pub struct AuthAES128 {
    has_sent_header: bool,
    recv_buffer: Vec<u8>,
    global: GlobalData,
    server_info: ServerInfo,
    user_key: Vec<u8>,
    uid: [u8; 4],
    pack_id: u32,
    recv_id: u32,
    last_data_len: usize,
    salt: &'static str,
    hash_fn: fn(&[u8]) -> Vec<u8>,  // md5 (16B) or sha1 (20B)
    hmac_fn: fn(&[u8], &[u8]) -> Vec<u8>,  // hmac_md5 or hmac_sha1
    hash_len: usize,
    rng: XorShift128Plus,
}

fn hexs(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }
fn hash_md5_v(data: &[u8]) -> Vec<u8> { md5(data).to_vec() }
fn hash_sha1_v(data: &[u8]) -> Vec<u8> { sha1(data).to_vec() }
fn hmac_md5_v(key: &[u8], data: &[u8]) -> Vec<u8> { hmac_md5(key, data).to_vec() }
fn hmac_sha1_v(key: &[u8], data: &[u8]) -> Vec<u8> { hmac_sha1(key, data).to_vec() }

impl AuthAES128 {
    pub fn new_md5(server_info: ServerInfo) -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        let seed_val = u64::from_le_bytes(seed);
        Self {
            has_sent_header: false,
            recv_buffer: Vec::with_capacity(16384),
            global: GlobalData::new(),
            server_info,
            user_key: Vec::new(),
            uid: [0; 4],
            pack_id: 1,
            recv_id: 1,
            last_data_len: 0,
            salt: "auth_aes128_md5",
            hash_fn: hash_md5_v,
            hmac_fn: hmac_md5_v,
            hash_len: 16,
            rng: XorShift128Plus::new(seed_val),
        }
    }

    pub fn new_sha1(server_info: ServerInfo) -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        let seed_val = u64::from_le_bytes(seed);
        Self {
            has_sent_header: false,
            recv_buffer: Vec::with_capacity(16384),
            global: GlobalData::new(),
            server_info,
            user_key: Vec::new(),
            uid: [0; 4],
            pack_id: 1,
            recv_id: 1,
            last_data_len: 0,
            salt: "auth_aes128_sha1",
            hash_fn: hash_sha1_v,
            hmac_fn: hmac_sha1_v,
            hash_len: 20,
            rng: XorShift128Plus::new(seed_val),
        }
    }

    pub fn init_user_key(&mut self) {
        if !self.user_key.is_empty() {
            return;
        }
        if !self.server_info.extra_param.is_empty() {
            if let Some(delim_pos) = self.server_info.extra_param.find(':') {
                let uid_str = &self.server_info.extra_param[..delim_pos];
                let key_str = &self.server_info.extra_param[delim_pos + 1..];
                if let Ok(uid_long) = uid_str.trim().parse::<u32>() {
                    memintcopy_lt(&mut self.uid, uid_long);
                    let hash = (self.hash_fn)(key_str.as_bytes());
                    self.user_key = hash[..self.hash_len].to_vec();
                    return;
                }
            }
        }
        // Default: random uid, use server key
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut self.uid);
        self.user_key = self.server_info.key.clone();
    }

    fn get_rand_len(&mut self, datalength: usize, fulldatalength: usize) -> usize {
        // C code get_rand_len (auth.c:1000-1015)
        if datalength > 1300 || self.last_data_len > 1300 || fulldatalength >= self.server_info.buffer_size as usize {
            return 0;
        }
        if datalength > 1100 {
            return (self.rng.next() & 0x7F) as usize;
        }
        if datalength > 900 {
            return (self.rng.next() & 0xFF) as usize;
        }
        if datalength > 400 {
            return (self.rng.next() & 0x1FF) as usize;
        }
        (self.rng.next() & 0x3FF) as usize
    }

    fn pack_data(&mut self, data: &[u8], fulldatalength: usize) -> Vec<u8> {
        self.init_user_key();

        let rand_len = self.get_rand_len(data.len(), fulldatalength) + 1;
        let out_size = rand_len + data.len() + 8;
        let mut out = vec![0u8; out_size];

        // Length (little-endian u16)
        out[0] = out_size as u8;
        out[1] = (out_size >> 8) as u8;

        // HMAC of first 2 bytes
        let mut key = Vec::new();
        key.extend_from_slice(&self.user_key);
        key.extend_from_slice(&self.pack_id.to_le_bytes());
        let hash = (self.hmac_fn)(&key, &out[0..2]);
        out[2] = hash[0];
        out[3] = hash[1];

        // Random padding
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[4..4 + rand_len]);

        // rand_len field
        if rand_len < 128 {
            out[4] = rand_len as u8;
        } else {
            out[4] = 0xFF;
            out[5] = rand_len as u8;
            out[6] = (rand_len >> 8) as u8;
        }

        self.pack_id += 1;

        // Payload
        let data_start = 4 + rand_len;
        out[data_start..data_start + data.len()].copy_from_slice(data);

        // HMAC of everything except last 4 bytes
        let hash = (self.hmac_fn)(&key, &out[..out_size - 4]);
        out[out_size - 4..].copy_from_slice(&hash[..4]);

        out
    }

    /// Set the server IV. Must equal the transmitted cipher IV — the SSR server
    /// uses the received cipher IV as the MAC-key prefix (C ssr_executive.c:400,
    /// auth.c:1398-1399).
    pub fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.server_info.iv = iv;
    }

    fn pack_auth_data(&mut self, data: &[u8]) -> Vec<u8> {
        self.init_user_key();

        // C code auth_aes128_sha1_pack_auth_data line 1084:
        //   unsigned int rand_len = (datalength > 400 ? (xorshift128plus() & 0x1FF)
        //                                             : (xorshift128plus() & 0x3FF));
        let rand_len = if data.len() > 400 {
            (self.rng.next() & 0x1FF) as usize
        } else {
            (self.rng.next() & 0x3FF) as usize
        };
        let data_offset = rand_len + 16 + 4 + 4 + 7;
        let out_size = data_offset + data.len() + 4;
        let mut out = vec![0u8; out_size];

        // IV + Key for HMAC
        let mut key = Vec::new();
        key.extend_from_slice(&self.server_info.iv);
        key.extend_from_slice(&self.server_info.key);
        ssr_debug!("[pack_auth] iv={} key={}", hexs(&self.server_info.iv), hexs(&self.server_info.key));

        // Random padding
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[data_offset - rand_len..data_offset]);

        // Increment connection_id
        self.global.increment();

        // Build encrypt block (20 bytes)
        let mut encrypt = [0u8; 24];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        memintcopy_lt(&mut encrypt[0..4], now);
        encrypt[4..8].copy_from_slice(&self.global.local_client_id[..4]);
        memintcopy_lt(&mut encrypt[8..12], self.global.connection_id);
        encrypt[12] = out_size as u8;
        encrypt[13] = (out_size >> 8) as u8;
        encrypt[14] = rand_len as u8;
        encrypt[15] = (rand_len >> 8) as u8;

        // Derive encryption key from user_key + salt
        let user_key_b64 = b64encode(&self.user_key);
        let enc_key_input = format!("{}{}", user_key_b64, self.salt);
        let enc_key = bytes_to_key(enc_key_input.as_bytes(), 16);

        // AES-128-CBC encrypt (C encrypt.c:744 encrypts encrypt[0..16]: t+client_id+conn_id+sizes)
        let encrypted = aes_128_cbc_encrypt(&enc_key, &encrypt[0..16]);
        encrypt[4..20].copy_from_slice(&encrypted[..16]);
        encrypt[0..4].copy_from_slice(&self.uid);

        // HMAC of encrypt block
        let hash = (self.hmac_fn)(&key, &encrypt[..20]);
        encrypt[20..24].copy_from_slice(&hash[..4]);

        // Random byte + HMAC
        rand::thread_rng().fill_bytes(&mut out[0..1]);
        let hash = (self.hmac_fn)(&key, &out[0..1]);
        out[1..7].copy_from_slice(&hash[..6]);

        // Copy encrypt block
        out[7..31].copy_from_slice(&encrypt[..24]);

        // Payload
        out[data_offset..data_offset + data.len()].copy_from_slice(data);

        // Final HMAC
        let hash = (self.hmac_fn)(&self.user_key, &out[..out_size - 4]);
        out[out_size - 4..].copy_from_slice(&hash[..4]);

        out
    }
}

/// Simple AES-128-CBC encrypt (PKCS7 padding)
pub(crate) fn aes_128_cbc_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    type Aes128Enc = aes::Aes128;

    // PKCS7 pad
    let block_size = 16;
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

    let cipher = Aes128Enc::new_from_slice(key).unwrap();
    let mut iv = [0u8; 16];
    let mut output = Vec::with_capacity(padded.len());

    for chunk in padded.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ iv[i];
        }
        let mut block_arr = aes::Block::clone_from_slice(&block);
        cipher.encrypt_block(&mut block_arr);
        iv.copy_from_slice(&block_arr);
        output.extend_from_slice(&block_arr);
    }

    output
}

/// Simple AES-128-CBC decrypt (remove PKCS7 padding)
pub fn aes_128_cbc_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherDecrypt, KeyInit};
    type Aes128Dec = aes::Aes128;

    let cipher = Aes128Dec::new_from_slice(key).unwrap();
    let mut iv = [0u8; 16];
    let mut output = Vec::with_capacity(data.len());

    for chunk in data.chunks(16) {
        let block_arr = aes::Block::clone_from_slice(chunk);
        let mut decrypted = block_arr;
        cipher.decrypt_block(&mut decrypted);
        let mut plain = [0u8; 16];
        for i in 0..16 {
            plain[i] = decrypted[i] ^ iv[i];
        }
        iv.copy_from_slice(chunk);
        output.extend_from_slice(&plain);
    }

    // Remove PKCS7 padding
    if let Some(&pad_len) = output.last() {
        if pad_len > 0 && pad_len <= 16 && output.len() >= pad_len as usize {
            let new_len = output.len() - pad_len as usize;
            output.truncate(new_len);
        }
    }
    output
}

impl Protocol for AuthAES128 {
    fn set_salt(&mut self, salt: &str) {
        // Salt is set via constructor
        let _ = salt;
    }
    fn get_overhead(&self) -> usize { 9 }
    fn need_feedback(&self) -> bool { true }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut data = plaindata;
        let mut len = plaindata.len();

        if len > 0 && !self.has_sent_header {
            let head_size = 1200.min(len);
            let packed = self.pack_auth_data(&data[..head_size]);
            result.extend_from_slice(&packed);
            data = &data[head_size..];
            len -= head_size;
            self.has_sent_header = true;
        }

        while len > PACK_UNIT_SIZE {
            let packed = self.pack_data(&data[..PACK_UNIT_SIZE], plaindata.len());
            result.extend_from_slice(&packed);
            data = &data[PACK_UNIT_SIZE..];
            len -= PACK_UNIT_SIZE;
        }

        if len > 0 {
            let packed = self.pack_data(data, plaindata.len());
            result.extend_from_slice(&packed);
        }

        self.last_data_len = plaindata.len();
        Ok(result)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.recv_buffer.extend_from_slice(data);

        let mut output = Vec::new();

        while self.recv_buffer.len() > 4 {
            // Verify first HMAC
            let mut key = Vec::new();
            key.extend_from_slice(&self.user_key);
            key.extend_from_slice(&self.recv_id.to_le_bytes());

            let hash = (self.hmac_fn)(&key, &self.recv_buffer[..2]);
            if hash[0] != self.recv_buffer[2] || hash[1] != self.recv_buffer[3] {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol("auth_aes128: HMAC mismatch".into()));
            }

            // Length (little-endian)
            let length = (self.recv_buffer[1] as usize) << 8 | self.recv_buffer[0] as usize;

            if length >= 8192 || length < 8 {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol("auth_aes128: invalid length".into()));
            }

            if length > self.recv_buffer.len() {
                break;
            }

            // Verify trailing HMAC
            let hash = (self.hmac_fn)(&key, &self.recv_buffer[..length - 4]);
            if hash[..4] != self.recv_buffer[length - 4..length] {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol("auth_aes128: trailing HMAC mismatch".into()));
            }

            self.recv_id += 1;

            // Parse rand_len
            let pos = if self.recv_buffer[4] < 255 {
                self.recv_buffer[4] as usize + 4
            } else {
                ((self.recv_buffer[6] as usize) << 8 | self.recv_buffer[5] as usize) + 4
            };
            let data_size = length.saturating_sub(pos + 4);

            output.extend_from_slice(&self.recv_buffer[pos..pos + data_size]);
            self.recv_buffer.drain(..length);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_aes128_md5_data_packets() {
        // Test that pack_data and post_decrypt work for data packets (not auth header)
        let server_info = ServerInfo {
            key: vec![0x42u8; 16],
            iv: vec![0x24u8; 16],
            ..Default::default()
        };
        let mut proto = AuthAES128::new_md5(server_info);
        
        // Initialize user key
        proto.init_user_key();
        
        // Pack two data packets
        let data1 = b"hello auth_aes128 part 1";
        let data2 = b"hello auth_aes128 part 2";
        let packed1 = proto.pack_data(data1, data1.len());
        let packed2 = proto.pack_data(data2, data2.len());
        
        // Combine and decrypt
        let mut combined = packed1;
        combined.extend_from_slice(&packed2);
        
        let plain = proto.client_post_decrypt(&combined).unwrap();
        assert_eq!(&plain[..data1.len()], data1);
        assert_eq!(&plain[data1.len()..], data2);
    }

    #[test]
    fn test_aes_128_cbc_roundtrip() {
        let key = [0x42u8; 16];
        let data = b"hello aes cbc!";
        let encrypted = aes_128_cbc_encrypt(&key, data);
        let decrypted = aes_128_cbc_decrypt(&key, &encrypted);
        assert_eq!(decrypted, data);
    }
}
