use super::{get_s5_head_size, memintcopy_lt, GlobalData, Protocol, ServerInfo, XorShift128Plus};
use crate::error::SsrResult;
use crate::utils::adler32::fill_adler32;
use crate::utils::crc32::fill_crc32_to;
use crate::utils::hash::hmac_sha1;

const PACK_UNIT_SIZE: usize = 2000;
const HMAC_SHA1_LEN: usize = 10;

pub struct AuthSHA1 {
    has_sent_header: bool,
    has_recv_header: bool,
    recv_buffer: Vec<u8>,
    global: GlobalData,
    server_info: ServerInfo,
    rng: XorShift128Plus,
}

impl AuthSHA1 {
    pub fn new(server_info: ServerInfo) -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        let seed_val = u64::from_le_bytes(seed);
        Self {
            has_sent_header: false,
            has_recv_header: false,
            recv_buffer: Vec::with_capacity(16384),
            global: GlobalData::new(),
            server_info,
            rng: XorShift128Plus::new(seed_val),
        }
    }

    fn pack_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = ((self.rng.next_u64() & 0x7F) + 1) as usize;
        let out_size = rand_len + data.len() + 6;
        let mut out = vec![0u8; out_size];
        out[0] = (out_size >> 8) as u8;
        out[1] = out_size as u8;
        out[2] = rand_len as u8;
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[3..3 + rand_len]);
        let data_start = 2 + rand_len;
        out[data_start..data_start + data.len()].copy_from_slice(data);
        fill_adler32(&mut out, out_size);
        out
    }

    fn pack_auth_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = ((self.rng.next_u64() & 0x7F) + 1) as usize;
        // Auth: CRC32(4) + length(2) + rand_len(1) + random(rand_len) + timestamp(4) + client_id(4) + connection_id(4) + data + HMAC(10)
        let data_offset = 4 + 2 + 1 + rand_len + 12;
        let out_size = data_offset + data.len() + HMAC_SHA1_LEN;
        let mut out = vec![0u8; out_size];
        fill_crc32_to(&self.server_info.key, &mut out[0..4]);
        out[4] = (out_size >> 8) as u8;
        out[5] = out_size as u8;
        out[6] = rand_len as u8;
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[7..7 + rand_len]);
        self.global.increment();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        memintcopy_lt(&mut out[7 + rand_len..7 + rand_len + 4], now);
        out[7 + rand_len + 4..7 + rand_len + 8].copy_from_slice(&self.global.local_client_id[..4]);
        memintcopy_lt(
            &mut out[7 + rand_len + 8..7 + rand_len + 12],
            self.global.connection_id,
        );
        let payload_offset = data_offset;
        out[payload_offset..payload_offset + data.len()].copy_from_slice(data);
        let mut hmac_key = Vec::new();
        hmac_key.extend_from_slice(&self.server_info.iv);
        hmac_key.extend_from_slice(&self.server_info.key);
        let hash = hmac_sha1(&hmac_key, &out[..out_size - HMAC_SHA1_LEN]);
        out[out_size - HMAC_SHA1_LEN..].copy_from_slice(&hash[..HMAC_SHA1_LEN]);
        out
    }
}

impl Protocol for AuthSHA1 {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize {
        0
    }
    fn need_feedback(&self) -> bool {
        false
    }
    fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.server_info.iv = iv;
    }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut data = plaindata;
        let mut len = plaindata.len();
        if len > 0 && !self.has_sent_header {
            let head_size = get_s5_head_size(plaindata, 30).min(len);
            let packed = self.pack_auth_data(&data[..head_size]);
            result.extend_from_slice(&packed);
            data = &data[head_size..];
            len -= head_size;
            self.has_sent_header = true;
        }
        while len > PACK_UNIT_SIZE {
            let packed = self.pack_data(&data[..PACK_UNIT_SIZE]);
            result.extend_from_slice(&packed);
            data = &data[PACK_UNIT_SIZE..];
            len -= PACK_UNIT_SIZE;
        }
        if len > 0 {
            let packed = self.pack_data(data);
            result.extend_from_slice(&packed);
        }
        Ok(result)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.recv_buffer.extend_from_slice(data);
        let mut output = Vec::new();

        if !self.has_recv_header {
            if self.recv_buffer.len() < 7 {
                return Ok(output);
            }
            let length = ((self.recv_buffer[4] as usize) << 8) | self.recv_buffer[5] as usize;
            if !(7..8192).contains(&length) {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_sha1: invalid auth length".into(),
                ));
            }
            if length > self.recv_buffer.len() {
                return Ok(output);
            }
            let mut hmac_key = Vec::new();
            hmac_key.extend_from_slice(&self.server_info.iv);
            hmac_key.extend_from_slice(&self.server_info.key);
            let hash = hmac_sha1(&hmac_key, &self.recv_buffer[..length - HMAC_SHA1_LEN]);
            if hash[..HMAC_SHA1_LEN] != self.recv_buffer[length - HMAC_SHA1_LEN..length] {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_sha1: HMAC mismatch".into(),
                ));
            }
            let rand_len = self.recv_buffer[6] as usize;
            let data_offset = 4 + 2 + 1 + rand_len + 12;
            let data_size = length - data_offset - HMAC_SHA1_LEN;
            output.extend_from_slice(&self.recv_buffer[data_offset..data_offset + data_size]);
            self.recv_buffer.drain(..length);
            self.has_recv_header = true;
        }

        while self.recv_buffer.len() > 2 {
            let length = ((self.recv_buffer[0] as usize) << 8) | self.recv_buffer[1] as usize;
            if !(7..8192).contains(&length) {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_sha1: invalid length".into(),
                ));
            }
            if length > self.recv_buffer.len() {
                break;
            }
            if !crate::utils::adler32::check_adler32(&self.recv_buffer[..length]) {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_sha1: Adler32 mismatch".into(),
                ));
            }
            let pos = self.recv_buffer[2] as usize + 2;
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
    fn test_auth_sha1_roundtrip() {
        let server_info = ServerInfo {
            key: vec![0x42u8; 16],
            iv: vec![0x24u8; 16],
            ..Default::default()
        };
        let mut proto = AuthSHA1::new(server_info);
        let data = b"hello auth_sha1";
        let framed = proto.client_pre_encrypt(data).unwrap();
        assert!(framed.len() > data.len());
        let plain = proto.client_post_decrypt(&framed).unwrap();
        assert_eq!(plain, data);
    }
}
