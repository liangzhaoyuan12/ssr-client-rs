use crate::error::SsrResult;
use crate::utils::adler32::fill_adler32;
use crate::utils::crc32::crc32;
use crate::utils::hash::hmac_sha1;
use super::ss_hmac_key;
use super::{Protocol, GlobalData, ServerInfo, get_s5_head_size, memintcopy_lt, XorShift128Plus};

const PACK_UNIT_SIZE: usize = 2000;
const HMAC_SHA1_LEN: usize = 10;

pub struct AuthSHA1V4 {
    has_sent_header: bool,
    recv_buffer: Vec<u8>,
    global: GlobalData,
    server_info: ServerInfo,
    rng: XorShift128Plus,
}

impl AuthSHA1V4 {
    pub fn new(server_info: ServerInfo) -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        let seed_val = u64::from_le_bytes(seed);
        Self {
            has_sent_header: false,
            recv_buffer: Vec::with_capacity(16384),
            global: GlobalData::new(),
            server_info,
            rng: XorShift128Plus::new(seed_val),
        }
    }

    fn get_rand_len(&mut self, datalength: usize) -> usize {
        if datalength > 1300 { 1 }
        else if datalength > 400 { ((self.rng.next() & 0x7F) + 1) as usize }
        else { ((self.rng.next() & 0x3FF) + 1) as usize }
    }

    fn pack_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = self.get_rand_len(data.len());
        // C: out_size = rand_len + datalength + 8
        // Layout: [len(2)][CRC(2)][rand_len_field(1|3)][zeros(rand_len-field_size)][data][adler32(4)]
        let out_size = rand_len + data.len() + 8;
        let mut out = vec![0u8; out_size];
        out[0] = (out_size >> 8) as u8;
        out[1] = out_size as u8;
        let crc_val = crc32(&out[0..2]);
        out[2] = crc_val as u8;
        out[3] = (crc_val >> 8) as u8;
        if rand_len < 128 {
            out[4] = rand_len as u8;
        } else {
            out[4] = 0xFF;
            out[5] = (rand_len >> 8) as u8;
            out[6] = rand_len as u8;
        }
        // C does NOT fill the gap with random data — zeros from calloc
        let data_start = rand_len + 4;
        out[data_start..data_start + data.len()].copy_from_slice(data);
        fill_adler32(&mut out, out_size);
        out
    }

    fn pack_auth_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = self.get_rand_len(data.len());
        // C: data_offset = rand_len + 4 + 2 = rand_len + 6
        // C: out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN
        let data_offset = rand_len + 6;
        let out_size = data_offset + data.len() + 12 + HMAC_SHA1_LEN;
        let mut out = vec![0u8; out_size];
        // CRC salt: [out_size(2)][salt][key]
        let salt = b"auth_sha1_v4";
        let mut crc_salt = Vec::new();
        crc_salt.push((out_size >> 8) as u8);
        crc_salt.push(out_size as u8);
        crc_salt.extend_from_slice(salt);
        crc_salt.extend_from_slice(&self.server_info.key);
        let crc_val = crc32(&crc_salt);
        out[0] = (out_size >> 8) as u8;
        out[1] = out_size as u8;
        // C uses fillcrc32to which writes 4 bytes (full CRC32 LE)
        let crc_bytes = crc_val.to_le_bytes();
        out[2] = crc_bytes[0];
        out[3] = crc_bytes[1];
        out[4] = crc_bytes[2];
        out[5] = crc_bytes[3];
        // rand_len field at position 6
        if rand_len < 128 {
            out[6] = rand_len as u8;
        } else {
            out[6] = 0xFF;
            out[7] = (rand_len >> 8) as u8;
            out[8] = rand_len as u8;
        }
        // Gap between rand_len field and auth data is zeros (from calloc)
        // Auth data: timestamp, client_id, connection_id
        self.global.increment();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        memintcopy_lt(&mut out[data_offset..data_offset + 4], now);
        out[data_offset + 4..data_offset + 8].copy_from_slice(&self.global.local_client_id[..4]);
        memintcopy_lt(&mut out[data_offset + 8..data_offset + 12], self.global.connection_id);
        // Data after auth
        out[data_offset + 12..data_offset + 12 + data.len()].copy_from_slice(data);
        // HMAC — pad key to match C's ss_sha1_hmac: [iv(16)][key(32)][zeros(32)]
        let hmac_key = ss_hmac_key(&self.server_info.iv, &self.server_info.key);
        let hash = hmac_sha1(&hmac_key, &out[..out_size - HMAC_SHA1_LEN]);
        out[out_size - HMAC_SHA1_LEN..].copy_from_slice(&hash[..HMAC_SHA1_LEN]);
        out
    }
}

impl Protocol for AuthSHA1V4 {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize { 0 }
    fn need_feedback(&self) -> bool { true }
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
        // C: auth_sha1_v4_client_post_decrypt (auth.c:772)
        // Client ONLY receives pack_data packets from the server (not pack_auth_data).
        // No auth header, no HMAC, no CRC with salt — just data packet processing.
        use crate::utils::adler32::check_adler32;

        self.recv_buffer.extend_from_slice(data);
        let mut output = Vec::new();

        while self.recv_buffer.len() > 4 {
            let recv = &self.recv_buffer;
            // CRC check: crc32(buffer[0..2]) truncated to uint16, compare with buffer[2..3]
            let crc_val = crc32(&recv[0..2]);
            let crc_stock = ((recv[3] as u32) << 8) | (recv[2] as u32);
            if (crc_val & 0xFFFF) != crc_stock {
                self.recv_buffer.clear();
                break;
            }
            let length = ((recv[0] as usize) << 8) | recv[1] as usize;
            if length >= 8192 || length < 7 {
                self.recv_buffer.clear();
                break;
            }
            if length > self.recv_buffer.len() {
                break; // wait for more data
            }
            // Adler32 check
            if !check_adler32(&recv[..length]) {
                self.recv_buffer.clear();
                break;
            }
            // Extract data from pack_data format:
            // [length(2)][CRC(2)][rand_len(1|3)][zeros(rand_len)][data][adler32(4)]
            let pos = recv[4] as usize;
            let data_start = if pos < 255 { pos + 4 } else { ((recv[5] as usize) << 8 | recv[6] as usize) + 4 };
            let data_size = length.saturating_sub(data_start + 4); // -4 for adler32
            if data_size > 0 {
                output.extend_from_slice(&recv[data_start..data_start + data_size]);
            }
            self.recv_buffer.drain(..length);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_sha1_v4_roundtrip() {
        let server_info = ServerInfo {
            key: vec![0x42u8; 16],
            iv: vec![0x24u8; 16],
            ..Default::default()
        };
        let mut proto = AuthSHA1V4::new(server_info);
        // Phase 1: client_pre_encrypt with address → generates pack_auth_data (auth header)
        let address = vec![0x01, 127, 0, 0, 1, 0x46, 0xA0]; // 127.0.0.1:18080
        let framed = proto.client_pre_encrypt(&address).unwrap();
        assert!(framed.len() > address.len());
        // Phase 2: client_pre_encrypt with data → generates pack_data packets
        let data = b"hello auth_sha1_v4";
        let data_framed = proto.client_pre_encrypt(data).unwrap();
        assert!(data_framed.len() > data.len());
        // client_post_decrypt only handles data packets (not auth header)
        let plain = proto.client_post_decrypt(&data_framed).unwrap();
        assert_eq!(plain, data);
    }
}
