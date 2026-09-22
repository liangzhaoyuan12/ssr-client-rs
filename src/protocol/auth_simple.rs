use super::{get_s5_head_size, memintcopy_lt, GlobalData, Protocol, XorShift128Plus};
use crate::error::SsrResult;
use crate::utils::crc32::{check_crc32, fill_crc32};

const PACK_UNIT_SIZE: usize = 2000;

/// Auth Simple protocol — CRC32 verification with auth header (timestamp + client_id + connection_id)
pub struct AuthSimple {
    has_sent_header: bool,
    has_recv_header: bool,
    recv_buffer: Vec<u8>,
    global: GlobalData,
    rng: XorShift128Plus,
}

impl Default for AuthSimple {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthSimple {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        let seed_val = u64::from_le_bytes(seed);
        Self {
            has_sent_header: false,
            has_recv_header: false,
            recv_buffer: Vec::with_capacity(16384),
            global: GlobalData::new(),
            rng: XorShift128Plus::new(seed_val),
        }
    }

    fn pack_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = ((self.rng.next_u64() & 0xF) + 1) as usize;
        let out_size = rand_len + data.len() + 6;
        let mut out = vec![0u8; out_size];

        out[0] = (out_size >> 8) as u8;
        out[1] = out_size as u8;
        out[2] = rand_len as u8;

        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[3..3 + rand_len]);

        let data_start = 2 + rand_len;
        out[data_start..data_start + data.len()].copy_from_slice(data);

        fill_crc32(&mut out, out_size);
        out
    }

    fn pack_auth_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = ((self.rng.next_u64() & 0xF) + 1) as usize;
        let out_size = rand_len + data.len() + 6 + 12;
        let mut out = vec![0u8; out_size];

        out[0] = (out_size >> 8) as u8;
        out[1] = out_size as u8;
        out[2] = rand_len as u8;

        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[3..3 + rand_len]);

        let data_offset = rand_len + 2;

        // Timestamp (4 bytes, little-endian)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        memintcopy_lt(&mut out[data_offset..data_offset + 4], now);

        // Client ID (4 bytes)
        self.global.increment();
        out[data_offset + 4..data_offset + 8].copy_from_slice(&self.global.local_client_id[..4]);

        // Connection ID (4 bytes, little-endian)
        memintcopy_lt(
            &mut out[data_offset + 8..data_offset + 12],
            self.global.connection_id,
        );

        // Payload
        let payload_offset = data_offset + 12;
        out[payload_offset..payload_offset + data.len()].copy_from_slice(data);

        fill_crc32(&mut out, out_size);
        out
    }
}

impl Protocol for AuthSimple {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize {
        0
    }
    fn need_feedback(&self) -> bool {
        false
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

        while self.recv_buffer.len() > 2 {
            let length = ((self.recv_buffer[0] as usize) << 8) | self.recv_buffer[1] as usize;

            if !(7..8192).contains(&length) {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_simple: invalid length".into(),
                ));
            }

            if length > self.recv_buffer.len() {
                break;
            }

            // Check CRC32
            if !check_crc32(&self.recv_buffer[..length]) {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_simple: CRC32 mismatch".into(),
                ));
            }

            let rand_len = self.recv_buffer[2] as usize;
            let data_size = length.saturating_sub(rand_len + 6);
            let data_start = 2 + rand_len; // 2(len) + 1(rand_len_field) + rand_len(random_data)

            let mut payload = self.recv_buffer[data_start..data_start + data_size].to_vec();

            // First received packet has auth header (timestamp + client_id + connection_id = 12 bytes)
            if !self.has_recv_header && payload.len() >= 12 {
                payload.drain(..12);
                self.has_recv_header = true;
            }

            output.extend_from_slice(&payload);
            self.recv_buffer.drain(..length);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_simple_roundtrip() {
        let mut proto = AuthSimple::new();
        let data = b"hello auth_simple";
        let framed = proto.client_pre_encrypt(data).unwrap();
        assert!(framed.len() > data.len());
        let plain = proto.client_post_decrypt(&framed).unwrap();
        assert_eq!(plain, data);
    }

    #[test]
    fn test_auth_simple_has_header() {
        let mut proto = AuthSimple::new();
        assert!(!proto.has_sent_header);
        let data = b"first packet";
        let _ = proto.client_pre_encrypt(data).unwrap();
        assert!(proto.has_sent_header);
    }
}
