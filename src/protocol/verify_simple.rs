use super::{Protocol, XorShift128Plus};
use crate::error::SsrResult;
use crate::utils::crc32::{check_crc32, fill_crc32};

const PACK_UNIT_SIZE: usize = 2000;

/// Verify Simple protocol — CRC32 verification with random padding
pub struct VerifySimple {
    recv_buffer: Vec<u8>,
    rng: XorShift128Plus,
}

impl Default for VerifySimple {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifySimple {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        let seed_val = u64::from_le_bytes(seed);
        Self {
            recv_buffer: Vec::with_capacity(16384),
            rng: XorShift128Plus::new(seed_val),
        }
    }

    fn pack_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = ((self.rng.next_u64() & 0xF) + 1) as usize;
        let out_size = rand_len + data.len() + 6;
        let mut out = vec![0u8; out_size];

        // Length (2 bytes, big-endian)
        out[0] = (out_size >> 8) as u8;
        out[1] = out_size as u8;

        // Random padding
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[3..3 + rand_len]);

        // rand_len byte
        out[2] = rand_len as u8;

        // Payload
        let data_start = 2 + rand_len;
        out[data_start..data_start + data.len()].copy_from_slice(data);

        // CRC32
        fill_crc32(&mut out, out_size);

        out
    }
}

impl Protocol for VerifySimple {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize {
        0
    }
    fn need_feedback(&self) -> bool {
        false
    }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < plaindata.len() {
            let chunk_len = if plaindata.len() - offset > PACK_UNIT_SIZE {
                PACK_UNIT_SIZE
            } else {
                plaindata.len() - offset
            };
            let packed = self.pack_data(&plaindata[offset..offset + chunk_len]);
            result.extend_from_slice(&packed);
            offset += chunk_len;
        }

        Ok(result)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        // Append to recv buffer
        self.recv_buffer.extend_from_slice(data);

        let mut output = Vec::new();

        while self.recv_buffer.len() > 2 {
            let length = ((self.recv_buffer[0] as usize) << 8) | self.recv_buffer[1] as usize;

            if !(7..8192).contains(&length) {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "verify_simple: invalid length".into(),
                ));
            }

            if length > self.recv_buffer.len() {
                break;
            }

            // Check CRC32
            if !check_crc32(&self.recv_buffer[..length]) {
                self.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "verify_simple: CRC32 mismatch".into(),
                ));
            }

            let rand_len = self.recv_buffer[2] as usize;
            let data_size = length.saturating_sub(rand_len + 6); // total - rand_len - 2(len) - 1(rand_len_field) - 4(crc) + 1 = rand_len-1
            let data_start = 2 + rand_len; // 2(len) + 1(rand_len_field) + (rand_len-1)(random) = 2 + rand_len

            output.extend_from_slice(&self.recv_buffer[data_start..data_start + data_size]);

            // Remove consumed data
            self.recv_buffer.drain(..length);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_simple_roundtrip() {
        let mut proto = VerifySimple::new();
        let data = b"hello verify_simple";
        let framed = proto.client_pre_encrypt(data).unwrap();
        assert!(framed.len() > data.len());
        let plain = proto.client_post_decrypt(&framed).unwrap();
        assert_eq!(plain, data);
    }

    #[test]
    fn test_verify_simple_chunked() {
        let mut proto = VerifySimple::new();
        let data = vec![0xABu8; 5000]; // Larger than PACK_UNIT_SIZE
        let framed = proto.client_pre_encrypt(&data).unwrap();
        let plain = proto.client_post_decrypt(&framed).unwrap();
        assert_eq!(plain, data);
    }
}
