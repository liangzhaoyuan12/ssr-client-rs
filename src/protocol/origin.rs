use crate::error::SsrResult;
use super::Protocol;

/// Origin protocol — pass-through, no framing
pub struct Origin;

impl Protocol for Origin {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize { 0 }
    fn need_feedback(&self) -> bool { false }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        Ok(plaindata.to_vec())
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin_roundtrip() {
        let mut proto = Origin;
        let data = b"hello world";
        let framed = proto.client_pre_encrypt(data).unwrap();
        assert_eq!(framed, data);
        let plain = proto.client_post_decrypt(&framed).unwrap();
        assert_eq!(plain, data);
    }
}
