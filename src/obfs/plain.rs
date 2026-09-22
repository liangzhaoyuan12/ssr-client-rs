use super::Obfs;
use crate::error::SsrResult;

/// Plain obfuscation — pass-through, no modification.
pub struct PlainObfs;

impl Default for PlainObfs {
    fn default() -> Self {
        Self::new()
    }
}

impl PlainObfs {
    /// Create the pass-through obfs: no framing, no overhead, no feedback.
    pub fn new() -> Self {
        Self
    }
}

impl Obfs for PlainObfs {
    fn set_key(&mut self, _key: Vec<u8>) {}
    fn client_encode(&mut self, buf: &[u8]) -> SsrResult<Vec<u8>> {
        Ok(buf.to_vec())
    }

    fn client_decode(&mut self, buf: &[u8]) -> SsrResult<(Vec<u8>, bool)> {
        Ok((buf.to_vec(), false))
    }

    fn get_overhead(&self) -> usize {
        0
    }

    fn need_feedback(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_encode_decode_roundtrip() {
        let mut obfs = PlainObfs::new();
        let data = b"hello world";
        let encoded = obfs.client_encode(data).unwrap();
        assert_eq!(encoded, data);
        let (decoded, feedback) = obfs.client_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert!(!feedback);
    }

    #[test]
    fn test_plain_empty() {
        let mut obfs = PlainObfs::new();
        let encoded = obfs.client_encode(b"").unwrap();
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_plain_overhead() {
        let obfs = PlainObfs::new();
        assert_eq!(obfs.get_overhead(), 0);
        assert!(!obfs.need_feedback());
    }
}
