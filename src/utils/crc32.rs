/// CRC32 hash
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// CRC32 hash as bytes (little-endian)
pub fn crc32_bytes(data: &[u8]) -> [u8; 4] {
    let val = crc32(data);
    val.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        let hash = crc32(b"hello");
        assert_eq!(hash, 0x3610a686);
    }
}
