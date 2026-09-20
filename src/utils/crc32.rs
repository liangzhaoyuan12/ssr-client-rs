/// CRC32 hash
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// CRC32 hash as bytes (little-endian)
pub fn crc32_bytes(data: &[u8]) -> [u8; 4] {
    let val = crc32(data);
    val.to_le_bytes()
}

/// Compute CRC32 of buffer[0..len-4] and write to buffer[len-4..len] (little-endian)
/// Used by SSR protocols: fillcrc32(buffer, total_size) computes CRC of first (total_size-4) bytes
pub fn fill_crc32(buffer: &mut [u8], total_size: usize) {
    let data_len = total_size - 4;
    let checksum = crc32(&buffer[..data_len]);
    let bytes = checksum.to_le_bytes();
    buffer[total_size - 4] = bytes[0];
    buffer[total_size - 3] = bytes[1];
    buffer[total_size - 2] = bytes[2];
    buffer[total_size - 1] = bytes[3];
}

/// Write CRC32 of data to outbuffer (little-endian)
pub fn fill_crc32_to(data: &[u8], outbuffer: &mut [u8]) {
    let checksum = crc32(data);
    let bytes = checksum.to_le_bytes();
    outbuffer[0] = bytes[0];
    outbuffer[1] = bytes[1];
    outbuffer[2] = bytes[2];
    outbuffer[3] = bytes[3];
}

/// Check if CRC32 of buffer[0..len-4] matches buffer[len-4..len]
pub fn check_crc32(buffer: &[u8]) -> bool {
    if buffer.len() < 4 {
        return false;
    }
    let data_len = buffer.len() - 4;
    let computed = crc32(&buffer[..data_len]);
    let expected = u32::from_le_bytes([
        buffer[data_len],
        buffer[data_len + 1],
        buffer[data_len + 2],
        buffer[data_len + 3],
    ]);
    computed == expected
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
