/// Adler-32 checksum (used by SSR auth_sha1 protocol)
pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Compute Adler32 of buffer[0..len-4] and write to buffer[len-4..len] (little-endian)
pub fn fill_adler32(buffer: &mut [u8], total_size: usize) {
    let data_len = total_size - 4;
    let checksum = adler32(&buffer[..data_len]);
    let bytes = checksum.to_le_bytes();
    buffer[total_size - 4] = bytes[0];
    buffer[total_size - 3] = bytes[1];
    buffer[total_size - 2] = bytes[2];
    buffer[total_size - 1] = bytes[3];
}

/// Check if Adler32 of buffer[0..len-4] matches buffer[len-4..len] (little-endian)
pub fn check_adler32(buffer: &[u8]) -> bool {
    if buffer.len() < 4 {
        return false;
    }
    let data_len = buffer.len() - 4;
    let computed = adler32(&buffer[..data_len]);
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
    fn test_adler32_basic() {
        let data = b"Hello, world!";
        let checksum = adler32(data);
        assert!(checksum != 0);
    }

    #[test]
    fn test_fill_and_check_adler32() {
        let mut buf = vec![0u8; 16];
        buf[..12].copy_from_slice(b"hello world!");
        fill_adler32(&mut buf, 16);
        assert!(check_adler32(&buf));
    }
}
