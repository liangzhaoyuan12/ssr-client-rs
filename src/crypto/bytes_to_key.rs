use md5::Md5;
use digest::Digest;

/// EVP_BytesToKey key derivation (MD5 iteration)
/// Used by Shadowsocks to derive encryption key from password.
pub fn bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    let mut md_buf = [0u8; 16];

    // First iteration: MD5(password)
    let hash = Md5::digest(password);
    md_buf.copy_from_slice(&hash);

    let mut offset = 0;
    let mut addmd = false;

    while offset < key_len {
        let mut hasher = Md5::new();
        if addmd {
            hasher.update(md_buf);
        }
        hasher.update(password);
        let result = hasher.finalize();
        md_buf.copy_from_slice(&result);

        let bytes_to_copy = std::cmp::min(16, key_len - offset);
        key[offset..offset + bytes_to_copy].copy_from_slice(&md_buf[..bytes_to_copy]);
        offset += bytes_to_copy;
        addmd = true;
    }

    key
}

/// EVP_BytesToKey with explicit md_size (for auth_chain salt-based key derivation)
pub fn bytes_to_key_with_size(password: &[u8], md_size: usize) -> Vec<u8> {
    let mut md = vec![0u8; md_size];
    let mut result = Md5::digest(password);

    let copy_len = std::cmp::min(16, md_size);
    md[..copy_len].copy_from_slice(&result[..copy_len]);

    let mut i = 16;
    while i < md_size {
        let mut hasher = Md5::new();
        hasher.update(result);
        hasher.update(password);
        result = hasher.finalize();
        let copy_len = std::cmp::min(16, md_size - i);
        md[i..i + copy_len].copy_from_slice(&result[..copy_len]);
        i += 16;
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_key_16() {
        let key = bytes_to_key(b"password", 16);
        assert_eq!(key.len(), 16);
        let key2 = bytes_to_key(b"password", 16);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_bytes_to_key_32() {
        let key = bytes_to_key(b"password", 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_bytes_to_key_empty() {
        let key = bytes_to_key(b"", 16);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_bytes_to_key_with_size() {
        let md = bytes_to_key_with_size(b"test", 32);
        assert_eq!(md.len(), 32);
    }
}
