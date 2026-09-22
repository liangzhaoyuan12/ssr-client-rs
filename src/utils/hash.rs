use digest::Digest;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

type HmacMD5 = Hmac<Md5>;
type HmacSHA1 = Hmac<Sha1>;

/// MD5 hash
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// MD5 hash with multiple data slices
pub fn md5_multi(data: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for d in data {
        hasher.update(d);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// SHA1 hash
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// HMAC-MD5
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let Ok(mut mac) = HmacMD5::new_from_slice(key) else {
        // hmac-0.12 accepts any key length, so this arm is unreachable.
        debug_assert!(false, "hmac-0.12 accepts any key length");
        return [0u8; 16];
    };
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA1
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let Ok(mut mac) = HmacSHA1::new_from_slice(key) else {
        // hmac-0.12 accepts any key length, so this arm is unreachable.
        debug_assert!(false, "hmac-0.12 accepts any key length");
        return [0u8; 20];
    };
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA1 with multiple data slices
pub fn hmac_sha1_multi(key: &[u8], data: &[&[u8]]) -> [u8; 20] {
    let Ok(mut mac) = HmacSHA1::new_from_slice(key) else {
        // hmac-0.12 accepts any key length, so this arm is unreachable.
        debug_assert!(false, "hmac-0.12 accepts any key length");
        return [0u8; 20];
    };
    for d in data {
        mac.update(d);
    }
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// HMAC-MD5 with multiple data slices
pub fn hmac_md5_multi(key: &[u8], data: &[&[u8]]) -> [u8; 16] {
    let Ok(mut mac) = HmacMD5::new_from_slice(key) else {
        // hmac-0.12 accepts any key length, so this arm is unreachable.
        debug_assert!(false, "hmac-0.12 accepts any key length");
        return [0u8; 16];
    };
    for d in data {
        mac.update(d);
    }
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let hash = md5(b"hello");
        assert_eq!(hex::encode(hash), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha1() {
        let hash = sha1(b"hello");
        assert_eq!(
            hex::encode(hash),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }

    #[test]
    fn test_hmac_md5() {
        let hash = hmac_md5(b"key", b"message");
        // Just verify it produces 16 bytes without panicking
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_hmac_sha1() {
        let hash = hmac_sha1(b"key", b"message");
        assert_eq!(hash.len(), 20);
    }
}
