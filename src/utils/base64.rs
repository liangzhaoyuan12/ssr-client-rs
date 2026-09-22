use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Base64 encode
pub fn b64encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Base64 decode
pub fn b64decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(data)
}

/// Base64 URL-safe encode
pub fn b64encode_url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64 URL-safe decode
pub fn b64decode_url(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b64encode() {
        assert_eq!(b64encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn test_b64decode() {
        assert_eq!(b64decode("aGVsbG8=").unwrap(), b"hello");
    }
}
