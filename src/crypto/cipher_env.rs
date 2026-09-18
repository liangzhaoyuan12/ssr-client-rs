use crate::crypto::types::CipherType;
use crate::error::SsrResult;
use crate::crypto::bytes_to_key::bytes_to_key;
use crate::crypto::table::TableCipher;

/// Unified cipher environment that manages key, IV, and encrypt/decrypt operations.
pub struct CipherEnv {
    method: CipherType,
    key: Vec<u8>,
    iv_len: usize,
    table_cipher: Option<TableCipher>,
    iv_cache: std::collections::HashSet<Vec<u8>>,
}

impl CipherEnv {
    /// Create a new cipher environment from password and method name
    pub fn new(password: &str, method_name: &str) -> SsrResult<Self> {
        let method = CipherType::from_name(method_name)?;
        Self::with_method(password, method)
    }

    /// Create a new cipher environment from password and CipherType
    pub fn with_method(password: &str, method: CipherType) -> SsrResult<Self> {
        match method {
            CipherType::None => Ok(Self {
                method,
                key: Vec::new(),
                iv_len: 0,
                table_cipher: None,
                iv_cache: std::collections::HashSet::new(),
            }),
            CipherType::Table => {
                let table_cipher = TableCipher::new(password.as_bytes());
                Ok(Self {
                    method,
                    key: password.as_bytes().to_vec(),
                    iv_len: 0,
                    table_cipher: Some(table_cipher),
                    iv_cache: std::collections::HashSet::new(),
                })
            }
            _ => {
                let key_len = method.key_size();
                let key = bytes_to_key(password.as_bytes(), key_len);
                let iv_len = if method.need_iv() { method.iv_size() } else { 0 };
                Ok(Self {
                    method,
                    key,
                    iv_len,
                    table_cipher: None,
                    iv_cache: std::collections::HashSet::new(),
                })
            }
        }
    }

    /// Get the cipher method
    pub fn method(&self) -> CipherType {
        self.method
    }

    /// Get the encryption key
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Get the IV length
    pub fn iv_len(&self) -> usize {
        self.iv_len
    }

    /// Check if IV has been seen before (replay protection)
    pub fn check_iv(&mut self, iv: &[u8]) -> bool {
        if self.iv_cache.contains(iv) {
            false // IV already seen
        } else {
            self.iv_cache.insert(iv.to_vec());
            true
        }
    }

    /// Encrypt data (one-shot, with IV prepended for non-table ciphers)
    pub fn encrypt(&self, plaintext: &[u8]) -> SsrResult<Vec<u8>> {
        match self.method {
            CipherType::None => Ok(plaintext.to_vec()),
            CipherType::Table => {
                if let Some(ref table) = self.table_cipher {
                    Ok(table.encrypt(plaintext))
                } else {
                    Ok(plaintext.to_vec())
                }
            }
            _ if self.method.is_aead() => {
                // AEAD encryption is handled differently (needs context)
                Err(crate::error::SsrError::crypto("AEAD requires context-based encryption"))
            }
            _ => {
                // Stream cipher: generate IV, encrypt, prepend IV
                let iv_len = self.iv_len;
                let mut iv = vec![0u8; iv_len];
                if iv_len > 0 {
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv);
                }
                let ciphertext = crate::crypto::stream::stream_encrypt(self.method, &self.key, &iv, plaintext)?;
                let mut output = Vec::with_capacity(iv_len + ciphertext.len());
                output.extend_from_slice(&iv);
                output.extend_from_slice(&ciphertext);
                Ok(output)
            }
        }
    }

    /// Decrypt data (one-shot, expects IV prepended for non-table ciphers)
    pub fn decrypt(&self, ciphertext: &[u8]) -> SsrResult<Vec<u8>> {
        match self.method {
            CipherType::None => Ok(ciphertext.to_vec()),
            CipherType::Table => {
                if let Some(ref table) = self.table_cipher {
                    Ok(table.decrypt(ciphertext))
                } else {
                    Ok(ciphertext.to_vec())
                }
            }
            _ if self.method.is_aead() => {
                Err(crate::error::SsrError::crypto("AEAD requires context-based decryption"))
            }
            _ => {
                // Stream cipher: extract IV, decrypt
                let iv_len = self.iv_len;
                if ciphertext.len() < iv_len {
                    return Err(crate::error::SsrError::crypto("Ciphertext too short"));
                }
                let iv = &ciphertext[..iv_len];
                let data = &ciphertext[iv_len..];
                crate::crypto::stream::stream_decrypt(self.method, &self.key, iv, data)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_env_none() {
        let env = CipherEnv::new("", "none").unwrap();
        let data = b"hello";
        let encrypted = env.encrypt(data).unwrap();
        assert_eq!(encrypted, data);
    }

    #[test]
    fn test_cipher_env_table() {
        let env = CipherEnv::new("password", "table").unwrap();
        let data = b"hello world";
        let encrypted = env.encrypt(data).unwrap();
        assert_ne!(encrypted, data);
        let decrypted = env.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_cipher_env_aes256_cfb() {
        let env = CipherEnv::new("password", "aes-256-cfb").unwrap();
        assert_eq!(env.method(), CipherType::AES256CFB);
        assert_eq!(env.key().len(), 32);
        assert_eq!(env.iv_len(), 16);
    }

    #[test]
    fn test_cipher_env_rc4() {
        let env = CipherEnv::new("password", "rc4").unwrap();
        let data = b"hello rc4";
        let encrypted = env.encrypt(data).unwrap();
        let decrypted = env.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_cipher_env_aes128_cfb() {
        let env = CipherEnv::new("password", "aes-128-cfb").unwrap();
        let data = b"hello aes-128-cfb";
        let encrypted = env.encrypt(data).unwrap();
        let decrypted = env.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_cipher_env_chacha20() {
        let env = CipherEnv::new("password", "chacha20").unwrap();
        let data = b"hello chacha20";
        let encrypted = env.encrypt(data).unwrap();
        let decrypted = env.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
}
