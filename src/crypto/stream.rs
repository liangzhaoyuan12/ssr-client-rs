use crate::crypto::types::CipherType;
use crate::error::{SsrError, SsrResult};
use cipher::{KeyIvInit, StreamCipher as _};

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;
type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;
type Aes192CfbEnc = cfb_mode::Encryptor<aes::Aes192>;
type Aes192CfbDec = cfb_mode::Decryptor<aes::Aes192>;
type Aes192Ctr = ctr::Ctr64BE<aes::Aes192>;
type Aes256CfbEnc = cfb_mode::Encryptor<aes::Aes256>;
type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;
type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
type BlowfishCfbEnc = cfb_mode::Encryptor<blowfish::Blowfish>;
type BlowfishCfbDec = cfb_mode::Decryptor<blowfish::Blowfish>;
type DesCfbEnc = cfb_mode::Encryptor<des::Des>;
type DesCfbDec = cfb_mode::Decryptor<des::Des>;

/// One-shot stream-cipher encryption with an explicit key and IV.
///
/// `none` returns the plaintext unchanged; `rc4-md5`/`rc4-md5-6` fold the IV
/// into the key as `md5(key || iv)` (C: `cipher_context_set_iv`,
/// ssr-n/src/encrypt.c); for salsa20/chacha20 the IV is the nonce. The IV is
/// not prepended to the output.
///
/// # Errors
/// Returns `SsrError::Crypto` when the cipher rejects the key/IV lengths or
/// when `method` is not a stream cipher (`table` and the AEAD methods reach
/// this error arm).
pub fn stream_encrypt(
    method: CipherType,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> SsrResult<Vec<u8>> {
    match method {
        CipherType::None => Ok(plaintext.to_vec()),
        CipherType::RC4 => {
            let mut cipher = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(key)
                .map_err(|e| SsrError::crypto(format!("RC4 init: {e}")))?;
            let mut output = plaintext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::RC4Md56 | CipherType::RC4Md5 => {
            let true_key = <md5::Md5 as digest::Digest>::digest([key, iv].concat());
            let mut cipher = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(&true_key)
                .map_err(|e| SsrError::crypto(format!("RC4-MD5 init: {e}")))?;
            let mut output = plaintext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::AES128CFB => {
            let mut output = plaintext.to_vec();
            Aes128CfbEnc::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-128-CFB init: {e}")))?
                .encrypt(&mut output);
            Ok(output)
        }
        CipherType::AES192CFB => {
            let mut output = plaintext.to_vec();
            Aes192CfbEnc::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-192-CFB init: {e}")))?
                .encrypt(&mut output);
            Ok(output)
        }
        CipherType::AES256CFB => {
            let mut output = plaintext.to_vec();
            Aes256CfbEnc::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-256-CFB init: {e}")))?
                .encrypt(&mut output);
            Ok(output)
        }
        CipherType::AES128CTR => {
            let mut output = plaintext.to_vec();
            Aes128Ctr::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-128-CTR init: {e}")))?
                .apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::AES192CTR => {
            let mut output = plaintext.to_vec();
            Aes192Ctr::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-192-CTR init: {e}")))?
                .apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::AES256CTR => {
            let mut output = plaintext.to_vec();
            Aes256Ctr::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-256-CTR init: {e}")))?
                .apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::BFCFB => {
            let mut output = plaintext.to_vec();
            BlowfishCfbEnc::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("Blowfish-CFB init: {e}")))?
                .encrypt(&mut output);
            Ok(output)
        }
        CipherType::DESCFB => {
            let mut output = plaintext.to_vec();
            DesCfbEnc::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("DES-CFB init: {e}")))?
                .encrypt(&mut output);
            Ok(output)
        }
        CipherType::Salsa20 => {
            let mut cipher = <salsa20::Salsa20 as cipher::KeyIvInit>::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("Salsa20 init: {e}")))?;
            let mut output = plaintext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::ChaCha20 => {
            // Original ChaCha20 (8-byte nonce, C: libsodium
            // crypto_stream_chacha20_xor_ic, encrypt.c:208-209).
            let mut cipher =
                <chacha20::ChaCha20Legacy as cipher::KeyIvInit>::new_from_slices(key, iv)
                    .map_err(|e| SsrError::crypto(format!("ChaCha20 init: {e}")))?;
            let mut output = plaintext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::ChaCha20IETF => {
            let mut cipher = <chacha20::ChaCha20 as cipher::KeyIvInit>::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("ChaCha20-IETF init: {e}")))?;
            let mut output = plaintext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        _ => Err(SsrError::crypto(format!(
            "Cipher {:?} not supported",
            method
        ))),
    }
}

/// One-shot stream-cipher decryption with an explicit key and IV.
///
/// Mirror of `stream_encrypt`: `rc4-md5`/`rc4-md5-6` derive
/// `md5(key || iv)` first, `none` passes the bytes through, and the IV must be
/// supplied separately because it is never read from `ciphertext`.
///
/// # Errors
/// Returns `SsrError::Crypto` when the cipher rejects the key/IV lengths or
/// when `method` is not a stream cipher (`table` and the AEAD methods reach
/// this error arm).
pub fn stream_decrypt(
    method: CipherType,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> SsrResult<Vec<u8>> {
    match method {
        CipherType::None => Ok(ciphertext.to_vec()),
        CipherType::RC4 => {
            let mut cipher = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(key)
                .map_err(|e| SsrError::crypto(format!("RC4 init: {e}")))?;
            let mut output = ciphertext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::RC4Md56 | CipherType::RC4Md5 => {
            let true_key = <md5::Md5 as digest::Digest>::digest([key, iv].concat());
            let mut cipher = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(&true_key)
                .map_err(|e| SsrError::crypto(format!("RC4-MD5 init: {e}")))?;
            let mut output = ciphertext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::AES128CFB => {
            let mut output = ciphertext.to_vec();
            Aes128CfbDec::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-128-CFB init: {e}")))?
                .decrypt(&mut output);
            Ok(output)
        }
        CipherType::AES192CFB => {
            let mut output = ciphertext.to_vec();
            Aes192CfbDec::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-192-CFB init: {e}")))?
                .decrypt(&mut output);
            Ok(output)
        }
        CipherType::AES256CFB => {
            let mut output = ciphertext.to_vec();
            Aes256CfbDec::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-256-CFB init: {e}")))?
                .decrypt(&mut output);
            Ok(output)
        }
        CipherType::AES128CTR => {
            let mut output = ciphertext.to_vec();
            Aes128Ctr::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-128-CTR init: {e}")))?
                .apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::AES192CTR => {
            let mut output = ciphertext.to_vec();
            Aes192Ctr::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-192-CTR init: {e}")))?
                .apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::AES256CTR => {
            let mut output = ciphertext.to_vec();
            Aes256Ctr::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("AES-256-CTR init: {e}")))?
                .apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::BFCFB => {
            let mut output = ciphertext.to_vec();
            BlowfishCfbDec::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("Blowfish-CFB init: {e}")))?
                .decrypt(&mut output);
            Ok(output)
        }
        CipherType::DESCFB => {
            let mut output = ciphertext.to_vec();
            DesCfbDec::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("DES-CFB init: {e}")))?
                .decrypt(&mut output);
            Ok(output)
        }
        CipherType::Salsa20 => {
            let mut cipher = <salsa20::Salsa20 as cipher::KeyIvInit>::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("Salsa20 init: {e}")))?;
            let mut output = ciphertext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::ChaCha20 => {
            // Original ChaCha20 (8-byte nonce, C: libsodium
            // crypto_stream_chacha20_xor_ic, encrypt.c:208-209).
            let mut cipher =
                <chacha20::ChaCha20Legacy as cipher::KeyIvInit>::new_from_slices(key, iv)
                    .map_err(|e| SsrError::crypto(format!("ChaCha20 init: {e}")))?;
            let mut output = ciphertext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        CipherType::ChaCha20IETF => {
            let mut cipher = <chacha20::ChaCha20 as cipher::KeyIvInit>::new_from_slices(key, iv)
                .map_err(|e| SsrError::crypto(format!("ChaCha20-IETF init: {e}")))?;
            let mut output = ciphertext.to_vec();
            cipher.apply_keystream(&mut output);
            Ok(output)
        }
        _ => Err(SsrError::crypto(format!(
            "Cipher {:?} not supported",
            method
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_roundtrip() {
        let data = b"hello world";
        let result = stream_encrypt(CipherType::None, &[], &[], data).unwrap();
        assert_eq!(result, data);
        let decrypted = stream_decrypt(CipherType::None, &[], &[], &result).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = [0x42u8; 16];
        let data = b"hello world test data";
        let encrypted = stream_encrypt(CipherType::RC4, &key, &[], data).unwrap();
        assert_ne!(encrypted, data);
        let decrypted = stream_decrypt(CipherType::RC4, &key, &[], &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes128_cfb_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 16];
        let data = b"hello world test data for aes-128-cfb";
        let encrypted = stream_encrypt(CipherType::AES128CFB, &key, &iv, data).unwrap();
        assert_ne!(encrypted, data);
        let decrypted = stream_decrypt(CipherType::AES128CFB, &key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes256_cfb_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let data = b"hello world test data for aes-256-cfb encryption";
        let encrypted = stream_encrypt(CipherType::AES256CFB, &key, &iv, data).unwrap();
        assert_ne!(encrypted, data);
        let decrypted = stream_decrypt(CipherType::AES256CFB, &key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_blowfish_cfb_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 8];
        let data = b"hello blowfish";
        let encrypted = stream_encrypt(CipherType::BFCFB, &key, &iv, data).unwrap();
        let decrypted = stream_decrypt(CipherType::BFCFB, &key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        // Original ChaCha20: 8-byte nonce (ssr_cipher_names.h: chacha20 iv=8).
        let key = [0x42u8; 32];
        let iv = [0x24u8; 8];
        let data = b"hello chacha20";
        let encrypted = stream_encrypt(CipherType::ChaCha20, &key, &iv, data).unwrap();
        let decrypted = stream_decrypt(CipherType::ChaCha20, &key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_salsa20_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 8];
        let data = b"hello salsa20";
        let encrypted = stream_encrypt(CipherType::Salsa20, &key, &iv, data).unwrap();
        let decrypted = stream_decrypt(CipherType::Salsa20, &key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
}
