//! Shadowsocks-AEAD (SIP004) support for the SSR relay.
//!
//! Mirrors `ssr-n/src/aead.c`. TCP wire format:
//!
//! ```text
//! [salt][encrypted length][length tag][encrypted payload][payload tag] ...
//! ```
//!
//! * `salt` is `key_len` random bytes, sent once at the head of the stream.
//! * The per-session subkey is `HKDF_SHA1(salt, master_key, "ss-subkey")`.
//! * Length is a 2-byte big-endian value masked with `0x3FFF`; a chunk carries
//!   at most 16383 bytes.
//! * The nonce starts at zero and increments as an unsigned little-endian
//!   integer after every AEAD operation — twice per chunk (length, payload).
//!
//! The AEAD branch of the C `cipher_env_new_instance` never populates
//! `env->enc_key`, so `enc_get_key_len()`/`enc_get_iv_len()` both report 0.
//! Callers must therefore see an empty cipher key and IV for AEAD (the obfs and
//! protocol layers derive empty keys); the real master key is kept privately
//! here for HKDF.

use crate::crypto::types::CipherType;
use crate::error::{SsrError, SsrResult};
use crate::utils::hash::hmac_sha1;

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::aes::cipher::consts::U12;
use aes_gcm::aes::Aes192;
use aes_gcm::{Nonce, Tag};

/// `aes-gcm` 0.11 only exports the 128- and 256-bit aliases, so define 192 here.
type Aes192Gcm = aes_gcm::AesGcm<Aes192, U12>;

/// Length prefix size in bytes.
pub const CHUNK_SIZE_LEN: usize = 2;
/// Mask applied to the length prefix (payload cap).
pub const CHUNK_SIZE_MASK: usize = 0x3FFF;
/// HKDF info string binding the subkey to this application.
const SUBKEY_INFO: &[u8] = b"ss-subkey";
/// Tag length for every supported AEAD cipher.
pub const TAG_LEN: usize = 16;

/// HKDF-SHA1 (RFC 5869): extract, then expand.
///
/// Built on the existing HMAC-SHA1 so no extra crate feature is needed.
pub fn hkdf_sha1(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let prk = hmac_sha1(salt, ikm);
    let mut okm = Vec::with_capacity(okm_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < okm_len {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_sha1(&prk, &input).to_vec();
        okm.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(okm_len);
    okm
}

/// Increment a little-endian counter (the C code's `sodium_increment`).
fn increment_le(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            return;
        }
    }
}

/// An initialised AEAD cipher.
pub enum AeadCipher {
    Aes128Gcm(Box<aes_gcm::Aes128Gcm>),
    Aes192Gcm(Box<Aes192Gcm>),
    Aes256Gcm(Box<aes_gcm::Aes256Gcm>),
    ChaCha20Poly1305(Box<chacha20poly1305::ChaCha20Poly1305>),
    XChaCha20Poly1305(Box<chacha20poly1305::XChaCha20Poly1305>),
}

impl AeadCipher {
    /// Whether a method is one of the AEAD ciphers.
    pub fn is_aead(method: CipherType) -> bool {
        Self::key_len_of(method).is_some()
    }

    /// Master-key length (also the salt length) for a method.
    pub fn key_len_of(method: CipherType) -> Option<usize> {
        match method {
            CipherType::AES128GCM => Some(16),
            CipherType::AES192GCM => Some(24),
            CipherType::AES256GCM => Some(32),
            CipherType::ChaCha20Poly1305IETF => Some(32),
            CipherType::XChaCha20Poly1305IETF => Some(32),
            _ => None,
        }
    }

    /// Nonce length for a method.
    pub fn nonce_len_of(method: CipherType) -> Option<usize> {
        match method {
            CipherType::XChaCha20Poly1305IETF => Some(24),
            _ if Self::is_aead(method) => Some(12),
            _ => None,
        }
    }

    /// Build a cipher from a master key.
    pub fn new(method: CipherType, key: &[u8]) -> SsrResult<Self> {
        let bad = |n: &str| SsrError::crypto(format!("AEAD key init failed for {n}"));
        Ok(match method {
            CipherType::AES128GCM => AeadCipher::Aes128Gcm(Box::new(
                aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| bad("aes-128-gcm"))?,
            )),
            CipherType::AES192GCM => AeadCipher::Aes192Gcm(Box::new(
                Aes192Gcm::new_from_slice(key).map_err(|_| bad("aes-192-gcm"))?,
            )),
            CipherType::AES256GCM => AeadCipher::Aes256Gcm(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| bad("aes-256-gcm"))?,
            )),
            CipherType::ChaCha20Poly1305IETF => AeadCipher::ChaCha20Poly1305(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| bad("chacha20-ietf-poly1305"))?,
            )),
            CipherType::XChaCha20Poly1305IETF => AeadCipher::XChaCha20Poly1305(Box::new(
                chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| bad("xchacha20-ietf-poly1305"))?,
            )),
            other => {
                return Err(SsrError::crypto(format!(
                    "Cipher {other:?} is not an AEAD cipher"
                )))
            }
        })
    }

    /// Derive the per-session subkey from `salt` and build the cipher.
    pub fn new_from_salt(method: CipherType, master_key: &[u8], salt: &[u8]) -> SsrResult<Self> {
        let key_len = Self::key_len_of(method)
            .ok_or_else(|| SsrError::crypto(format!("Cipher {method:?} is not an AEAD cipher")))?;
        let subkey = hkdf_sha1(salt, master_key, SUBKEY_INFO, key_len);
        Self::new(method, &subkey)
    }

    /// Encrypt `plaintext`; returns `plaintext.len() + TAG_LEN` bytes.
    pub fn seal(&self, nonce: &[u8], plaintext: &[u8]) -> SsrResult<Vec<u8>> {
        let mut buf = plaintext.to_vec();
        let r = match self {
            AeadCipher::Aes128Gcm(c) => c.encrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
            ),
            AeadCipher::Aes192Gcm(c) => c.encrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
            ),
            AeadCipher::Aes256Gcm(c) => c.encrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
            ),
            AeadCipher::ChaCha20Poly1305(c) => c.encrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
            ),
            AeadCipher::XChaCha20Poly1305(c) => c.encrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
            ),
        };
        let tag = r.map_err(|_| SsrError::crypto("AEAD encryption failed".to_string()))?;
        buf.extend_from_slice(&tag);
        Ok(buf)
    }

    /// Decrypt `ciphertext` (`plaintext.len() + TAG_LEN` bytes), verifying the tag.
    pub fn open(&self, nonce: &[u8], ciphertext: &[u8]) -> SsrResult<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(SsrError::crypto("AEAD ciphertext too short".to_string()));
        }
        let split = ciphertext.len() - TAG_LEN;
        let (body, tag_bytes) = ciphertext.split_at(split);
        let mut buf = body.to_vec();
        let tag = Tag::try_from(tag_bytes)
            .map_err(|_| SsrError::crypto("bad AEAD tag length".to_string()))?;
        let r = match self {
            AeadCipher::Aes128Gcm(c) => c.decrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
                &tag,
            ),
            AeadCipher::Aes192Gcm(c) => c.decrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
                &tag,
            ),
            AeadCipher::Aes256Gcm(c) => c.decrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
                &tag,
            ),
            AeadCipher::ChaCha20Poly1305(c) => c.decrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
                &tag,
            ),
            AeadCipher::XChaCha20Poly1305(c) => c.decrypt_inout_detached(
                &Nonce::try_from(nonce)
                    .map_err(|_| SsrError::crypto("bad AEAD nonce length".to_string()))?,
                b"",
                (&mut buf[..]).into(),
                &tag,
            ),
        };
        r.map_err(|_| SsrError::crypto("AEAD authentication failed".to_string()))?;
        Ok(buf)
    }
}

/// Encrypting AEAD stream state (client → server).
pub struct AeadEncryptCtx {
    method: CipherType,
    master_key: Vec<u8>,
    cipher: Option<AeadCipher>,
    nonce: Vec<u8>,
    /// Salt, transmitted once at the head of the stream.
    salt: Vec<u8>,
    init: bool,
}

impl AeadEncryptCtx {
    pub fn new(method: CipherType, master_key: &[u8]) -> SsrResult<Self> {
        let key_len = AeadCipher::key_len_of(method)
            .ok_or_else(|| SsrError::crypto(format!("Cipher {method:?} is not an AEAD cipher")))?;
        let nonce_len = AeadCipher::nonce_len_of(method).unwrap_or(12);
        let mut salt = vec![0u8; key_len];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        Ok(Self {
            method,
            master_key: master_key.to_vec(),
            cipher: None,
            nonce: vec![0u8; nonce_len],
            salt,
            init: false,
        })
    }

    /// The salt that will prefix the first encrypted packet.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Encrypt one buffer. The salt is emitted once, then the payload is split
    /// into `<= 0x3FFF`-byte chunks exactly like `aead_encrypt`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> SsrResult<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + self.salt.len() + 64);
        if !self.init {
            self.cipher = Some(AeadCipher::new_from_salt(
                self.method,
                &self.master_key,
                &self.salt,
            )?);
            out.extend_from_slice(&self.salt);
            self.init = true;
        }
        if plaintext.is_empty() {
            return Ok(out);
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| SsrError::Crypto("AEAD cipher not initialised".to_string()))?;
        let mut off = 0usize;
        while off < plaintext.len() {
            let n = (plaintext.len() - off).min(CHUNK_SIZE_MASK);
            let len_be = ((n & CHUNK_SIZE_MASK) as u16).to_be_bytes();
            let sealed_len = cipher.seal(&self.nonce, &len_be)?;
            out.extend_from_slice(&sealed_len);
            increment_le(&mut self.nonce);
            let sealed = cipher.seal(&self.nonce, &plaintext[off..off + n])?;
            out.extend_from_slice(&sealed);
            increment_le(&mut self.nonce);
            off += n;
        }
        Ok(out)
    }
}

/// Decrypting AEAD stream state (server → client).
pub struct AeadDecryptCtx {
    method: CipherType,
    master_key: Vec<u8>,
    cipher: Option<AeadCipher>,
    nonce: Vec<u8>,
    key_len: usize,
    /// Bytes received that do not yet form a complete chunk.
    buf: Vec<u8>,
    init: bool,
}

impl AeadDecryptCtx {
    pub fn new(method: CipherType, master_key: &[u8]) -> SsrResult<Self> {
        let key_len = AeadCipher::key_len_of(method)
            .ok_or_else(|| SsrError::crypto(format!("Cipher {method:?} is not an AEAD cipher")))?;
        let nonce_len = AeadCipher::nonce_len_of(method).unwrap_or(12);
        Ok(Self {
            method,
            master_key: master_key.to_vec(),
            cipher: None,
            nonce: vec![0u8; nonce_len],
            key_len,
            buf: Vec::new(),
            init: false,
        })
    }

    /// Feed ciphertext; returns whatever plaintext became available.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> SsrResult<Vec<u8>> {
        self.buf.extend_from_slice(ciphertext);
        if !self.init {
            // The salt can be split across packets, so wait until it is complete.
            if self.buf.len() <= self.key_len {
                return Ok(Vec::new());
            }
            let salt = self.buf[..self.key_len].to_vec();
            self.buf.drain(..self.key_len);
            self.cipher = Some(AeadCipher::new_from_salt(
                self.method,
                &self.master_key,
                &salt,
            )?);
            self.init = true;
        }
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| SsrError::Crypto("AEAD cipher not initialised".to_string()))?;
        let mut out = Vec::new();
        loop {
            // Need the length block plus at least one payload byte.
            if self.buf.len() <= CHUNK_SIZE_LEN + 2 * TAG_LEN {
                break;
            }
            let len_block = &self.buf[..CHUNK_SIZE_LEN + TAG_LEN];
            let len_plain = cipher.open(&self.nonce, len_block)?;
            if len_plain.len() != CHUNK_SIZE_LEN {
                return Err(SsrError::crypto("AEAD bad length prefix".to_string()));
            }
            let n = (((len_plain[0] as usize) << 8) | len_plain[1] as usize) & CHUNK_SIZE_MASK;
            if n == 0 {
                return Err(SsrError::crypto("AEAD zero-length chunk".to_string()));
            }
            let chunk_len = CHUNK_SIZE_LEN + 2 * TAG_LEN + n;
            if self.buf.len() < chunk_len {
                // Incomplete chunk: leave the nonce alone and wait for more data.
                break;
            }
            increment_le(&mut self.nonce);
            let payload = self.buf[CHUNK_SIZE_LEN + TAG_LEN..chunk_len].to_vec();
            let plain = cipher.open(&self.nonce, &payload)?;
            if plain.len() != n {
                return Err(SsrError::crypto("AEAD bad payload length".to_string()));
            }
            increment_le(&mut self.nonce);
            out.extend_from_slice(&plain);
            self.buf.drain(..chunk_len);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha1_matches_rfc5869_style_expansion() {
        // 20-byte PRK output then a second round for >20 bytes.
        let short = hkdf_sha1(b"salt", b"ikm", b"info", 16);
        assert_eq!(short.len(), 16);
        let long = hkdf_sha1(b"salt", b"ikm", b"info", 32);
        assert_eq!(long.len(), 32);
        // The first 20 bytes of both must agree (T(1) is shared).
        assert_eq!(&long[..16], &short[..16]);
        // T(2) must depend on T(1) and the counter, so no repetition.
        assert_ne!(&long[16..32], &long[0..16]);
    }

    #[test]
    fn increment_le_is_little_endian_with_carry() {
        let mut n = [0u8, 0u8, 0u8];
        increment_le(&mut n);
        assert_eq!(n, [1, 0, 0]);
        let mut n = [0xffu8, 0x00, 0x00];
        increment_le(&mut n);
        assert_eq!(n, [0x00, 0x01, 0x00]);
        let mut n = [0xffu8, 0xff, 0xff];
        increment_le(&mut n);
        assert_eq!(n, [0x00, 0x00, 0x00]);
    }

    #[test]
    fn large_payload_is_split_into_masked_chunks() {
        let method = CipherType::AES256GCM;
        let mut enc = AeadEncryptCtx::new(method, &[7u8; 32]).unwrap();
        // One byte past the chunk cap must produce two chunks.
        let data = vec![0xabu8; CHUNK_SIZE_MASK + 1];
        let wire = enc.encrypt(&data).unwrap();
        // salt + (2+16) + n + 16  for chunk 1, then (2+16) + 1 + 16 for chunk 2
        let expect = 32 + (2 + TAG_LEN) + CHUNK_SIZE_MASK + TAG_LEN + (2 + TAG_LEN) + 1 + TAG_LEN;
        assert_eq!(wire.len(), expect);
        assert_eq!(&wire[..32], enc.salt());
    }

    #[test]
    fn roundtrip_handles_split_packets() {
        for method in [
            CipherType::AES128GCM,
            CipherType::AES192GCM,
            CipherType::AES256GCM,
            CipherType::ChaCha20Poly1305IETF,
            CipherType::XChaCha20Poly1305IETF,
        ] {
            let key_len = AeadCipher::key_len_of(method).unwrap();
            let key = vec![0x5au8; key_len];
            let mut enc = AeadEncryptCtx::new(method, &key).unwrap();
            let wire = enc.encrypt(b"hello aead world").unwrap();

            // Feed the ciphertext one byte at a time: the decryptor must buffer.
            let mut dec = AeadDecryptCtx::new(method, &key).unwrap();
            let mut got = Vec::new();
            for b in &wire {
                got.extend_from_slice(&dec.decrypt(&[*b]).unwrap());
            }
            assert_eq!(got, b"hello aead world", "byte-at-a-time {method:?}");

            // And all at once.
            let mut dec = AeadDecryptCtx::new(method, &key).unwrap();
            assert_eq!(dec.decrypt(&wire).unwrap(), b"hello aead world");
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let method = CipherType::AES256GCM;
        let key = vec![1u8; 32];
        let mut enc = AeadEncryptCtx::new(method, &key).unwrap();
        let mut wire = enc.encrypt(b"secret").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        let mut dec = AeadDecryptCtx::new(method, &key).unwrap();
        assert!(dec.decrypt(&wire).is_err());
    }
}
