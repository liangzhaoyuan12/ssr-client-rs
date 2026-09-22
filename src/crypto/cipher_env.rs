use crate::crypto::types::CipherType;
use crate::error::{SsrError, SsrResult};
use crate::crypto::bytes_to_key::bytes_to_key;
use crate::crypto::table::TableCipher;
use crate::crypto::aead::{AeadCipher, AeadDecryptCtx, AeadEncryptCtx};
use cipher::{KeyIvInit, StreamCipher as _};

// For stateful encryption, we use BufEncryptor/BufDecryptor which have &mut self methods
type Aes128CfbEnc = cfb_mode::BufEncryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::BufDecryptor<aes::Aes128>;
type Aes192CfbEnc = cfb_mode::BufEncryptor<aes::Aes192>;
type Aes192CfbDec = cfb_mode::BufDecryptor<aes::Aes192>;
type Aes256CfbEnc = cfb_mode::BufEncryptor<aes::Aes256>;
type Aes256CfbDec = cfb_mode::BufDecryptor<aes::Aes256>;
type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;
type Aes192Ctr = ctr::Ctr64BE<aes::Aes192>;
type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
type BlowfishCfbEnc = cfb_mode::BufEncryptor<blowfish::Blowfish>;
type BlowfishCfbDec = cfb_mode::BufDecryptor<blowfish::Blowfish>;
type DesCfbEnc = cfb_mode::BufEncryptor<des::Des>;
type DesCfbDec = cfb_mode::BufDecryptor<des::Des>;

pub enum EncryptContext {
    None, Table,
    RC4 { cipher: rc4::Rc4 },
    AES128CFB { cipher: Aes128CfbEnc },
    AES192CFB { cipher: Aes192CfbEnc },
    AES256CFB { cipher: Aes256CfbEnc },
    AES128CTR { cipher: Aes128Ctr },
    AES192CTR { cipher: Aes192Ctr },
    AES256CTR { cipher: Aes256Ctr },
    BlowfishCFB { cipher: BlowfishCfbEnc },
    DESCFB { cipher: DesCfbEnc },
    Salsa20 { cipher: salsa20::Salsa20 },
    ChaCha20 { cipher: chacha20::ChaCha20 },
    /// AEAD streams replace the payload rather than transforming it in place,
    /// so they are handled in `encrypt_ctx` before `encrypt_in_place` runs.
    Aead(AeadEncryptCtx),
}

pub enum DecryptContext {
    None, Table,
    RC4 { cipher: rc4::Rc4 },
    AES128CFB { cipher: Aes128CfbDec },
    AES192CFB { cipher: Aes192CfbDec },
    AES256CFB { cipher: Aes256CfbDec },
    AES128CTR { cipher: Aes128Ctr },
    AES192CTR { cipher: Aes192Ctr },
    AES256CTR { cipher: Aes256Ctr },
    BlowfishCFB { cipher: BlowfishCfbDec },
    DESCFB { cipher: DesCfbDec },
    Salsa20 { cipher: salsa20::Salsa20 },
    ChaCha20 { cipher: chacha20::ChaCha20 },
    Aead(AeadDecryptCtx),
}

fn encrypt_in_place(ctx: &mut EncryptContext, output: &mut Vec<u8>) {
    match ctx {
        EncryptContext::None | EncryptContext::Table => {}
        EncryptContext::RC4 { cipher } => { cipher.apply_keystream(output); }
        EncryptContext::AES128CFB { cipher } => { cipher.encrypt(output); }
        EncryptContext::AES192CFB { cipher } => { cipher.encrypt(output); }
        EncryptContext::AES256CFB { cipher } => { cipher.encrypt(output); }
        EncryptContext::AES128CTR { cipher } => { cipher.apply_keystream(output); }
        EncryptContext::AES192CTR { cipher } => { cipher.apply_keystream(output); }
        EncryptContext::AES256CTR { cipher } => { cipher.apply_keystream(output); }
        EncryptContext::BlowfishCFB { cipher } => { cipher.encrypt(output); }
        EncryptContext::DESCFB { cipher } => { cipher.encrypt(output); }
        EncryptContext::Salsa20 { cipher } => { cipher.apply_keystream(output); }
        EncryptContext::ChaCha20 { cipher } => { cipher.apply_keystream(output); }
        // Handled in `encrypt_ctx`: AEAD changes the length, so it cannot be
        // transformed in place.
        EncryptContext::Aead(_) => unreachable!("AEAD is handled in encrypt_ctx"),
    }
}

fn decrypt_in_place(ctx: &mut DecryptContext, output: &mut Vec<u8>) {
    match ctx {
        DecryptContext::None | DecryptContext::Table => {}
        DecryptContext::RC4 { cipher } => { cipher.apply_keystream(output); }
        DecryptContext::AES128CFB { cipher } => { cipher.decrypt(output); }
        DecryptContext::AES192CFB { cipher } => { cipher.decrypt(output); }
        DecryptContext::AES256CFB { cipher } => { cipher.decrypt(output); }
        DecryptContext::AES128CTR { cipher } => { cipher.apply_keystream(output); }
        DecryptContext::AES192CTR { cipher } => { cipher.apply_keystream(output); }
        DecryptContext::AES256CTR { cipher } => { cipher.apply_keystream(output); }
        DecryptContext::BlowfishCFB { cipher } => { cipher.decrypt(output); }
        DecryptContext::DESCFB { cipher } => { cipher.decrypt(output); }
        DecryptContext::Salsa20 { cipher } => { cipher.apply_keystream(output); }
        DecryptContext::ChaCha20 { cipher } => { cipher.apply_keystream(output); }
        DecryptContext::Aead(_) => unreachable!("AEAD is handled in decrypt_ctx"),
    }
}

pub struct CipherEnv {
    method: CipherType,
    /// Cipher key reported to the obfs/protocol layers. For AEAD this is EMPTY:
    /// the C `cipher_env_new_instance` never fills `env->enc_key` on that path.
    key: Vec<u8>,
    iv_len: usize,
    table_cipher: Option<TableCipher>,
    iv_cache: std::collections::HashSet<Vec<u8>>,
    /// Master key used for AEAD HKDF subkey derivation (empty for stream ciphers).
    aead_master_key: Vec<u8>,
}

impl CipherEnv {
    pub fn new(password: &str, method_name: &str) -> SsrResult<Self> {
        let method = CipherType::from_name(method_name)?;
        Self::with_method(password, method)
    }

    pub fn with_method(password: &str, method: CipherType) -> SsrResult<Self> {
        match method {
            CipherType::None => Ok(Self { method, key: Vec::new(), iv_len: 0, table_cipher: None, iv_cache: Default::default(), aead_master_key: Vec::new() }),
            CipherType::Table => {
                let tc = TableCipher::new(password.as_bytes());
                Ok(Self { method, key: password.as_bytes().to_vec(), iv_len: 0, table_cipher: Some(tc), iv_cache: Default::default(), aead_master_key: Vec::new() })
            }
            m if AeadCipher::is_aead(m) => {
                // The C AEAD branch never populates env->enc_key, so
                // enc_get_key_len()/enc_get_iv_len() report an empty key and a
                // zero IV to the obfs and protocol layers. Keep the master key
                // private to this module for HKDF.
                let key_len = AeadCipher::key_len_of(m).expect("checked by is_aead");
                let master = bytes_to_key(password.as_bytes(), key_len);
                Ok(Self { method, key: Vec::new(), iv_len: 0, table_cipher: None, iv_cache: Default::default(), aead_master_key: master })
            }
            _ => {
                let key = bytes_to_key(password.as_bytes(), method.key_size());
                let iv_len = if method.need_iv() { method.iv_size() } else { 0 };
                Ok(Self { method, key, iv_len, table_cipher: None, iv_cache: Default::default(), aead_master_key: Vec::new() })
            }
        }
    }

    pub fn method(&self) -> CipherType { self.method }
    pub fn key(&self) -> &[u8] { &self.key }
    pub fn iv_len(&self) -> usize { self.iv_len }

    pub fn check_iv(&mut self, iv: &[u8]) -> bool {
        self.iv_cache.insert(iv.to_vec())
    }

    pub fn create_encrypt_ctx(&self) -> SsrResult<(EncryptContext, Vec<u8>)> {
        if AeadCipher::is_aead(self.method) {
            // The AEAD context emits and manages its own salt, and the C code
            // reports an empty IV to the obfs/protocol layers for AEAD.
            let ctx = AeadEncryptCtx::new(self.method, &self.aead_master_key)?;
            return Ok((EncryptContext::Aead(ctx), Vec::new()));
        }
        let iv_len = self.iv_len;
        let mut iv = vec![0u8; iv_len];
        if iv_len > 0 { rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv); }
        let ctx = self.make_encrypt_ctx(&iv)?;
        Ok((ctx, iv))
    }

    fn make_encrypt_ctx(&self, iv: &[u8]) -> SsrResult<EncryptContext> {
        use CipherType as CT;
        Ok(match self.method {
            CT::None => EncryptContext::None,
            CT::Table => EncryptContext::Table,
            CT::RC4 => {
                let mut c = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(&self.key).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))?;
                let mut skip = vec![0u8; iv.len()];
                c.apply_keystream(&mut skip);
                EncryptContext::RC4 { cipher: c }
            }
            CT::AES128CFB => EncryptContext::AES128CFB { cipher: Aes128CfbEnc::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES192CFB => EncryptContext::AES192CFB { cipher: Aes192CfbEnc::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES256CFB => EncryptContext::AES256CFB { cipher: Aes256CfbEnc::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES128CTR => EncryptContext::AES128CTR { cipher: Aes128Ctr::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES192CTR => EncryptContext::AES192CTR { cipher: Aes192Ctr::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES256CTR => EncryptContext::AES256CTR { cipher: Aes256Ctr::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::BFCFB => EncryptContext::BlowfishCFB { cipher: BlowfishCfbEnc::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::DESCFB => EncryptContext::DESCFB { cipher: DesCfbEnc::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::Salsa20 => EncryptContext::Salsa20 { cipher: <salsa20::Salsa20 as cipher::KeyIvInit>::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::ChaCha20 => {
                let piv = if iv.len() == 8 { let mut v = [0u8; 12]; v[..8].copy_from_slice(iv); v.to_vec() } else { iv.to_vec() };
                EncryptContext::ChaCha20 { cipher: <chacha20::ChaCha20 as cipher::KeyIvInit>::new_from_slices(&self.key, &piv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? }
            }
            CT::ChaCha20IETF => EncryptContext::ChaCha20 { cipher: <chacha20::ChaCha20 as cipher::KeyIvInit>::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::RC4Md5 | CT::RC4Md56 => {
                // SSR derives a per-connection RC4 key from key || iv and then
                // uses no further IV (encrypt.c:602-607). rc4-md5-6 keeps only
                // the first 6 bytes of the digest.
                let digest = crate::utils::hash::md5_multi(&[&self.key, iv]);
                let klen = if self.method == CT::RC4Md56 { 6 } else { 16 };
                let c = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(&digest[..klen]).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))?;
                EncryptContext::RC4 { cipher: c }
            }
            _ => return Err(crate::error::SsrError::crypto(format!("Cipher {:?} not supported", self.method))),
        })
    }

    pub fn encrypt_ctx(&self, ctx: &mut EncryptContext, plaintext: &[u8], _is_first: bool) -> SsrResult<Vec<u8>> {
        if let EncryptContext::Aead(a) = ctx {
            return a.encrypt(plaintext);
        }
        let mut output = plaintext.to_vec();
        encrypt_in_place(ctx, &mut output);
        Ok(output)
    }

    pub fn create_decrypt_ctx_from_ciphertext(&self, ciphertext: &[u8]) -> SsrResult<(DecryptContext, Vec<u8>)> {
        if AeadCipher::is_aead(self.method) {
            // No IV is consumed up front: the AEAD decryptor buffers until the
            // salt arrives (it may be split across packets) and returns all the
            // data untouched so `decrypt_ctx` can consume it.
            let ctx = AeadDecryptCtx::new(self.method, &self.aead_master_key)?;
            return Ok((DecryptContext::Aead(ctx), ciphertext.to_vec()));
        }
        let iv_len = self.iv_len;
        if iv_len > 0 {
            if ciphertext.len() < iv_len { return Err(crate::error::SsrError::crypto(format!("Ciphertext too short for IV"))); }
            let iv = ciphertext[..iv_len].to_vec();
            let data = ciphertext[iv_len..].to_vec();
            let ctx = self.make_decrypt_ctx(&iv)?;
            Ok((ctx, data))
        } else {
            Ok((self.make_decrypt_ctx(&[])?, ciphertext.to_vec()))
        }
    }

    fn make_decrypt_ctx(&self, iv: &[u8]) -> SsrResult<DecryptContext> {
        use CipherType as CT;
        Ok(match self.method {
            CT::None => DecryptContext::None,
            CT::Table => DecryptContext::Table,
            CT::RC4 => {
                let mut c = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(&self.key).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))?;
                let mut skip = vec![0u8; iv.len()];
                c.apply_keystream(&mut skip);
                DecryptContext::RC4 { cipher: c }
            }
            CT::AES128CFB => DecryptContext::AES128CFB { cipher: Aes128CfbDec::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES192CFB => DecryptContext::AES192CFB { cipher: Aes192CfbDec::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES256CFB => DecryptContext::AES256CFB { cipher: Aes256CfbDec::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES128CTR => DecryptContext::AES128CTR { cipher: Aes128Ctr::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES192CTR => DecryptContext::AES192CTR { cipher: Aes192Ctr::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::AES256CTR => DecryptContext::AES256CTR { cipher: Aes256Ctr::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::BFCFB => DecryptContext::BlowfishCFB { cipher: BlowfishCfbDec::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::DESCFB => DecryptContext::DESCFB { cipher: DesCfbDec::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::Salsa20 => DecryptContext::Salsa20 { cipher: <salsa20::Salsa20 as cipher::KeyIvInit>::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::ChaCha20 => {
                let piv = if iv.len() == 8 { let mut v = [0u8; 12]; v[..8].copy_from_slice(iv); v.to_vec() } else { iv.to_vec() };
                DecryptContext::ChaCha20 { cipher: <chacha20::ChaCha20 as cipher::KeyIvInit>::new_from_slices(&self.key, &piv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? }
            }
            CT::ChaCha20IETF => DecryptContext::ChaCha20 { cipher: <chacha20::ChaCha20 as cipher::KeyIvInit>::new_from_slices(&self.key, iv).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))? },
            CT::RC4Md5 | CT::RC4Md56 => {
                let digest = crate::utils::hash::md5_multi(&[&self.key, iv]);
                let klen = if self.method == CT::RC4Md56 { 6 } else { 16 };
                let c = <rc4::Rc4 as cipher::KeyInit>::new_from_slice(&digest[..klen]).map_err(|e| crate::error::SsrError::crypto(format!("{e}")))?;
                DecryptContext::RC4 { cipher: c }
            }
            _ => return Err(crate::error::SsrError::crypto(format!("Cipher {:?} not supported", self.method))),
        })
    }

    pub fn decrypt_ctx(&self, ctx: &mut DecryptContext, ciphertext: &[u8]) -> SsrResult<Vec<u8>> {
        if let DecryptContext::Aead(d) = ctx {
            return d.decrypt(ciphertext);
        }
        let mut output = ciphertext.to_vec();
        decrypt_in_place(ctx, &mut output);
        Ok(output)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> SsrResult<Vec<u8>> {
        match self.method {
            CipherType::None => Ok(plaintext.to_vec()),
            CipherType::Table => {
                if let Some(ref table) = self.table_cipher { Ok(table.encrypt(plaintext)) } else { Ok(plaintext.to_vec()) }
            }
            _ if self.method.is_aead() => Err(crate::error::SsrError::crypto(format!("AEAD requires context-based encryption"))),
            _ => {
                let iv_len = self.iv_len;
                let mut iv = vec![0u8; iv_len];
                if iv_len > 0 { rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv); }
                let ciphertext = crate::crypto::stream::stream_encrypt(self.method, &self.key, &iv, plaintext)?;
                let mut output = Vec::with_capacity(iv_len + ciphertext.len());
                output.extend_from_slice(&iv);
                output.extend_from_slice(&ciphertext);
                Ok(output)
            }
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> SsrResult<Vec<u8>> {
        match self.method {
            CipherType::None => Ok(ciphertext.to_vec()),
            CipherType::Table => {
                if let Some(ref table) = self.table_cipher { Ok(table.decrypt(ciphertext)) } else { Ok(ciphertext.to_vec()) }
            }
            _ if self.method.is_aead() => Err(crate::error::SsrError::crypto(format!("AEAD requires context-based decryption"))),
            _ => {
                let iv_len = self.iv_len;
                if ciphertext.len() < iv_len { return Err(crate::error::SsrError::crypto(format!("Ciphertext too short"))); }
                crate::crypto::stream::stream_decrypt(self.method, &self.key, &ciphertext[..iv_len], &ciphertext[iv_len..])
            }
        }
    }

    /// One-shot UDP datagram encryption.
    ///
    /// Stream/table ciphers: fresh random IV per datagram, IV prefixed
    /// (C: `ss_encrypt_all`). RC4 has `iv_len == 0`, so no IV — pure keystream.
    /// AEAD: `salt || seal(nonce = 0, plaintext) || tag`, fresh random salt per
    /// datagram, no chunk framing (C: `aead_encrypt_all`).
    pub fn encrypt_udp(&self, plaintext: &[u8]) -> SsrResult<Vec<u8>> {
        if AeadCipher::is_aead(self.method) {
            let key_len = AeadCipher::key_len_of(self.method)
                .ok_or_else(|| SsrError::crypto(format!("Cipher {:?} is not AEAD", self.method)))?;
            let nonce_len = AeadCipher::nonce_len_of(self.method).unwrap_or(12);
            let mut salt = vec![0u8; key_len];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            let cipher = AeadCipher::new_from_salt(self.method, &self.aead_master_key, &salt)?;
            let sealed = cipher.seal(&vec![0u8; nonce_len], plaintext)?;
            let mut out = salt;
            out.extend_from_slice(&sealed);
            Ok(out)
        } else {
            self.encrypt(plaintext)
        }
    }

    /// One-shot UDP datagram decryption (inverse of [`encrypt_udp`]).
    pub fn decrypt_udp(&self, ciphertext: &[u8]) -> SsrResult<Vec<u8>> {
        if AeadCipher::is_aead(self.method) {
            let key_len = AeadCipher::key_len_of(self.method)
                .ok_or_else(|| SsrError::crypto(format!("Cipher {:?} is not AEAD", self.method)))?;
            let nonce_len = AeadCipher::nonce_len_of(self.method).unwrap_or(12);
            if ciphertext.len() <= key_len {
                return Err(SsrError::crypto("AEAD UDP ciphertext too short".to_string()));
            }
            let (salt, body) = ciphertext.split_at(key_len);
            let cipher = AeadCipher::new_from_salt(self.method, &self.aead_master_key, salt)?;
            cipher.open(&vec![0u8; nonce_len], body)
        } else {
            self.decrypt(ciphertext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stateful_aes256_cfb() {
        let env = CipherEnv::new("password", "aes-256-cfb").unwrap();
        let (mut ectx, iv) = env.create_encrypt_ctx().unwrap();
        let p1 = b"hello world";
        let mut enc1 = env.encrypt_ctx(&mut ectx, p1, true).unwrap();
        enc1 = [iv.as_slice(), &enc1].concat();
        let p2 = b"another message";
        let enc2 = env.encrypt_ctx(&mut ectx, p2, false).unwrap();
        let (mut dctx, d1) = env.create_decrypt_ctx_from_ciphertext(&enc1).unwrap();
        assert_eq!(env.decrypt_ctx(&mut dctx, &d1).unwrap().as_slice(), p1);
        assert_eq!(env.decrypt_ctx(&mut dctx, &enc2).unwrap().as_slice(), p2);
    }
}
