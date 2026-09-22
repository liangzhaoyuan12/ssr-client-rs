use crate::error::SsrResult;
use crate::utils::hash::{hmac_md5, md5};
use crate::crypto::bytes_to_key::bytes_to_key;
use crate::crypto::types::CipherType;
use crate::utils::base64::b64encode;
use super::{Protocol, GlobalData, ServerInfo, memintcopy_lt, XorShift128Plus};
use cipher::{BlockCipherEncrypt, KeyInit, StreamCipher as _};
type Aes128Enc = aes::Aes128;
use std::time::{SystemTime, UNIX_EPOCH};

const SSR_BUFF_SIZE: usize = 2048;

// ==================== Shift128plus ====================

struct Shift128plusCtx {
    v: [u64; 2],
}

impl Shift128plusCtx {
    fn new() -> Self {
        Self { v: [0; 2] }
    }

    fn from_bin(data: &[u8]) -> Self {
        assert!(data.len() >= 16);
        let mut fill = [0u8; 16];
        fill[..data.len().min(16)].copy_from_slice(&data[..data.len().min(16)]);
        let mut ctx = Self::new();
        ctx.v[0] = u64::from_le_bytes(fill[0..8].try_into().unwrap());
        ctx.v[1] = u64::from_le_bytes(fill[8..16].try_into().unwrap());
        ctx
    }

    fn from_bin_datalen(data: &[u8], datalen: usize) -> Self {
        let mut fill = [0u8; 16];
        let copy_len = data.len().min(16);
        fill[..copy_len].copy_from_slice(&data[..copy_len]);
        fill[0] = datalen as u8;
        fill[1] = (datalen >> 8) as u8;
        let mut ctx = Self::new();
        ctx.v[0] = u64::from_le_bytes(fill[0..8].try_into().unwrap());
        ctx.v[1] = u64::from_le_bytes(fill[8..16].try_into().unwrap());
        for _ in 0..4 {
            ctx.next();
        }
        ctx
    }

    fn next(&mut self) -> u64 {
        let x = self.v[0];
        let y = self.v[1];
        self.v[0] = y;
        let mut x = x;
        x ^= x << 23;
        x ^= x >> 17;
        x ^= y ^ (y >> 26);
        self.v[1] = x;
        x.wrapping_add(y)
    }
}

// ==================== Auth Chain A ====================

/// Variant-specific state for the rand_len callback (C: subclass_context
/// plus server_info.overhead which the b/c/d/e/f variants read).
struct RandLenCtx {
    overhead: u16,
    b: Option<AuthChainBContext>,
    c: Option<AuthChainCContext>,
}

/// C: local->get_tcp_rand_len. Each variant callback reinitialises the random
/// context from (last_hash, datalength) itself — after its own datalength
/// guard, matching C — so the subsequent get_rand_start_pos continues that
/// same stream; otherwise the server reads the payload from a different offset.
type RandLenFn = fn(&mut Shift128plusCtx, &[u8; 16], &RandLenCtx, usize) -> usize;

/// C: auth_chain_find_pos — lower_bound, first element >= key.
/// (Rust's binary_search returns an arbitrary match on duplicates.)
fn find_pos(arr: &[i32], key: i32) -> usize {
    let mut low = 0usize;
    let mut high = arr.len() - 1;
    if key > arr[high] {
        return arr.len();
    }
    while low < high {
        let middle = (low + high) / 2;
        if key > arr[middle] {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low
}

/// C: auth_chain_a_get_rand_len (auth_chain.c:300-316)
fn rand_len_a(
    random: &mut Shift128plusCtx,
    last_hash: &[u8; 16],
    _ctx: &RandLenCtx,
    datalength: usize,
) -> usize {
    if datalength > 1440 {
        return 0;
    }
    *random = Shift128plusCtx::from_bin_datalen(last_hash, datalength);
    if datalength > 1300 {
        return (random.next() % 31) as usize;
    }
    if datalength > 900 {
        return (random.next() % 127) as usize;
    }
    if datalength > 400 {
        return (random.next() % 521) as usize;
    }
    (random.next() % 1021) as usize
}

/// C: auth_chain_b_get_rand_len (auth_chain.c:1162-1202). Uses the
/// data_size_list/data_size_list2 tables from subclass_context (rand_len_ctx.b)
/// and server_info->overhead (rand_len_ctx.overhead).
fn rand_len_b(
    random: &mut Shift128plusCtx,
    last_hash: &[u8; 16],
    ctx: &RandLenCtx,
    datalength: usize,
) -> usize {
    if datalength >= 1440 {
        return 0;
    }
    *random = Shift128plusCtx::from_bin_datalen(last_hash, datalength);
    let b = ctx
        .b
        .as_ref()
        .expect("auth_chain_b: missing data_size_list context");
    let overhead = ctx.overhead as usize;

    let pos = find_pos(&b.data_size_list, (datalength + overhead) as i32);
    let final_pos = pos + (random.next() as usize) % b.data_size_list.len();
    if final_pos < b.data_size_list.len() {
        return (b.data_size_list[final_pos] as usize).saturating_sub(datalength + overhead);
    }

    let pos2 = find_pos(&b.data_size_list2, (datalength + overhead) as i32);
    let final_pos2 = pos2 + (random.next() as usize) % b.data_size_list2.len();
    if final_pos2 < b.data_size_list2.len() {
        return (b.data_size_list2[final_pos2] as usize).saturating_sub(datalength + overhead);
    }
    if final_pos2 < pos2 + b.data_size_list2.len() - 1 {
        return 0;
    }

    if datalength > 1300 {
        return (random.next() % 31) as usize;
    }
    if datalength > 900 {
        return (random.next() % 127) as usize;
    }
    if datalength > 400 {
        return (random.next() % 521) as usize;
    }
    (random.next() % 1021) as usize
}

/// C: auth_chain_c_get_rand_len (auth_chain.c:1270-1297). Unlike A/B, the
/// PRNG is reinitialised UNCONDITIONALLY before any branch check — C's comment:
/// "must init random in here to make sure output sync in server and client".
fn rand_len_c(
    random: &mut Shift128plusCtx,
    last_hash: &[u8; 16],
    ctx: &RandLenCtx,
    datalength: usize,
) -> usize {
    let overhead = ctx.overhead as usize;
    let c = ctx
        .c
        .as_ref()
        .expect("auth_chain_c: missing data_size_list0 context");
    let other_data_size = datalength + overhead;

    *random = Shift128plusCtx::from_bin_datalen(last_hash, datalength);

    if other_data_size >= c.data_size_list0[c.data_size_list0.len() - 1] as usize {
        if datalength > 1440 {
            return 0;
        }
        if datalength > 1300 {
            return (random.next() % 31) as usize;
        }
        if datalength > 900 {
            return (random.next() % 127) as usize;
        }
        if datalength > 400 {
            return (random.next() % 521) as usize;
        }
        return (random.next() % 1021) as usize;
    }

    // other_data_size < list0.last() guarantees find_pos < len (no %0 here)
    let pos = find_pos(&c.data_size_list0, other_data_size as i32);
    let final_pos = pos + (random.next() as usize) % (c.data_size_list0.len() - pos);
    (c.data_size_list0[final_pos] as usize).saturating_sub(other_data_size)
}

/// C: auth_chain_d_get_rand_len (auth_chain.c:1368-1388). Unlike variant C,
/// the guard `other >= list0.last()` comes BEFORE the reinit and returns 0
/// directly — there is no >1440/>1300 fallback ladder here.
fn rand_len_d(
    random: &mut Shift128plusCtx,
    last_hash: &[u8; 16],
    ctx: &RandLenCtx,
    datalength: usize,
) -> usize {
    let overhead = ctx.overhead as usize;
    let c = ctx
        .c
        .as_ref()
        .expect("auth_chain_d: missing data_size_list0 context");
    let other_data_size = datalength + overhead;

    // if other_data_size > the biggest item in data_size_list0, no padding
    if other_data_size >= c.data_size_list0[c.data_size_list0.len() - 1] as usize {
        return 0;
    }

    *random = Shift128plusCtx::from_bin_datalen(last_hash, datalength);
    let pos = find_pos(&c.data_size_list0, other_data_size as i32);
    let final_pos = pos + (random.next() as usize) % (c.data_size_list0.len() - pos);
    (c.data_size_list0[final_pos] as usize).saturating_sub(other_data_size)
}

struct AuthChainAContext {
    obfs: Option<*mut AuthChainA>, // back-reference
    has_sent_header: bool,
    recv_buffer: Vec<u8>,
    recv_id: u32,
    pack_id: u32,
    user_key: Vec<u8>,
    uid: [u8; 4],
    last_data_len: usize,
    last_client_hash: [u8; 16],
    last_server_hash: [u8; 16],
    random_client: Shift128plusCtx,
    random_server: Shift128plusCtx,
    cipher_type: CipherType,
    encrypt_ctx: Option<rc4::Rc4>, // RC4 stateful cipher (encrypt direction)
    decrypt_ctx: Option<rc4::Rc4>, // RC4 stateful cipher (decrypt direction)
    unit_len: usize,
    max_time_dif: i64,
    client_id: u32,
    connection_id: u32,
    user_id_num: u32,
    client_over_head: u16,
    tcp_mss: u16,
    salt: &'static str,
    /// C: local->get_tcp_rand_len — variant dispatch (A by default)
    rand_len_fn: RandLenFn,
    /// C: local->subclass_context + overhead for the callback
    rand_len_ctx: RandLenCtx,
}

pub struct AuthChainA {
    global: GlobalData,
    server_info: ServerInfo,
    local: AuthChainAContext,
}

impl AuthChainA {
    pub fn new(server_info: ServerInfo, salt: &'static str) -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let mut local = AuthChainAContext {
            obfs: None,
            has_sent_header: false,
            recv_buffer: Vec::with_capacity(SSR_BUFF_SIZE * 2),
            recv_id: 1,
            pack_id: 1,
            user_key: Vec::new(),
            uid: [0; 4],
            last_data_len: 0,
            last_client_hash: [0; 16],
            last_server_hash: [0; 16],
            random_client: Shift128plusCtx::from_bin(&seed),
            random_server: Shift128plusCtx::from_bin(&seed[8..]),
            cipher_type: CipherType::RC4,
            encrypt_ctx: None,
            decrypt_ctx: None,
            unit_len: 2000,
            max_time_dif: 86400,
            client_id: 0,
            connection_id: 0,
            user_id_num: 0,
            client_over_head: 0,
            tcp_mss: 1460,
            salt,
            rand_len_fn: rand_len_a,
            rand_len_ctx: RandLenCtx { overhead: server_info.overhead, b: None, c: None },
        };
        local.random_client.next();
        local.random_server.next();

        let mut ctx = Self {
            global: GlobalData::new(),
            server_info,
            local,
        };
        ctx.local.tcp_mss = ctx.server_info.tcp_mss;
        ctx
    }

    /// C: get_client_rand_len — dispatch to the variant callback with
    /// random_client + last_client_hash. The callback reinitialises the PRNG
    /// (after its own datalength guard, like C) so that pack_client_data's
    /// subsequent get_rand_start_pos continues the SAME stream — otherwise the
    /// server reads the payload from a different offset.
    fn get_rand_len(local: &mut AuthChainAContext, datalength: usize) -> usize {
        let f = local.rand_len_fn;
        let AuthChainAContext {
            random_client,
            last_client_hash,
            rand_len_ctx,
            ..
        } = local;
        f(random_client, last_client_hash, rand_len_ctx, datalength)
    }

    /// C: get_server_rand_len — same dispatch for parsing packets sent BY the
    /// server (random_server + last_server_hash).
    fn get_server_rand_len(local: &mut AuthChainAContext, datalength: usize) -> usize {
        let f = local.rand_len_fn;
        let AuthChainAContext {
            random_server,
            last_server_hash,
            rand_len_ctx,
            ..
        } = local;
        f(random_server, last_server_hash, rand_len_ctx, datalength)
    }

    fn get_rand_start_pos(rand_len: usize, random: &mut Shift128plusCtx) -> usize {
        if rand_len > 0 {
            return (random.next() % 8589934609) as usize % rand_len;
        }
        0
    }

    fn init_user_key(&mut self) {
        if !self.local.user_key.is_empty() {
            return;
        }
        if !self.server_info.extra_param.is_empty() {
            if let Some(delim_pos) = self.server_info.extra_param.find(':') {
                let uid_str = &self.server_info.extra_param[..delim_pos];
                let key_str = &self.server_info.extra_param[delim_pos + 1..];
                if let Ok(uid_long) = uid_str.trim().parse::<u32>() {
                    memintcopy_lt(&mut self.local.uid, uid_long);
                    let hash = md5(key_str.as_bytes());
                    self.local.user_key = hash.to_vec();
                    return;
                }
            }
        }
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut self.local.uid);
        self.local.user_key = self.server_info.key.clone();
    }

    fn init_rc4(&mut self, password: &str) {
        // Derive RC4 key using EVP_BytesToKey (same as cipher_env_new_instance)
        let key = bytes_to_key(password.as_bytes(), 16); // RC4 key size is 16
        let enc = <rc4::Rc4 as KeyInit>::new_from_slice(&key)
            .expect("RC4 key init should not fail");
        let dec = <rc4::Rc4 as KeyInit>::new_from_slice(&key)
            .expect("RC4 key init should not fail");
        self.local.encrypt_ctx = Some(enc);
        self.local.decrypt_ctx = Some(dec);
    }

    fn encrypt_buffer(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let mut output = data.to_vec();
        if let Some(ref mut cipher) = self.local.encrypt_ctx {
            cipher.apply_keystream(&mut output);
        }
        output
    }

    fn decrypt_buffer(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let mut output = data.to_vec();
        if let Some(ref mut cipher) = self.local.decrypt_ctx {
            cipher.apply_keystream(&mut output);
        }
        output
    }



    fn pack_client_data(&mut self, data: &[u8]) -> Vec<u8> {
        let rand_len = Self::get_rand_len(&mut self.local, data.len());
        let out_size = rand_len + data.len() + 2 + 2; // +2 for length, +2 for HMAC
        let mut out = vec![0u8; out_size];

        // XOR length with last_client_hash
        let datalen = data.len() as u16;
        out[0] = (datalen ^ self.local.last_client_hash[14] as u16) as u8;
        out[1] = ((datalen >> 8) ^ self.local.last_client_hash[15] as u16) as u8;

        // Random padding + encrypted data
        use rand::RngCore;
        let rnd_data: Vec<u8> = (0..rand_len).map(|_| rand::random::<u8>()).collect();

        if data.len() > 0 {
            let start_pos = Self::get_rand_start_pos(rand_len, &mut self.local.random_client);
            let encrypted = self.encrypt_buffer(data);
            out[2..2 + start_pos].copy_from_slice(&rnd_data[..start_pos]);
            out[2 + start_pos..2 + start_pos + data.len()].copy_from_slice(&encrypted);
            out[2 + start_pos + data.len()..2 + start_pos + data.len() + rand_len - start_pos]
                .copy_from_slice(&rnd_data[start_pos..]);
        } else {
            out[2..2 + rand_len].copy_from_slice(&rnd_data);
        }

        // HMAC-MD5
        let mut key = self.local.user_key.clone();
        key.extend_from_slice(&self.local.pack_id.to_le_bytes());
        self.local.pack_id += 1;

        let hash = hmac_md5(&key, &out[..out_size - 2]);
        out[out_size - 2..].copy_from_slice(&hash[..2]);

        self.local.last_client_hash = hash;
        out
    }

    fn pack_auth_data(&mut self, data: &[u8]) -> Vec<u8> {
        // C auth_chain_a_pack_auth_data format (auth_chain.c:486-598):
        // [random(4)] [HMAC-MD5(8)] [UID(4)] [AES-CBC encrypted block(16)] [HMAC-MD5(4)] [pack_client_data(data)]
        // Total header: 4 + 8 + 4 + 16 + 4 = 36 bytes, then data packet follows
        let authhead_len = 36;
        let mut out = vec![0u8; authhead_len];

        // Increment connection_id
        self.global.increment();

        // Build key = iv + key
        let mut key = Vec::new();
        key.extend_from_slice(&self.server_info.iv);
        key.extend_from_slice(&self.server_info.key);

        // [0..4] random
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut out[0..4]);

        // [4..12] HMAC-MD5 of random(0..4), key = iv+key
        let hash = hmac_md5(&key, &out[0..4]);
        out[4..12].copy_from_slice(&hash[..8]);

        // Store hash as last_client_hash (used for RC4 key and data length XOR)
        self.local.last_client_hash = hash;

        // [12..16] UID (XORed with hash[8..12])
        for i in 0..4 {
            out[12 + i] = self.local.uid[i] ^ hash[8 + i];
        }

        // [16..32] AES-128-CBC encrypted block
        // Plaintext: timestamp(4) + client_id(4) + connection_id(4) + overhead(2) + zeros(2)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let mut plain_block = [0u8; 16];
        memintcopy_lt(&mut plain_block[0..4], now);
        plain_block[4..8].copy_from_slice(&self.global.local_client_id[..4]);
        memintcopy_lt(&mut plain_block[8..12], self.global.connection_id);
        plain_block[12] = self.server_info.overhead as u8;
        plain_block[13] = (self.server_info.overhead >> 8) as u8;
        // plain_block[14..16] = 0 (zeros)

        // Key for AES: bytes_to_key(base64(user_key) + salt, 16)
        let user_key_b64 = crate::utils::base64::b64encode(&self.local.user_key);
        let enc_key_input = format!("{}{}", user_key_b64, self.local.salt);
        let enc_key = bytes_to_key(enc_key_input.as_bytes(), 16);

        // AES-CBC encrypt with zero IV, no padding (matching C ss_aes_128_cbc_encrypt)
        let cipher = Aes128Enc::new_from_slice(&enc_key).unwrap();
        let iv = [0u8; 16];
        // XOR plaintext with zero IV (first block only, CBC mode)
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = plain_block[i] ^ iv[i];
        }
        let mut block_arr = aes::Block::clone_from_slice(&block);
        cipher.encrypt_block(&mut block_arr);
        let encrypted = block_arr.to_vec();
        // AES-CBC outputs 16 bytes (PKCS7 padded, but for 16-byte input it's exactly 16+16=32)
        // Copy encrypted block (16 bytes, no padding - matches C ss_aes_128_cbc_encrypt)
        out[16..32].copy_from_slice(&encrypted);

        // [32..36] HMAC-MD5 of bytes 12..32 (UID + encrypted block), key = user_key
        // C stores this full 16-byte hash into local->last_server_hash — the
        // server does the same when parsing our auth header, and it becomes the
        // XOR key for the first data packet the server sends us.
        let hmac_input = &out[12..32];
        let enc_hmac = hmac_md5(&self.local.user_key, hmac_input);
        out[32..36].copy_from_slice(&enc_hmac[..4]);
        self.local.last_server_hash = enc_hmac;

        // Initialize RC4 BEFORE packing the data payload (C auth_chain.c:589-595).
        // Password = base64(user_key) + base64(last_client_hash=hmac1).
        // Must happen here, not after pack_auth_data returns — the data packet
        // below is encrypted with this cipher.
        let password = format!(
            "{}{}",
            b64encode(&self.local.user_key),
            b64encode(&self.local.last_client_hash)
        );
        self.init_rc4(&password);

        // Pack data as a data packet (matching C auth_chain_a_pack_client_data)
        // The C code appends auth_chain_a_pack_client_data after the auth header
        let client_data_packet = self.pack_client_data(data);
        out.extend_from_slice(&client_data_packet);

        out
    }


    fn client_pre_encrypt_inner(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut data = plaindata;
        let mut len = plaindata.len();

        if len > 0 && !self.local.has_sent_header {
            let head_size = 1200.min(len);
            let packed = self.pack_auth_data(&data[..head_size]);
            result.extend_from_slice(&packed);
            data = &data[head_size..];
            len -= head_size;
            self.local.has_sent_header = true;
            // RC4 is initialized inside pack_auth_data (C auth_chain.c:589-593),
            // BEFORE its pack_client_data call — do not re-init here or the
            // keystream state from the header packet would be lost.
        }

        let unit_size = self.local.tcp_mss as usize - self.server_info.overhead as usize;
        while len > unit_size {
            let packed = self.pack_client_data(&data[..unit_size]);
            result.extend_from_slice(&packed);
            data = &data[unit_size..];
            len -= unit_size;
        }
        if len > 0 {
            let packed = self.pack_client_data(data);
            result.extend_from_slice(&packed);
        }

        self.local.last_data_len = plaindata.len();
        Ok(result)
    }

    /// C: auth_chain_a_client_post_decrypt (auth_chain.c:644-731).
    /// The client NEVER receives an auth header — only data packets produced by
    /// the server's server_pre_encrypt, so there is no header to skip.
    fn client_post_decrypt_inner(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        if self.local.recv_buffer.len() + data.len() > 16384 {
            return Err(crate::error::SsrError::Protocol("auth_chain: recv buffer overflow".into()));
        }
        self.local.recv_buffer.extend_from_slice(data);

        let mut output = Vec::new();
        ssr_debug!("[acapostd] feed {} bytes, buf={} first16={}", data.len(), self.local.recv_buffer.len(),
            self.local.recv_buffer.iter().take(16).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));

        while self.local.recv_buffer.len() > 4 {
            // data_len is XORed with last_server_hash[14..16] (server direction)
            let data_len = (((self.local.recv_buffer[1] ^ self.local.last_server_hash[15]) as usize) << 8)
                + (self.local.recv_buffer[0] ^ self.local.last_server_hash[14]) as usize;

            // Reinit random_server from last_server_hash + data_len, so that the
            // rand_len draw and the start_pos draw share one PRNG stream — same
            // as C get_server_rand_len followed by get_rand_start_pos.
            let rand_len = Self::get_server_rand_len(&mut self.local, data_len);
            let mut len = data_len + rand_len;
            if len >= SSR_BUFF_SIZE * 2 {
                self.local.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol("auth_chain: over size".into()));
            }
            len += 4; // +2 length field +2 HMAC
            if len > self.local.recv_buffer.len() {
                ssr_debug!("[acapostd] incomplete: data_len={} rand_len={} need={} have={}",
                    data_len, rand_len, len, self.local.recv_buffer.len());
                break;
            }

            // HMAC key = user_key + recv_id (LE u32), recv_id updated per packet
            let mut key = self.local.user_key.clone();
            key.extend_from_slice(&self.local.recv_id.to_le_bytes());
            let hash = hmac_md5(&key, &self.local.recv_buffer[..len - 2]);
            if hash[..2] != self.local.recv_buffer[len - 2..len] {
                ssr_debug!("[acapostd] HMAC mismatch: data_len={} rand_len={} recv_id={} need={} have={}",
                    data_len, rand_len, self.local.recv_id,
                    hash[..2].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
                    self.local.recv_buffer[len-2..len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
                self.local.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol("auth_chain: HMAC mismatch".into()));
            }

            // Payload offset continues the random_server stream reinit'd above
            let pos = if data_len > 0 && rand_len > 0 {
                2 + Self::get_rand_start_pos(rand_len, &mut self.local.random_server)
            } else {
                2
            };

            // Decrypt (copy slice first to avoid borrow conflict)
            let encrypted_slice = self.local.recv_buffer[pos..pos + data_len].to_vec();
            let decrypted = self.decrypt_buffer(&encrypted_slice);

            // First server packet carries tcp_mss in its first 2 bytes
            if self.local.recv_id == 1 && decrypted.len() >= 2 {
                self.local.tcp_mss = (decrypted[0] as u16) | ((decrypted[1] as u16) << 8);
                output.extend_from_slice(&decrypted[2..]);
            } else {
                output.extend_from_slice(&decrypted);
            }

            // Only the server-direction hash advances here (C line 713)
            self.local.last_server_hash = hash;
            self.local.recv_id += 1;
            self.local.recv_buffer.drain(..len);
            ssr_debug!("[acapostd] packet ok: data_len={} -> out_total={}", data_len, output.len());
        }

        Ok(output)
    }
}

impl Protocol for AuthChainA {
    fn set_salt(&mut self, salt: &str) {
        // Salt is set via constructor
        let _ = salt;
    }

    fn get_overhead(&self) -> usize {
        4
    }

    fn set_server_iv(&mut self, iv: Vec<u8>) { self.server_info.iv = iv; }

    fn need_feedback(&self) -> bool {
        true
    }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.init_user_key();
        self.client_pre_encrypt_inner(plaindata)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.client_post_decrypt_inner(data)
    }
}

// ==================== Auth Chain B ====================

struct AuthChainBContext {
    data_size_list: Vec<i32>,
    data_size_list2: Vec<i32>,
}

pub struct AuthChainB {
    inner: AuthChainA,
}

impl AuthChainB {
    pub fn new(server_info: ServerInfo) -> Self {
        // C: auth_chain_b_new_obfs = auth_chain_a_new_obfs() + swap
        // get_tcp_rand_len/salt + subclass_context; pre/post encrypt are the
        // GENERIC auth_chain_a ones (only the rand_len callback differs).
        let mut inner = AuthChainA::new(server_info.clone(), "auth_chain_b");
        inner.local.rand_len_fn = rand_len_b;
        inner.local.rand_len_ctx.b = Some(Self::init_data_size(&server_info.key));
        Self { inner }
    }

    /// C: auth_chain_b_init_data_size (auth_chain.c:1121-1155)
    fn init_data_size(key: &[u8]) -> AuthChainBContext {
        let mut random = Shift128plusCtx::from_bin(key);
        let list_len = (random.next() % 8 + 4) as usize;
        let mut data_size_list: Vec<i32> = (0..list_len)
            .map(|_| (random.next() % 2340 % 2040 % 1440) as i32)
            .collect();
        data_size_list.sort();

        let list2_len = (random.next() % 16 + 8) as usize;
        let mut data_size_list2: Vec<i32> = (0..list2_len)
            .map(|_| (random.next() % 2340 % 2040 % 1440) as i32)
            .collect();
        data_size_list2.sort();

        AuthChainBContext {
            data_size_list,
            data_size_list2,
        }
    }
}

impl Protocol for AuthChainB {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize { 4 }
    fn need_feedback(&self) -> bool { true }
    fn set_server_iv(&mut self, iv: Vec<u8>) { self.inner.set_server_iv(iv); }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        // Generic C path: auth_chain_a_client_pre_encrypt with the b variant's
        // get_tcp_rand_len callback installed in new().
        self.inner.client_pre_encrypt(plaindata)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }
}

// ==================== Auth Chain C ====================

struct AuthChainCContext {
    data_size_list0: Vec<i32>,
}

pub struct AuthChainC {
    inner: AuthChainA,
}

impl AuthChainC {
    pub fn new(server_info: ServerInfo) -> Self {
        // C: auth_chain_c_new_obfs = auth_chain_a_new_obfs() + swap
        // get_tcp_rand_len/salt + subclass_context; generic pre/post encrypt.
        let mut inner = AuthChainA::new(server_info.clone(), "auth_chain_c");
        inner.local.rand_len_fn = rand_len_c;
        inner.local.rand_len_ctx.c = Some(Self::init_data_size(&server_info.key));
        Self { inner }
    }

    /// C: auth_chain_c_init_data_size (auth_chain.c:1240-1263)
    fn init_data_size(key: &[u8]) -> AuthChainCContext {
        let mut random = Shift128plusCtx::from_bin(key);
        let list_len = (random.next() % (8 + 16) + (4 + 8)) as usize;
        let mut data_size_list0: Vec<i32> = (0..list_len)
            .map(|_| (random.next() % 2340 % 2040 % 1440) as i32)
            .collect();
        data_size_list0.sort();
        AuthChainCContext { data_size_list0 }
    }
}

impl Protocol for AuthChainC {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize { 4 }
    fn need_feedback(&self) -> bool { true }
    fn set_server_iv(&mut self, iv: Vec<u8>) { self.inner.set_server_iv(iv); }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        // Generic C path: auth_chain_a_client_pre_encrypt with the c variant's
        // get_tcp_rand_len callback installed in new().
        self.inner.client_pre_encrypt(plaindata)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }
}

// Auth Chain D, E, F are variations of C with different data_size_list initialization
// D: extends data_size_list0 until last element >= 1300
// E: uses find_pos to get minimum size
// F: uses time-based key for data_size_list initialization

pub struct AuthChainD {
    inner: AuthChainA,
}

impl AuthChainD {
    pub fn new(server_info: ServerInfo) -> Self {
        // C: auth_chain_d_new_obfs = auth_chain_c_new_obfs() + swap
        // get_tcp_rand_len/salt; generic pre/post encrypt.
        let mut inner = AuthChainA::new(server_info.clone(), "auth_chain_d");
        inner.local.rand_len_fn = rand_len_d;
        inner.local.rand_len_ctx.c = Some(Self::init_data_size(&server_info.key));
        Self { inner }
    }

    /// C: auth_chain_d_init_data_size + check_and_patch
    /// (auth_chain.c:1317-1361): fill, sort, then keep appending
    /// next()%2340%2040%1440 while the tail (unsorted append position) < 1300
    /// and len < 64, re-sorting once at the end.
    fn init_data_size(key: &[u8]) -> AuthChainCContext {
        let mut random = Shift128plusCtx::from_bin(key);
        let list_len = (random.next() % (8 + 16) + (4 + 8)) as usize;
        let mut data_size_list0: Vec<i32> = (0..64) // max size
            .map(|i| if i < list_len { (random.next() % 2340 % 2040 % 1440) as i32 } else { 0 })
            .collect();
        data_size_list0[..list_len].sort();

        // Check and patch: ensure last item >= 1300
        let mut current_len = list_len;
        while *data_size_list0[..current_len].last().unwrap_or(&0) < 1300 && current_len < 64 {
            data_size_list0[current_len] = (random.next() % 2340 % 2040 % 1440) as i32;
            current_len += 1;
        }
        data_size_list0[..current_len].sort();

        AuthChainCContext {
            data_size_list0: data_size_list0[..current_len].to_vec(),
        }
    }
}

impl Protocol for AuthChainD {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize { 4 }
    fn need_feedback(&self) -> bool { true }
    fn set_server_iv(&mut self, iv: Vec<u8>) { self.inner.set_server_iv(iv); }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        // Generic C path with the d variant's get_tcp_rand_len callback
        // installed in new().
        self.inner.client_pre_encrypt(plaindata)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }
}

pub struct AuthChainE {
    inner: AuthChainA,
    c_ctx: AuthChainCContext,
}

impl AuthChainE {
    pub fn new(server_info: ServerInfo) -> Self {
        let mut inner = AuthChainA::new(server_info.clone(), "auth_chain_e");
        let c_ctx = AuthChainD::init_data_size(&server_info.key);
        Self { inner, c_ctx }
    }

    fn get_rand_len(local: &mut AuthChainAContext, c_ctx: &AuthChainCContext, datalength: usize) -> usize {
        let overhead = local.client_over_head as usize;
        let other_data_size = datalength + overhead;

        let mut rng = Shift128plusCtx::from_bin_datalen(&local.last_client_hash, datalength);

        if other_data_size >= *c_ctx.data_size_list0.last().unwrap_or(&0) as usize {
            return 0;
        }
        let pos = find_pos(&c_ctx.data_size_list0, other_data_size as i32);
        // E uses minimum size (pos) instead of random selection
        (c_ctx.data_size_list0[pos] as usize).saturating_sub(other_data_size)
    }
}

impl Protocol for AuthChainE {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize { 4 }
    fn need_feedback(&self) -> bool { true }
    fn set_server_iv(&mut self, iv: Vec<u8>) { self.inner.set_server_iv(iv); }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.init_user_key();
        let mut result = Vec::new();
        let mut data = plaindata;
        let mut len = plaindata.len();
        if len > 0 && !self.inner.local.has_sent_header {
            let head_size = 1200.min(len);
            let packed = self.inner.pack_auth_data(&data[..head_size]);
            result.extend_from_slice(&packed);
            data = &data[head_size..];
            len -= head_size;
            self.inner.local.has_sent_header = true;
        }
        while len > 2000 {
            let packed = self.inner.pack_client_data(&data[..2000]);
            result.extend_from_slice(&packed);
            data = &data[2000..];
            len -= 2000;
        }
        if len > 0 {
            let packed = self.inner.pack_client_data(data);
            result.extend_from_slice(&packed);
        }
        self.inner.local.last_data_len = plaindata.len();
        Ok(result)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }
}

pub struct AuthChainF {
    inner: AuthChainA,
    c_ctx: AuthChainCContext,
}

impl AuthChainF {
    pub fn new(server_info: ServerInfo, extra_param: &str) -> Self {
        let mut inner = AuthChainA::new(server_info.clone(), "auth_chain_f");
        let key_change_interval = Self::parse_key_change_interval(extra_param);
        let c_ctx = Self::init_data_size(&server_info.key, key_change_interval);
        Self { inner, c_ctx }
    }

    fn parse_key_change_interval(extra_param: &str) -> u64 {
        if let Some(hash_pos) = extra_param.find('#') {
            let rest = &extra_param[hash_pos + 1..];
            if let Some(end) = rest.find('#') {
                let num_str = &rest[..end];
                if let Ok(n) = num_str.parse::<u64>() {
                    if n > 0 { return n; }
                }
            } else if !rest.is_empty() {
                if let Ok(n) = rest.parse::<u64>() {
                    if n > 0 { return n; }
                }
            }
        }
        86400 // default: 1 day
    }

    fn init_data_size(key: &[u8], key_change_interval: u64) -> AuthChainCContext {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let key_change_datetime_key = now / key_change_interval;

        let mut key_change_bytes = [0u8; 8];
        for i in (0..8).rev() {
            key_change_bytes[7 - i] = ((key_change_datetime_key >> (8 * i)) & 0xFF) as u8;
        }

        let mut new_key = key.to_vec();
        for i in 0..8.min(new_key.len()) {
            new_key[i] ^= key_change_bytes[i];
        }

        let mut random = Shift128plusCtx::from_bin(&new_key);
        let list_len = (random.next() % (8 + 16) + (4 + 8)) as usize;
        let mut data_size_list0: Vec<i32> = (0..64)
            .map(|i| if i < list_len { (random.next() % 2340 % 2040 % 1440) as i32 } else { 0 })
            .collect();
        data_size_list0[..list_len].sort();

        let mut current_len = list_len;
        while *data_size_list0[..current_len].last().unwrap_or(&0) < 1300 && current_len < 64 {
            data_size_list0[current_len] = (random.next() % 2340 % 2040 % 1440) as i32;
            current_len += 1;
        }
        data_size_list0[..current_len].sort();

        AuthChainCContext {
            data_size_list0: data_size_list0[..current_len].to_vec(),
        }
    }
}

impl Protocol for AuthChainF {
    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize { 4 }
    fn need_feedback(&self) -> bool { true }
    fn set_server_iv(&mut self, iv: Vec<u8>) { self.inner.set_server_iv(iv); }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.init_user_key();
        let mut result = Vec::new();
        let mut data = plaindata;
        let mut len = plaindata.len();
        if len > 0 && !self.inner.local.has_sent_header {
            let head_size = 1200.min(len);
            let packed = self.inner.pack_auth_data(&data[..head_size]);
            result.extend_from_slice(&packed);
            data = &data[head_size..];
            len -= head_size;
            self.inner.local.has_sent_header = true;
        }
        while len > 2000 {
            let packed = self.inner.pack_client_data(&data[..2000]);
            result.extend_from_slice(&packed);
            data = &data[2000..];
            len -= 2000;
        }
        if len > 0 {
            let packed = self.inner.pack_client_data(data);
            result.extend_from_slice(&packed);
        }
        self.inner.local.last_data_len = plaindata.len();
        Ok(result)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_info() -> ServerInfo {
        ServerInfo {
            key: vec![0x42u8; 16],
            iv: vec![0x24u8; 16],
            ..Default::default()
        }
    }

    #[test]
    fn test_auth_chain_a_basic() {
        let mut proto = AuthChainA::new(server_info(), "auth_chain_a");
        let data = b"hello auth_chain_a";
        let framed = proto.client_pre_encrypt(data).unwrap();
        assert!(framed.len() > data.len());
    }

    #[test]
    fn test_auth_chain_b_basic() {
        let mut proto = AuthChainB::new(server_info());
        let data = b"hello auth_chain_b";
        let framed = proto.client_pre_encrypt(data).unwrap();
        assert!(framed.len() > data.len());
    }

    #[test]
    fn test_shift128plus() {
        let mut ctx = Shift128plusCtx::from_bin(&[1u8; 16]);
        let val = ctx.next();
        assert!(val != 0);
    }
}

// SAFETY: These types contain raw pointers (for C FFI compatibility), but
// they are never used in async contexts that require Send. Adding Send here
// allows them to exist as trait objects without blocking the Protocol trait.
unsafe impl Send for AuthChainA {}
unsafe impl Send for AuthChainB {}
unsafe impl Send for AuthChainC {}
unsafe impl Send for AuthChainD {}
unsafe impl Send for AuthChainE {}
