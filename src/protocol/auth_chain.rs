use super::{memintcopy_lt, GlobalData, Protocol, ServerInfo};
use crate::crypto::bytes_to_key::bytes_to_key;
use crate::error::{SsrError, SsrResult};
use crate::utils::base64::b64encode;
use crate::utils::hash::hmac_md5;
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
        let [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] = fill;
        ctx.v[0] = u64::from_le_bytes([w0, w1, w2, w3, w4, w5, w6, w7]);
        ctx.v[1] = u64::from_le_bytes([w8, w9, w10, w11, w12, w13, w14, w15]);
        ctx
    }

    fn from_bin_datalen(data: &[u8], datalen: usize) -> Self {
        let mut fill = [0u8; 16];
        let copy_len = data.len().min(16);
        fill[..copy_len].copy_from_slice(&data[..copy_len]);
        fill[0] = datalen as u8;
        fill[1] = (datalen >> 8) as u8;
        let mut ctx = Self::new();
        let [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] = fill;
        ctx.v[0] = u64::from_le_bytes([w0, w1, w2, w3, w4, w5, w6, w7]);
        ctx.v[1] = u64::from_le_bytes([w8, w9, w10, w11, w12, w13, w14, w15]);
        for _ in 0..4 {
            ctx.next_u64();
        }
        ctx
    }

    pub fn next_u64(&mut self) -> u64 {
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

/// One-shot RC4 (C: `cipher_simple_update_data(password, "rc4", …)` — fresh
/// context per call, `bytes_to_key(password, 16)`, IV length 0 so no IV).
/// RC4 is symmetric, so the same fn encrypts and decrypts.
fn rc4_once(password: &str, data: &[u8]) -> SsrResult<Vec<u8>> {
    let key = bytes_to_key(password.as_bytes(), 16);
    let mut ctx = <rc4::Rc4 as KeyInit>::new_from_slice(&key)
        .map_err(|_| SsrError::Crypto(format!("rc4: invalid key length {}", key.len())))?;
    let mut out = data.to_vec();
    ctx.apply_keystream(&mut out);
    Ok(out)
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
        return (random.next_u64() % 31) as usize;
    }
    if datalength > 900 {
        return (random.next_u64() % 127) as usize;
    }
    if datalength > 400 {
        return (random.next_u64() % 521) as usize;
    }
    (random.next_u64() % 1021) as usize
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
    let Some(b) = ctx.b.as_ref() else {
        // Wired by the variant's new() — unreachable; 0 = no padding if missing.
        debug_assert!(false, "auth_chain_b: missing data_size_list context");
        return 0;
    };
    let overhead = ctx.overhead as usize;

    let pos = find_pos(&b.data_size_list, (datalength + overhead) as i32);
    let final_pos = pos + (random.next_u64() as usize) % b.data_size_list.len();
    if final_pos < b.data_size_list.len() {
        return (b.data_size_list[final_pos] as usize).saturating_sub(datalength + overhead);
    }

    let pos2 = find_pos(&b.data_size_list2, (datalength + overhead) as i32);
    let final_pos2 = pos2 + (random.next_u64() as usize) % b.data_size_list2.len();
    if final_pos2 < b.data_size_list2.len() {
        return (b.data_size_list2[final_pos2] as usize).saturating_sub(datalength + overhead);
    }
    if final_pos2 < pos2 + b.data_size_list2.len() - 1 {
        return 0;
    }

    if datalength > 1300 {
        return (random.next_u64() % 31) as usize;
    }
    if datalength > 900 {
        return (random.next_u64() % 127) as usize;
    }
    if datalength > 400 {
        return (random.next_u64() % 521) as usize;
    }
    (random.next_u64() % 1021) as usize
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
    let Some(c) = ctx.c.as_ref() else {
        // Wired by the variant's new() — unreachable; 0 = no padding if missing.
        debug_assert!(false, "auth_chain_c: missing data_size_list0 context");
        return 0;
    };
    let other_data_size = datalength + overhead;

    *random = Shift128plusCtx::from_bin_datalen(last_hash, datalength);

    if other_data_size >= c.data_size_list0[c.data_size_list0.len() - 1] as usize {
        if datalength > 1440 {
            return 0;
        }
        if datalength > 1300 {
            return (random.next_u64() % 31) as usize;
        }
        if datalength > 900 {
            return (random.next_u64() % 127) as usize;
        }
        if datalength > 400 {
            return (random.next_u64() % 521) as usize;
        }
        return (random.next_u64() % 1021) as usize;
    }

    // other_data_size < list0.last() guarantees find_pos < len (no %0 here)
    let pos = find_pos(&c.data_size_list0, other_data_size as i32);
    let final_pos = pos + (random.next_u64() as usize) % (c.data_size_list0.len() - pos);
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
    let Some(c) = ctx.c.as_ref() else {
        // Wired by the variant's new() — unreachable; 0 = no padding if missing.
        debug_assert!(false, "auth_chain_d: missing data_size_list0 context");
        return 0;
    };
    let other_data_size = datalength + overhead;

    // if other_data_size > the biggest item in data_size_list0, no padding
    if other_data_size >= c.data_size_list0[c.data_size_list0.len() - 1] as usize {
        return 0;
    }

    *random = Shift128plusCtx::from_bin_datalen(last_hash, datalength);
    let pos = find_pos(&c.data_size_list0, other_data_size as i32);
    let final_pos = pos + (random.next_u64() as usize) % (c.data_size_list0.len() - pos);
    (c.data_size_list0[final_pos] as usize).saturating_sub(other_data_size)
}

/// C: auth_chain_e_get_rand_len (auth_chain.c:1405-1429). PRNG reinitialised
/// unconditionally BEFORE the guard (like variant C, unlike D), then the guard
/// returns 0; the tail pick uses the minimum list item at pos — NO random
/// selection. auth_chain_f shares this callback (f_new_obfs only swaps salt).
fn rand_len_e(
    random: &mut Shift128plusCtx,
    last_hash: &[u8; 16],
    ctx: &RandLenCtx,
    datalength: usize,
) -> usize {
    *random = Shift128plusCtx::from_bin_datalen(last_hash, datalength);

    let overhead = ctx.overhead as usize;
    let Some(c) = ctx.c.as_ref() else {
        // Wired by the variant's new() — unreachable; 0 = no padding if missing.
        debug_assert!(false, "auth_chain_e: missing data_size_list0 context");
        return 0;
    };
    let other_data_size = datalength + overhead;

    if other_data_size >= c.data_size_list0[c.data_size_list0.len() - 1] as usize {
        return 0;
    }
    // use the mini size in the data_size_list0
    let pos = find_pos(&c.data_size_list0, other_data_size as i32);
    (c.data_size_list0[pos] as usize).saturating_sub(other_data_size)
}

struct AuthChainAContext {
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
    encrypt_ctx: Option<rc4::Rc4>, // RC4 stateful cipher (encrypt direction)
    decrypt_ctx: Option<rc4::Rc4>, // RC4 stateful cipher (decrypt direction)
    tcp_mss: u16,
    salt: &'static str,
    /// C: local->get_tcp_rand_len — variant dispatch (A by default)
    rand_len_fn: RandLenFn,
    /// C: local->subclass_context + overhead for the callback
    rand_len_ctx: RandLenCtx,
}

/// `auth_chain_a` — HMAC-SHA1 chained protocol: the first packet carries
/// an auth header, later packets chain the previous 16-byte hash, and the
/// UDP hooks are registered here only. C: auth_chain_a_new_obfs
/// (ssr-n/src/obfs/auth_chain.c:241).
pub struct AuthChainA {
    global: GlobalData,
    server_info: ServerInfo,
    local: AuthChainAContext,
}

impl AuthChainA {
    /// Fresh instance whose 32-byte random seed is split between the
    /// client and server XORShift128+ streams. C: auth_chain_a_new_obfs
    /// (ssr-n/src/obfs/auth_chain.c:241).
    pub fn new(server_info: ServerInfo, salt: &'static str) -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let mut local = AuthChainAContext {
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
            encrypt_ctx: None,
            decrypt_ctx: None,
            tcp_mss: 1460,
            salt,
            rand_len_fn: rand_len_a,
            rand_len_ctx: RandLenCtx {
                overhead: server_info.overhead,
                b: None,
                c: None,
            },
        };
        local.random_client.next_u64();
        local.random_server.next_u64();

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
            return (random.next_u64() % 8589934609) as usize % rand_len;
        }
        0
    }

    fn init_user_key(&mut self) {
        if !self.local.user_key.is_empty() {
            return;
        }
        if !self.server_info.extra_param.is_empty() {
            if let Some(delim_pos) = self.server_info.extra_param.find(':') {
                // C (auth_chain.c:545-558): delimiter present always wins —
                // strtol() yields 0 for garbage uid, then raw key_str is stored.
                let uid_str = &self.server_info.extra_param[..delim_pos];
                let key_str = &self.server_info.extra_param[delim_pos + 1..];
                let uid_long = uid_str.trim().parse::<u32>().unwrap_or(0);
                memintcopy_lt(&mut self.local.uid, uid_long);
                // C: buffer_store(local->user_key, key_str, strlen(key_str))
                // — stores the RAW key string, no hashing (auth_chain.c:557).
                self.local.user_key = key_str.as_bytes().to_vec();
                return;
            }
        }
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut self.local.uid);
        self.local.user_key = self.server_info.key.clone();
    }

    /// C: udp_get_rand_len (auth_chain.c:370-374) — reinit the PRNG from the
    /// 16-byte hash (no warmup), then `next() % 127`.
    fn udp_rand_len(ctx: &mut Shift128plusCtx, hash: &[u8; 16]) -> usize {
        *ctx = Shift128plusCtx::from_bin(hash);
        (ctx.next_u64() % 127) as usize
    }

    /// C: auth_chain_a_client_udp_pre_encrypt (auth_chain.c:1533-1606).
    ///
    /// ```text
    /// rc4(b64(user_key)+b64(md5(hmac(server_key, auth3))), plain)
    ///   || rand(rand_len) || auth(3) || uid^md5(4) || hmac(user_key, ·)[0]
    /// ```
    fn udp_pre_inner(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        use rand::RngCore;
        self.init_user_key();
        let mut auth_data = [0u8; 3];
        rand::thread_rng().fill_bytes(&mut auth_data);
        let md5data = hmac_md5(&self.server_info.key, &auth_data);
        let mut uid_obf = [0u8; 4];
        for i in 0..4 {
            uid_obf[i] = self.local.uid[i] ^ md5data[i];
        }
        let rand_len = Self::udp_rand_len(&mut self.local.random_client, &md5data);
        // auth_chain_a_encryptor(true, "rc4", user_key, md5data, plain)
        let mixed_key = format!("{}{}", b64encode(&self.local.user_key), b64encode(&md5data));
        let mut out = rc4_once(&mixed_key, plaindata)?;
        let mut rnd = vec![0u8; rand_len];
        rand::thread_rng().fill_bytes(&mut rnd);
        out.extend_from_slice(&rnd);
        out.extend_from_slice(&auth_data);
        out.extend_from_slice(&uid_obf);
        let mac = hmac_md5(&self.local.user_key, &out);
        out.push(mac[0]);
        Ok(out)
    }

    /// C: auth_chain_a_client_udp_post_decrypt (auth_chain.c:1608-1661).
    /// Returns the decrypted datagram; `Err` means drop (C returns 0).
    fn udp_post_inner(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        if data.len() <= 8 {
            return Err(SsrError::Protocol(
                "auth_chain: udp datagram too short".into(),
            ));
        }
        let verify = hmac_md5(&self.local.user_key, &data[..data.len() - 1]);
        if verify[0] != data[data.len() - 1] {
            return Err(SsrError::Protocol("auth_chain: udp mac mismatch".into()));
        }
        // C: buffer_create_from(plaindata + datalength - 8, 7)
        let hash = hmac_md5(&self.server_info.key, &data[data.len() - 8..data.len() - 1]);
        let rand_len = Self::udp_rand_len(&mut self.local.random_server, &hash);
        if data.len() < rand_len + 8 {
            return Err(SsrError::Protocol(
                "auth_chain: udp datagram truncated".into(),
            ));
        }
        let outlength = data.len() - rand_len - 8;
        let password = format!("{}{}", b64encode(&self.local.user_key), b64encode(&hash));
        rc4_once(&password, &data[..outlength])
    }

    fn init_rc4(&mut self, password: &str) -> SsrResult<()> {
        // Derive RC4 key using EVP_BytesToKey (same as cipher_env_new_instance)
        let key = bytes_to_key(password.as_bytes(), 16); // RC4 key size is 16
        let enc = <rc4::Rc4 as KeyInit>::new_from_slice(&key)
            .map_err(|_| SsrError::Crypto(format!("rc4: invalid key length {}", key.len())))?;
        let dec = <rc4::Rc4 as KeyInit>::new_from_slice(&key)
            .map_err(|_| SsrError::Crypto(format!("rc4: invalid key length {}", key.len())))?;
        self.local.encrypt_ctx = Some(enc);
        self.local.decrypt_ctx = Some(dec);
        Ok(())
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
        let rnd_data: Vec<u8> = (0..rand_len).map(|_| rand::random::<u8>()).collect();

        if !data.is_empty() {
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

    fn pack_auth_data(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
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
        let cipher = Aes128Enc::new_from_slice(&enc_key)
            .map_err(|_| SsrError::Crypto(format!("aes-128: bad key length {}", enc_key.len())))?;
        let iv = [0u8; 16];
        // XOR plaintext with zero IV (first block only, CBC mode)
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = plain_block[i] ^ iv[i];
        }
        let mut block_arr = aes::Block::from(block);
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
        self.init_rc4(&password)?;

        // Pack data as a data packet (matching C auth_chain_a_pack_client_data)
        // The C code appends auth_chain_a_pack_client_data after the auth header
        let client_data_packet = self.pack_client_data(data);
        out.extend_from_slice(&client_data_packet);

        Ok(out)
    }

    fn client_pre_encrypt_inner(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        let mut result = Vec::new();
        let mut data = plaindata;
        let mut len = plaindata.len();

        if len > 0 && !self.local.has_sent_header {
            let head_size = 1200.min(len);
            let packed = self.pack_auth_data(&data[..head_size])?;
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
            return Err(crate::error::SsrError::Protocol(
                "auth_chain: recv buffer overflow".into(),
            ));
        }
        self.local.recv_buffer.extend_from_slice(data);

        let mut output = Vec::new();
        ssr_debug!(
            "[acapostd] feed {} bytes, buf={} first16={}",
            data.len(),
            self.local.recv_buffer.len(),
            self.local
                .recv_buffer
                .iter()
                .take(16)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("")
        );

        while self.local.recv_buffer.len() > 4 {
            // data_len is XORed with last_server_hash[14..16] (server direction)
            let data_len =
                (((self.local.recv_buffer[1] ^ self.local.last_server_hash[15]) as usize) << 8)
                    + (self.local.recv_buffer[0] ^ self.local.last_server_hash[14]) as usize;

            // Reinit random_server from last_server_hash + data_len, so that the
            // rand_len draw and the start_pos draw share one PRNG stream — same
            // as C get_server_rand_len followed by get_rand_start_pos.
            let rand_len = Self::get_server_rand_len(&mut self.local, data_len);
            let mut len = data_len + rand_len;
            if len >= SSR_BUFF_SIZE * 2 {
                self.local.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_chain: over size".into(),
                ));
            }
            len += 4; // +2 length field +2 HMAC
            if len > self.local.recv_buffer.len() {
                ssr_debug!(
                    "[acapostd] incomplete: data_len={} rand_len={} need={} have={}",
                    data_len,
                    rand_len,
                    len,
                    self.local.recv_buffer.len()
                );
                break;
            }

            // HMAC key = user_key + recv_id (LE u32), recv_id updated per packet
            let mut key = self.local.user_key.clone();
            key.extend_from_slice(&self.local.recv_id.to_le_bytes());
            let hash = hmac_md5(&key, &self.local.recv_buffer[..len - 2]);
            if hash[..2] != self.local.recv_buffer[len - 2..len] {
                ssr_debug!(
                    "[acapostd] HMAC mismatch: data_len={} rand_len={} recv_id={} need={} have={}",
                    data_len,
                    rand_len,
                    self.local.recv_id,
                    hash[..2]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(""),
                    self.local.recv_buffer[len - 2..len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join("")
                );
                self.local.recv_buffer.clear();
                return Err(crate::error::SsrError::Protocol(
                    "auth_chain: HMAC mismatch".into(),
                ));
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
            ssr_debug!(
                "[acapostd] packet ok: data_len={} -> out_total={}",
                data_len,
                output.len()
            );
        }

        Ok(output)
    }
}

impl Protocol for AuthChainA {
    fn udp_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.udp_pre_inner(plaindata)
    }

    fn udp_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.udp_post_inner(data)
    }

    fn set_salt(&mut self, salt: &str) {
        // Salt is set via constructor
        let _ = salt;
    }

    fn get_overhead(&self) -> usize {
        4
    }

    fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.server_info.iv = iv;
    }

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

/// `auth_chain_b` — `auth_chain_a` with the b rand_len variant: two
/// sorted random data-size lists derived from the server key.
pub struct AuthChainB {
    inner: AuthChainA,
}

impl AuthChainB {
    /// `auth_chain_a` core with the b rand_len callback and its two
    /// data-size lists installed. C: auth_chain_b_new_obfs
    /// (ssr-n/src/obfs/auth_chain.c:1087).
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
        let list_len = (random.next_u64() % 8 + 4) as usize;
        let mut data_size_list: Vec<i32> = (0..list_len)
            .map(|_| (random.next_u64() % 2340 % 2040 % 1440) as i32)
            .collect();
        data_size_list.sort();

        let list2_len = (random.next_u64() % 16 + 8) as usize;
        let mut data_size_list2: Vec<i32> = (0..list2_len)
            .map(|_| (random.next_u64() % 2340 % 2040 % 1440) as i32)
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
    fn get_overhead(&self) -> usize {
        4
    }
    fn need_feedback(&self) -> bool {
        true
    }
    fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.inner.set_server_iv(iv);
    }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        // Generic C path: auth_chain_a_client_pre_encrypt with the b variant's
        // get_tcp_rand_len callback installed in new().
        self.inner.client_pre_encrypt(plaindata)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }

    // C: auth_chain_b_new_obfs derives from auth_chain_a_new_obfs
    // without overriding the UDP hooks — delegate to inner (auth_chain.c:261).
    fn udp_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_pre_encrypt(plaindata)
    }

    fn udp_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_post_decrypt(data)
    }
}

// ==================== Auth Chain C ====================

struct AuthChainCContext {
    data_size_list0: Vec<i32>,
}

/// `auth_chain_c` — `auth_chain_a` with the c rand_len variant built on
/// one sorted `data_size_list0` derived from the server key.
pub struct AuthChainC {
    inner: AuthChainA,
}

impl AuthChainC {
    /// `auth_chain_a` core with the c rand_len callback installed.
    /// C: auth_chain_c_new_obfs (ssr-n/src/obfs/auth_chain.c:1211).
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
        let list_len = (random.next_u64() % (8 + 16) + (4 + 8)) as usize;
        let mut data_size_list0: Vec<i32> = (0..list_len)
            .map(|_| (random.next_u64() % 2340 % 2040 % 1440) as i32)
            .collect();
        data_size_list0.sort();
        AuthChainCContext { data_size_list0 }
    }
}

impl Protocol for AuthChainC {
    // C: derives from auth_chain_a_new_obfs — UDP hooks inherited unchanged
    // (auth_chain.c:261 registers them only in auth_chain_a_new_obfs).
    fn udp_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_pre_encrypt(plaindata)
    }

    fn udp_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_post_decrypt(data)
    }

    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize {
        4
    }
    fn need_feedback(&self) -> bool {
        true
    }
    fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.inner.set_server_iv(iv);
    }

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

/// `auth_chain_d` — like C, but the data-size list keeps growing until
/// its last element is >= 1300 (at most 64 entries).
pub struct AuthChainD {
    inner: AuthChainA,
}

impl AuthChainD {
    /// `auth_chain_a` core with the d rand_len callback installed.
    /// C: auth_chain_d_new_obfs (ssr-n/src/obfs/auth_chain.c:1304).
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
        let list_len = (random.next_u64() % (8 + 16) + (4 + 8)) as usize;
        let mut data_size_list0: Vec<i32> = (0..64) // max size
            .map(|i| {
                if i < list_len {
                    (random.next_u64() % 2340 % 2040 % 1440) as i32
                } else {
                    0
                }
            })
            .collect();
        data_size_list0[..list_len].sort();

        // Check and patch: ensure last item >= 1300
        let mut current_len = list_len;
        while *data_size_list0[..current_len].last().unwrap_or(&0) < 1300 && current_len < 64 {
            data_size_list0[current_len] = (random.next_u64() % 2340 % 2040 % 1440) as i32;
            current_len += 1;
        }
        data_size_list0[..current_len].sort();

        AuthChainCContext {
            data_size_list0: data_size_list0[..current_len].to_vec(),
        }
    }
}

impl Protocol for AuthChainD {
    // C: derives from auth_chain_a_new_obfs — UDP hooks inherited unchanged
    // (auth_chain.c:261 registers them only in auth_chain_a_new_obfs).
    fn udp_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_pre_encrypt(plaindata)
    }

    fn udp_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_post_decrypt(data)
    }

    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize {
        4
    }
    fn need_feedback(&self) -> bool {
        true
    }
    fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.inner.set_server_iv(iv);
    }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        // Generic C path with the d variant's get_tcp_rand_len callback
        // installed in new().
        self.inner.client_pre_encrypt(plaindata)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }
}

/// `auth_chain_e` — like D: reuses D's data-size list initialization
/// with the e rand_len callback.
pub struct AuthChainE {
    inner: AuthChainA,
}

impl AuthChainE {
    /// `auth_chain_a` core reusing `AuthChainD::init_data_size` for the
    /// e rand_len callback. C: auth_chain_e_new_obfs
    /// (ssr-n/src/obfs/auth_chain.c:1395).
    pub fn new(server_info: ServerInfo) -> Self {
        // C: auth_chain_e_new_obfs = auth_chain_d_new_obfs() + swap
        // get_tcp_rand_len/salt (E reuses D's init_data_size); generic
        // pre/post encrypt.
        let mut inner = AuthChainA::new(server_info.clone(), "auth_chain_e");
        inner.local.rand_len_fn = rand_len_e;
        inner.local.rand_len_ctx.c = Some(AuthChainD::init_data_size(&server_info.key));
        Self { inner }
    }
}

impl Protocol for AuthChainE {
    // C: derives from auth_chain_a_new_obfs — UDP hooks inherited unchanged
    // (auth_chain.c:261 registers them only in auth_chain_a_new_obfs).
    fn udp_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_pre_encrypt(plaindata)
    }

    fn udp_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_post_decrypt(data)
    }

    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize {
        4
    }
    fn need_feedback(&self) -> bool {
        true
    }
    fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.inner.set_server_iv(iv);
    }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        // Generic C path with the e variant's get_tcp_rand_len callback
        // installed in new().
        self.inner.client_pre_encrypt(plaindata)
    }

    fn client_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.client_post_decrypt_inner(data)
    }
}

/// `auth_chain_f` — like E, but the data-size list key rotates on a
/// time interval parsed from the extra parameter.
pub struct AuthChainF {
    inner: AuthChainA,
}

impl AuthChainF {
    /// `auth_chain_a` core whose data-size key rotates over time; the
    /// interval comes from `extra_param` (default 1 day). C:
    /// auth_chain_f_new_obfs (ssr-n/src/obfs/auth_chain.c:1436) with
    /// auth_chain_f_set_server_info (ssr-n/src/obfs/auth_chain.c:1500-1518).
    pub fn new(server_info: ServerInfo, extra_param: &str) -> Self {
        // C: auth_chain_f_new_obfs = auth_chain_e_new_obfs() + swap salt
        // (F inherits E's get_tcp_rand_len; only the data_size_list0 init key
        // is time-dependent via auth_chain_f_set_server_info).
        let mut inner = AuthChainA::new(server_info.clone(), "auth_chain_f");
        let key_change_interval = Self::parse_key_change_interval(extra_param);
        inner.local.rand_len_fn = rand_len_e;
        inner.local.rand_len_ctx.c =
            Some(Self::init_data_size(&server_info.key, key_change_interval));
        Self { inner }
    }

    /// C: auth_chain_f_set_server_info `#N#`/`#N` parsing
    /// (auth_chain.c:1500-1518): strtoll with base0, digit run must be
    /// longer than 2 chars (C: `if (l > 2)`), result must be >0 and not
    /// LLONG_MAX/LLONG_MIN; otherwise the default (1 day) applies.
    fn parse_key_change_interval(extra_param: &str) -> u64 {
        if let Some(hash_pos) = extra_param.find('#') {
            let rest = &extra_param[hash_pos + 1..];
            let num_str = match rest.find('#') {
                Some(end) => &rest[..end],
                None => rest,
            };
            if num_str.len() > 2 {
                if let Some(n) = Self::strtoll_base0(num_str) {
                    if n > 0 && n != i64::MAX {
                        return n as u64;
                    }
                }
            }
        }
        86400 // default: a day by second
    }

    /// strtoll(...,0)-lite: optional sign + base0 (0x/0 hex, leading-0 octal,
    /// decimal), overflow fails (strtoll saturates to LLONG_MAX/MIN, which the
    /// caller rejects).
    fn strtoll_base0(s: &str) -> Option<i64> {
        let (neg, digits) = if let Some(r) = s.strip_prefix('-') {
            (true, r)
        } else {
            (false, s.strip_prefix('+').unwrap_or(s))
        };
        if digits.is_empty() {
            return None;
        }
        let (radix, unsigned) = if let Some(h) = digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0X"))
        {
            (16, h)
        } else if digits.starts_with('0') && digits.len() > 1 {
            (8, &digits[1..])
        } else {
            (10, digits)
        };
        let mag = i64::from_str_radix(unsigned, radix).ok()?;
        Some(if neg { -mag } else { mag })
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
        let list_len = (random.next_u64() % (8 + 16) + (4 + 8)) as usize;
        let mut data_size_list0: Vec<i32> = (0..64)
            .map(|i| {
                if i < list_len {
                    (random.next_u64() % 2340 % 2040 % 1440) as i32
                } else {
                    0
                }
            })
            .collect();
        data_size_list0[..list_len].sort();

        let mut current_len = list_len;
        while *data_size_list0[..current_len].last().unwrap_or(&0) < 1300 && current_len < 64 {
            data_size_list0[current_len] = (random.next_u64() % 2340 % 2040 % 1440) as i32;
            current_len += 1;
        }
        data_size_list0[..current_len].sort();

        AuthChainCContext {
            data_size_list0: data_size_list0[..current_len].to_vec(),
        }
    }
}

impl Protocol for AuthChainF {
    // C: derives from auth_chain_a_new_obfs — UDP hooks inherited unchanged
    // (auth_chain.c:261 registers them only in auth_chain_a_new_obfs).
    fn udp_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_pre_encrypt(plaindata)
    }

    fn udp_post_decrypt(&mut self, data: &[u8]) -> SsrResult<Vec<u8>> {
        self.inner.udp_post_decrypt(data)
    }

    fn set_salt(&mut self, _salt: &str) {}
    fn get_overhead(&self) -> usize {
        4
    }
    fn need_feedback(&self) -> bool {
        true
    }
    fn set_server_iv(&mut self, iv: Vec<u8>) {
        self.inner.set_server_iv(iv);
    }

    fn client_pre_encrypt(&mut self, plaindata: &[u8]) -> SsrResult<Vec<u8>> {
        // Generic C path — F shares E's get_tcp_rand_len callback (f_new_obfs
        // only swaps the salt).
        self.inner.client_pre_encrypt(plaindata)
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
        let val = ctx.next_u64();
        assert!(val != 0);
    }

    #[test]
    fn test_key_change_interval_parse() {
        // C (auth_chain.c:1512): digit run must be longer than 2 chars
        assert_eq!(AuthChainF::parse_key_change_interval("#86400#"), 86400);
        assert_eq!(AuthChainF::parse_key_change_interval("#1800#"), 1800);
        assert_eq!(AuthChainF::parse_key_change_interval("x#72#"), 86400); // l == 2 rejected
                                                                           // C strtoll base0: 0x hex and leading-0 octal
        assert_eq!(AuthChainF::parse_key_change_interval("x#0x100#"), 256);
        assert_eq!(AuthChainF::parse_key_change_interval("x#010#"), 8);
        // no # / empty / zero / trailing form fall back to the default
        assert_eq!(AuthChainF::parse_key_change_interval(""), 86400);
        assert_eq!(AuthChainF::parse_key_change_interval("x#0#"), 86400);
        assert_eq!(AuthChainF::parse_key_change_interval("#3600"), 3600);
    }
}
