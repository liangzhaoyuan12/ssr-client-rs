use crate::error::SsrResult;
use crate::utils::hash::hmac_sha1;
use super::Obfs;
use rand::Rng;

/// TLS 1.2 ticket auth obfuscation overhead (5 bytes: \x17\x03\x03 + 2 byte length)
const TLS_RECORD_OVERHEAD: usize = 5;

/// HMAC-SHA1 truncation length (first 10 bytes)
const HMAC_SHA1_LEN: usize = 10;

/// Cipher suites for TLS ClientHello (from C source)
static TLS_CIPHER_SUITES: &[u8] = &[
    0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9,
    0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a,
    0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c,
    0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a, 0x01, 0x00,
];

/// Session ticket extension header
static TLS_SESSION_TICKET_EXT: &[u8] = &[
    0xff, 0x01, 0x00, 0x01, 0x00,
];

/// Extended master secret + other extensions header
static TLS_EXTENDED_MASTER_SECRET: &[u8] = &[
    0x00, 0x17, 0x00, 0x00, 0x00, 0x23,
];

/// Signature algorithms and other extensions
static TLS_SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01,
    0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01,
    0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01,
    0x02, 0x03, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x75,
    0x50, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01,
    0x00, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00,
    0x17, 0x00, 0x18,
];

/// Build TLS SNI extension for a given hostname
fn build_sni(hostname: &str) -> Vec<u8> {
    // Match C code exactly: \x00\x00 + len(2) + len0+2(2) + \x00(1) + url_len(2) + url
    let url_len = hostname.len();
    let len0 = 1 + 2 + url_len; // server name type(1) + server name len(2) + hostname
    let total_len = 2 + 2 + 2 + len0; // padding(2) + ext_len(2) + name_list_len(2) + len0

    let mut result = Vec::with_capacity(total_len);
    // Extra 2 bytes (matching C code's \x00\x00)
    result.extend_from_slice(&[0x00, 0x00]);
    // Extension data length
    result.extend_from_slice(&(len0 + 2).to_be_bytes());
    // Server name list length
    result.extend_from_slice(&(len0 as u16).to_be_bytes());
    // Server name type: host_name (0x00)
    result.push(0x00);
    // Server name length
    result.extend_from_slice(&(url_len as u16).to_be_bytes());
    // Server name
    result.extend_from_slice(hostname.as_bytes());

    result
}

/// Pack auth data: 4 bytes timestamp + 18 random bytes + HMAC-SHA1(10 bytes)
fn pack_auth_data(key: &[u8], client_id: &[u8]) -> [u8; 32] {
    let mut outdata = [0u8; 32];
    let mut rng = rand::thread_rng();

    // Timestamp (4 bytes, big-endian)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    outdata[0..4].copy_from_slice(&timestamp.to_be_bytes());

    // Random bytes (18 bytes)
    rng.fill(&mut outdata[4..22]);

    // HMAC-SHA1 over first 22 bytes, key = server_key + client_id
    let mut hmac_key = Vec::with_capacity(key.len() + client_id.len());
    hmac_key.extend_from_slice(key);
    hmac_key.extend_from_slice(client_id);
    let hash = hmac_sha1(&hmac_key, &outdata[..22]);
    outdata[22..32].copy_from_slice(&hash[..HMAC_SHA1_LEN]);

    outdata
}

/// Pack data into TLS record: \x17\x03\x03 + 2-byte length + data
fn pack_data(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(5 + data.len());
    result.extend_from_slice(&[0x17, 0x03, 0x03]);
    result.extend_from_slice(&(data.len() as u16).to_be_bytes());
    result.extend_from_slice(data);
    result
}

/// TLS 1.2 ticket auth obfuscation
pub struct Tls12TicketAuthObfs {
    server_host: String,
    server_port: u16,
    extra_param: String,
    fastauth: bool,
    /// Handshake status bitmask:
    /// bit 0: ClientHello sent
    /// bit 1: Finish sent
    /// bit 2: Handshake complete
    /// bit 3: Server response validated
    handshake_status: u8,
    client_id: [u8; 32],
    send_id: u32,
    key: Vec<u8>,
    send_buffer: Vec<Vec<u8>>,
    recv_buffer: Vec<u8>,
}

impl Tls12TicketAuthObfs {
    pub fn new(server_host: String, server_port: u16, extra_param: String, fastauth: bool) -> Self {
        let mut client_id = [0u8; 32];
        rand::thread_rng().fill(&mut client_id);
        Self {
            server_host,
            server_port,
            extra_param,
            fastauth,
            handshake_status: 0,
            client_id,
            send_id: 0,
            send_buffer: Vec::new(),
            recv_buffer: Vec::new(),
            key: Vec::new(),
        }
    }

    /// Set the encryption key (used for HMAC computation)
    pub fn get_client_id(&self) -> &[u8; 32] {
        &self.client_id
    }

    pub fn set_key(&mut self, key: Vec<u8>) {
        self.key = key;
    }

    /// Build the TLS ClientHello message for initial handshake
    fn build_client_hello(&mut self) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        // Pack auth data (32 bytes) - matches C tls12_ticket_pack_auth_data
        let auth_data = pack_auth_data(&self.key, &self.client_id);

        // Build extensions buffer
        let mut ext_buf = Vec::with_capacity(256);

        // Renegotiation info extension
        ext_buf.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

        // SNI extension
        let host = if self.extra_param.is_empty() {
            &self.server_host
        } else {
            self.extra_param.split(',').next().unwrap_or(&self.server_host)
        };
        ext_buf.extend_from_slice(&build_sni(host));

        // Session ticket extension (C tls_data2 = "\x00\x17\x00\x00\x00\x23")
        ext_buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x00, 0x00, 0x23]);
        // Session ticket data (random)
        let ticket_size: usize = (32 + rng.gen_range(0..164)) * 2;
        ext_buf.extend_from_slice(&(ticket_size as u16).to_be_bytes());
        let mut ticket = vec![0u8; ticket_size];
        rng.fill(&mut ticket[..]);
        ext_buf.extend_from_slice(&ticket);

        // Signature algorithms + supported groups + ec_point_formats + renegotiation_info
        ext_buf.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01,
            0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01,
            0x02, 0x03,
            0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x12, 0x00, 0x00,
            0x75, 0x50, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18,
        ]);

        // Extensions length (2 bytes, big-endian)
        let ext_len = ext_buf.len() as u16;
        ext_buf.insert(0, (ext_len >> 8) as u8);
        ext_buf.insert(1, ext_len as u8);

        // Cipher suites + compression methods (C code tls_data0, 32 bytes):
        //   cipher_suites_len(2) + 28 suite bytes + compression_len(1) + null(1)
        let cipher_suites: Vec<u8> = vec![
            0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8,
            0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09,
            0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a,
            0x01, 0x00,
        ];

        // Build ClientHello body (before prepend headers)
        // Matches C code: auth_data(32) + session_id_len(1) + session_id(32) + cipher_suites_len(2) + cipher_suites + compression(2) + extensions
        let mut msg = Vec::with_capacity(512);
        msg.extend_from_slice(&auth_data[..32]); // Random (auth data)
        msg.push(0x20); // Session ID length = 32
        msg.extend_from_slice(&self.client_id[..32]); // Session ID
        msg.extend_from_slice(&cipher_suites); // tls_data0: suites + compression
        msg.extend_from_slice(&ext_buf);

        // Build final result by prepending headers (matching C code order):
        // 1. TLS record header: 0x16 0x03 0x01
        // 2. Handshake length (4 + msg.len())
        // 3. ClientHello type: 0x01 0x00
        // 4. Body length (msg.len())
        // 5. Client version: 0x03 0x03
        // 6. Body
        let mut result = Vec::with_capacity(msg.len() + 12);

        // TLS record header
        result.extend_from_slice(&[0x16, 0x03, 0x01]);
        // TLS record length = payload length = type(2) + body_len(2) + version(2) + body
        // C code: htons(buffer_get_length(result)) after inserting "\x01\x00", body_len, version
        result.extend_from_slice(&((6 + msg.len()) as u16).to_be_bytes());
        // ClientHello type + high byte of the 3-byte handshake length
        result.extend_from_slice(&[0x01, 0x00]);
        // Handshake length = version(2) + body
        result.extend_from_slice(&((2 + msg.len()) as u16).to_be_bytes());
        // Client version
        result.extend_from_slice(&[0x03, 0x03]);
        // Body
        result.extend_from_slice(&msg);

        self.handshake_status |= 0x01;
        result
    }


    fn build_handshake_finish(&mut self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let finish_len: usize = 32; // Must match C code's finish_len_set

        // Handshake finish prefix — CCS record + start of Finished record
        let handshake_finish: &[u8] = &[
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03,
        ];

        let mut hmac_data = Vec::with_capacity(handshake_finish.len() + 2 + finish_len - 10 + 10);
        hmac_data.extend_from_slice(handshake_finish);

        // Length of finish data
        let len = finish_len as u16;
        hmac_data.extend_from_slice(&len.to_be_bytes());

        // Random data
        let mut rnd = vec![0u8; finish_len - 10];
        rng.fill(&mut rnd[..]);
        hmac_data.extend_from_slice(&rnd);

        // HMAC-SHA1 — key = obfs_key + client_id (matches C tls12_sha1_hmac)
        let mut hmac_key = Vec::with_capacity(self.key.len() + self.client_id.len());
        hmac_key.extend_from_slice(&self.key);
        hmac_key.extend_from_slice(&self.client_id);
        let hash = hmac_sha1(&hmac_key, &hmac_data);
        hmac_data.extend_from_slice(&hash[..10]); // OBFS_HMAC_SHA1_LEN = 10

        hmac_data
    }
}

impl Obfs for Tls12TicketAuthObfs {
    fn set_key(&mut self, key: Vec<u8>) {
        self.key = key;
    }
    fn client_encode(&mut self, buf: &[u8]) -> SsrResult<Vec<u8>> {
        // Matches C code: tls12_ticket_auth_client_encode
        if self.handshake_status == 0xFF {
            return Ok(buf.to_vec());
        }

        let mut result = Vec::new();

        // After Finish sent (bit 2 set): wrap data in TLS Application Data records
        if (self.handshake_status & 0x04) != 0 {
            let mut start = 0;
            while self.send_id <= 4 && buf.len() - start > 256 {
                let len = ((rand::random::<usize>() % 512 + 64)).min(buf.len() - start);
                result.extend_from_slice(&pack_data(&buf[start..start + len]));
                start += len;
                self.send_id += 1;
            }
            while buf.len() - start > 2048 {
                let len = ((rand::random::<usize>() % 4096 + 100)).min(buf.len() - start);
                result.extend_from_slice(&pack_data(&buf[start..start + len]));
                start += len;
            }
            if start < buf.len() {
                result.extend_from_slice(&pack_data(&buf[start..]));
            }
            return Ok(result);
        }

        // During handshake: buffer data and generate ClientHello if needed
        if !buf.is_empty() {
            self.send_buffer.push(buf.to_vec());
        }

        // Build ClientHello if not yet sent (regardless of buf emptiness)
        if (self.handshake_status & 0x01) == 0 {
            let client_hello = self.build_client_hello();
            self.handshake_status |= 0x01;

            if self.fastauth {
                // Fastauth: send ClientHello + Finished immediately
                let finish = self.build_handshake_finish();
                self.handshake_status |= 0x02;
                result.extend_from_slice(&client_hello);
                result.extend_from_slice(&finish);
                for data in self.send_buffer.drain(..) {
                    result.extend_from_slice(&pack_data(&data));
                }
                self.handshake_status |= 0x04;
                return Ok(result);
            }

            // Normal: return ClientHello only, data will be sent after server response
            return Ok(client_hello);
        }

        // Build Finish if ClientHello already sent (bit 0) but Finish not yet sent (bit 2)
        if (self.handshake_status & 0x01) != 0 && (self.handshake_status & 0x02) == 0 {
            let finish = self.build_handshake_finish();
            self.handshake_status |= 0x02;
            result.extend_from_slice(&finish);
            for data in self.send_buffer.drain(..) {
                result.extend_from_slice(&pack_data(&data));
            }
            self.handshake_status |= 0x04;
            return Ok(result);
        }

        Ok(result)
    }

    fn client_decode(&mut self, buf: &[u8]) -> SsrResult<(Vec<u8>, bool)> {
        // Matches C code: tls12_ticket_auth_client_decode
        self.recv_buffer.extend_from_slice(buf);

        // After handshake complete (bit 3): strip TLS Application Data (0x17) records
        if (self.handshake_status & 0x08) != 0 {
            let mut result = Vec::new();
            while self.recv_buffer.len() > 5 {
                if self.recv_buffer[0] != 0x17 {
                    return Err(crate::error::SsrError::Protocol(
                        "Expected TLS application data record".to_string(),
                    ));
                }
                let size = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;
                if size + 5 > self.recv_buffer.len() {
                    break;
                }
                result.extend_from_slice(&self.recv_buffer[5..5 + size]);
                self.recv_buffer.drain(..5 + size);
            }
            return Ok((result, false));
        }

        // During handshake: validate server response
        if self.recv_buffer.len() < 11 + 32 + 1 + 32 {
            return Ok((Vec::new(), false));
        }

        // Validate auth_data HMAC
        // auth_data is at offset 11 in the Finished message body
        // But we need to find it by iterating through TLS records
        let mut header_length: usize = 0;
        let iter = self.recv_buffer.clone();

        // First try direct offset (raw bytes without TLS record headers)
        let encryptdata = &iter;
        let mut hmac_key = Vec::with_capacity(self.key.len() + self.client_id.len());
        hmac_key.extend_from_slice(&self.key);
        hmac_key.extend_from_slice(&self.client_id);

        // HMAC over encryptdata[11..33] (22 bytes)
        let mut hash = hmac_sha1(&hmac_key, &encryptdata[11..33]);
        if hash[..10] == encryptdata[33..43] {
            // First HMAC matches, check final HMAC
            let total_len = encryptdata.len() - 10;
            let mut hash2 = hmac_sha1(&hmac_key, &encryptdata[..total_len]);
            if hash2[..10] == encryptdata[encryptdata.len() - 10..] {
                // Both HMACs match
                header_length = encryptdata.len();
                self.handshake_status |= 0x08;
                self.recv_buffer.drain(..header_length);
                let mut result = Vec::new();
                // Strip any remaining TLS Application Data records
                while self.recv_buffer.len() > 5 {
                    if self.recv_buffer[0] != 0x17 {
                        break;
                    }
                    let size = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;
                    if size + 5 > self.recv_buffer.len() {
                        break;
                    }
                    result.extend_from_slice(&self.recv_buffer[5..5 + size]);
                    self.recv_buffer.drain(..5 + size);
                }
                return Ok((result, true));
            }
        }

        // Direct offset didn't work: iterate through TLS records (0x14 or 0x16)
        header_length = 0;
        while header_length < iter.len()
            && (iter[header_length] == 0x14 || iter[header_length] == 0x16)
        {
            header_length += 5;
            if header_length >= iter.len() {
                return Ok((buf.to_vec(), false));
            }
            let rec_len = u16::from_be_bytes([iter[header_length - 2], iter[header_length - 1]]) as usize;
            header_length += rec_len;
            if header_length > iter.len() {
                return Ok((buf.to_vec(), false));
            }
        }

        // Validate HMAC over accumulated records
        let mut hash = hmac_sha1(&hmac_key, &iter[..header_length - 10]);
        if hash[..10] == iter[header_length - 10..header_length] {
            self.handshake_status |= 0x08;
            self.recv_buffer.drain(..header_length);
            let mut result = Vec::new();
            // Strip any remaining TLS Application Data records
            while self.recv_buffer.len() > 5 {
                if self.recv_buffer[0] != 0x17 {
                    break;
                }
                let size = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;
                if size + 5 > self.recv_buffer.len() {
                    break;
                }
                result.extend_from_slice(&self.recv_buffer[5..5 + size]);
                self.recv_buffer.drain(..5 + size);
            }
            return Ok((result, true));
        }

        Ok((Vec::new(), false))
    }

    fn get_overhead(&self) -> usize {
        TLS_RECORD_OVERHEAD
    }

    fn need_feedback(&self) -> bool {
        true
    }
}

/// Generate random number in range [min, max)
fn rng_range(min: usize, max: usize) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(min..max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sni() {
        let sni = build_sni("example.com");
        // Should contain the hostname
        let sni_str = String::from_utf8_lossy(&sni);
        assert!(sni_str.contains("example.com"));
        // Should start with extension type 0x0000
        assert_eq!(sni[0], 0x00);
        assert_eq!(sni[1], 0x00);
    }

    #[test]
    fn test_pack_auth_data() {
        let key = b"test_key_12345678";
        let client_id = &[0u8; 32];
        let auth_data = pack_auth_data(key, client_id);
        assert_eq!(auth_data.len(), 32);

        // First 4 bytes should be timestamp (non-zero after epoch)
        let timestamp = u32::from_be_bytes(auth_data[0..4].try_into().unwrap());
        assert!(timestamp > 0);

        // Last 10 bytes should be HMAC (not all zeros)
        assert!(auth_data[22..32].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_pack_data() {
        let data = b"hello";
        let packed = pack_data(data);
        assert_eq!(packed[0], 0x17); // Application data
        assert_eq!(packed[1], 0x03);
        assert_eq!(packed[2], 0x03);
        assert_eq!(packed[3], 0x00);
        assert_eq!(packed[4], 0x05); // length = 5
        assert_eq!(&packed[5..], data);
    }

    #[test]
    fn test_tls_overhead() {
        let obfs = Tls12TicketAuthObfs::new(
            "example.com".to_string(),
            443,
            String::new(),
            false,
        );
        assert_eq!(obfs.get_overhead(), 5);
        assert!(obfs.need_feedback());
    }

    #[test]
    fn test_build_client_hello() {
        let mut obfs = Tls12TicketAuthObfs::new(
            "example.com".to_string(),
            443,
            String::new(),
            false,
        );
        obfs.key = vec![0u8; 16];
        let client_hello = obfs.build_client_hello();

        // Should start with TLS record header
        assert_eq!(client_hello[0], 0x16);
        assert_eq!(client_hello[1], 0x03);
        assert_eq!(client_hello[2], 0x01);

        // Should contain ClientHello type
        assert_eq!(client_hello[5], 0x01);

        // Should be at least 5 + some reasonable minimum
        assert!(client_hello.len() > 50);
    }

    #[test]
    fn test_build_handshake_finish() {
        let mut obfs = Tls12TicketAuthObfs::new(
            "example.com".to_string(),
            443,
            String::new(),
            false,
        );
        obfs.key = vec![0u8; 16];
        let finish = obfs.build_handshake_finish();

        // Should contain handshake finish prefix
        assert_eq!(finish[0], 0x14);
        assert_eq!(finish[1], 0x03);
        assert_eq!(finish[2], 0x03);

        // Should end with HMAC
        assert!(finish.len() > 10);
    }

    #[test]
    fn test_rng_range() {
        for _ in 0..100 {
            let val = rng_range(10, 20);
            assert!(val >= 10 && val < 20);
        }
    }

    #[test]
    fn test_tls_auth_encode_first_call() {
        let mut obfs = Tls12TicketAuthObfs::new(
            "example.com".to_string(),
            443,
            String::new(),
            false,
        );
        obfs.key = vec![0u8; 16];

        // First call with empty data should return ClientHello
        let result = obfs.client_encode(b"").unwrap();
        assert!(!result.is_empty());
        assert_eq!(result[0], 0x16); // TLS record
        assert_eq!(obfs.handshake_status & 0x01, 0x01); // ClientHello sent
    }

    #[test]
    fn test_tls_auth_fastauth() {
        let mut obfs = Tls12TicketAuthObfs::new(
            "example.com".to_string(),
            443,
            String::new(),
            true,
        );
        obfs.key = vec![0u8; 16];

        // First call should return ClientHello + Finish
        let result = obfs.client_encode(b"").unwrap();
        assert!(!result.is_empty());
        // Should have both ClientHello and Finish
        assert_eq!(obfs.handshake_status & 0x04, 0x04); // Handshake complete
    }

    #[test]
    fn test_tls_auth_encode_after_handshake() {
        let mut obfs = Tls12TicketAuthObfs::new(
            "example.com".to_string(),
            443,
            String::new(),
            false,
        );
        obfs.key = vec![0u8; 16];
        obfs.handshake_status = 0x04; // Handshake complete

        let data = b"test data to encrypt";
        let result = obfs.client_encode(data).unwrap();

        // Should be wrapped in TLS records
        assert!(!result.is_empty());
        assert_eq!(result[0], 0x17); // Application data
    }

    #[test]
    fn test_tls_auth_decode_after_handshake() {
        let mut obfs = Tls12TicketAuthObfs::new(
            "example.com".to_string(),
            443,
            String::new(),
            false,
        );
        obfs.handshake_status = 0x08; // Server validated

        // Create a TLS application data record
        let data = b"decoded data";
        let mut record = vec![0x17, 0x03, 0x03];
        record.extend_from_slice(&(data.len() as u16).to_be_bytes());
        record.extend_from_slice(data);

        let (decoded, feedback) = obfs.client_decode(&record).unwrap();
        assert_eq!(decoded, data);
        assert!(!feedback);
    }
}
