use super::Obfs;
use crate::error::SsrResult;
use rand::Rng;

/// Random User-Agent strings (from C source)
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
    "Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
];

/// Fake request path templates (from C source: pairs of [prefix, suffix])
static REQUEST_PATHS: &[(&str, &str)] = &[
    ("", ""),
    ("login.php?redir=", ""),
    ("register.php?code=", ""),
    ("?keyword=", ""),
    ("search?src=typd&q=", "&lang=en"),
    ("s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&ch=&bar=&wd=", "&rn="),
    ("post.php?id=", "&goto=view.php"),
];

/// URL-encode a byte slice into %XX format
fn url_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 3);
    for &byte in data {
        result.push('%');
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

/// Generate a fake request path with encoded data
fn fake_request_path(encoded_data: &str) -> String {
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..REQUEST_PATHS.len());
    let (prefix, suffix) = REQUEST_PATHS[index];
    format!("{}{}{}", prefix, encoded_data, suffix)
}

/// Generate a random boundary string for multipart form data
fn random_boundary() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        .chars()
        .collect();
    (0..32)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// Select a random User-Agent string
fn random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())]
}

/// HTTP Simple obfuscation — wraps first data in HTTP GET request
pub struct HttpSimpleObfs {
    server_host: String,
    server_port: u16,
    extra_param: String,
    has_sent_header: bool,
    has_recv_header: bool,
}

impl HttpSimpleObfs {
    pub fn new(server_host: String, server_port: u16, extra_param: String) -> Self {
        Self {
            server_host,
            server_port,
            extra_param,
            has_sent_header: false,
            has_recv_header: false,
        }
    }

    /// Build host header value, handling comma-separated hosts and extra_param
    fn build_host_header(&self) -> String {
        let host_str = if self.extra_param.is_empty() {
            &self.server_host
        } else {
            &self.extra_param
        };

        // Split by comma, pick one randomly
        let hosts: Vec<&str> = host_str.split(',').collect();
        let mut rng = rand::thread_rng();
        let selected = hosts[rng.gen_range(0..hosts.len())];

        if self.server_port == 80 {
            selected.to_string()
        } else {
            format!("{}:{}", selected, self.server_port)
        }
    }
}

impl Obfs for HttpSimpleObfs {
    fn set_key(&mut self, _key: Vec<u8>) {}
    fn client_encode(&mut self, buf: &[u8]) -> SsrResult<Vec<u8>> {
        if self.has_sent_header {
            return Ok(buf.to_vec());
        }

        let mut rng = rand::thread_rng();
        // head_size is random: server_head_len + random(0..64)
        // For client-side, we don't know server_head_len, so use 0 + random
        let head_size = (rng.gen_range(0u32..64) as usize).min(buf.len());

        let encoded_head = url_encode(&buf[..head_size]);
        let path = fake_request_path(&encoded_head);
        let hostport = self.build_host_header();
        let user_agent = random_user_agent();

        let http_header = format!(
            "GET /{} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Accept-Language: en-US,en;q=0.8\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             DNT: 1\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path, hostport, user_agent
        );

        let mut result = Vec::with_capacity(http_header.len() + buf.len() - head_size);
        result.extend_from_slice(http_header.as_bytes());
        result.extend_from_slice(&buf[head_size..]);

        self.has_sent_header = true;
        Ok(result)
    }

    fn client_decode(&mut self, buf: &[u8]) -> SsrResult<(Vec<u8>, bool)> {
        if self.has_recv_header {
            return Ok((buf.to_vec(), false));
        }

        // Find \r\n\r\n to skip HTTP response header
        if let Some(pos) = find_crlfcrlf(buf) {
            let data_start = pos + 4;
            self.has_recv_header = true;
            Ok((buf[data_start..].to_vec(), false))
        } else {
            // Incomplete header, return empty
            Ok((Vec::new(), false))
        }
    }

    fn get_overhead(&self) -> usize {
        0
    }

    fn need_feedback(&self) -> bool {
        false
    }
}

/// HTTP POST obfuscation — wraps first data in HTTP POST request
pub struct HttpPostObfs {
    inner: HttpSimpleObfs,
}

impl HttpPostObfs {
    pub fn new(server_host: String, server_port: u16, extra_param: String) -> Self {
        Self {
            inner: HttpSimpleObfs::new(server_host, server_port, extra_param),
        }
    }
}

impl Obfs for HttpPostObfs {
    fn set_key(&mut self, _key: Vec<u8>) {}
    fn client_encode(&mut self, buf: &[u8]) -> SsrResult<Vec<u8>> {
        if self.inner.has_sent_header {
            return Ok(buf.to_vec());
        }

        let mut rng = rand::thread_rng();
        let head_size = (rng.gen_range(0u32..64) as usize).min(buf.len());

        let encoded_head = url_encode(&buf[..head_size]);
        let path = fake_request_path(&encoded_head);
        let hostport = self.inner.build_host_header();
        let user_agent = random_user_agent();
        let boundary = random_boundary();

        let http_header = format!(
            "POST /{} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Accept-Language: en-US,en;q=0.8\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Content-Type: multipart/form-data; boundary={}\r\n\
             DNT: 1\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path, hostport, user_agent, boundary
        );

        let mut result = Vec::with_capacity(http_header.len() + buf.len() - head_size);
        result.extend_from_slice(http_header.as_bytes());
        result.extend_from_slice(&buf[head_size..]);

        self.inner.has_sent_header = true;
        Ok(result)
    }

    fn client_decode(&mut self, buf: &[u8]) -> SsrResult<(Vec<u8>, bool)> {
        self.inner.client_decode(buf)
    }

    fn get_overhead(&self) -> usize {
        0
    }

    fn need_feedback(&self) -> bool {
        false
    }
}

/// HTTP Mix obfuscation — randomly uses GET or POST
pub struct HttpMixObfs {
    http_simple: HttpSimpleObfs,
    http_post: HttpPostObfs,
    use_post: bool,
}

impl HttpMixObfs {
    pub fn new(server_host: String, server_port: u16, extra_param: String) -> Self {
        let simple = HttpSimpleObfs::new(server_host.clone(), server_port, extra_param.clone());
        let post = HttpPostObfs::new(server_host, server_port, extra_param);
        // Determine if first request should be POST (1/4 to 1/7 chance)
        let mut rng = rand::thread_rng();
        let rate = rng.gen_range(3..7u32);
        let use_post = rng.gen_range(0..rate) == 0;
        Self {
            http_simple: simple,
            http_post: post,
            use_post,
        }
    }
}

impl Obfs for HttpMixObfs {
    fn set_key(&mut self, _key: Vec<u8>) {}
    fn client_encode(&mut self, buf: &[u8]) -> SsrResult<Vec<u8>> {
        if self.use_post {
            self.http_post.client_encode(buf)
        } else {
            self.http_simple.client_encode(buf)
        }
    }

    fn client_decode(&mut self, buf: &[u8]) -> SsrResult<(Vec<u8>, bool)> {
        // Both simple and post use same decode logic
        self.http_simple.client_decode(buf)
    }

    fn get_overhead(&self) -> usize {
        0
    }

    fn need_feedback(&self) -> bool {
        false
    }
}

/// Find \r\n\r\n in a byte slice
fn find_crlfcrlf(data: &[u8]) -> Option<usize> {
    let pattern = b"\r\n\r\n";
    data.windows(pattern.len())
        .position(|window| window == pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode(b"hello"), "%68%65%6c%6c%6f");
        assert_eq!(url_encode(b"\x00\x01\xff"), "%00%01%ff");
        assert_eq!(url_encode(b""), "");
    }

    #[test]
    fn test_http_simple_encode_first_time() {
        let mut obfs = HttpSimpleObfs::new("example.com".to_string(), 80, String::new());
        let data = b"test data";
        let encoded = obfs.client_encode(data).unwrap();

        // Should contain HTTP GET header
        let header_str = String::from_utf8_lossy(&encoded);
        assert!(header_str.starts_with("GET /"));
        assert!(header_str.contains("HTTP/1.1\r\n"));
        assert!(header_str.contains("Host: example.com\r\n"));
        assert!(header_str.contains("User-Agent:"));
        assert!(header_str.contains("\r\n\r\n"));
    }

    #[test]
    fn test_http_simple_encode_subsequent() {
        let mut obfs = HttpSimpleObfs::new("example.com".to_string(), 80, String::new());
        let data = b"test data";

        // First encode wraps in HTTP
        let _ = obfs.client_encode(data).unwrap();

        // Second encode should pass through
        let data2 = b"more data";
        let encoded = obfs.client_encode(data2).unwrap();
        assert_eq!(encoded, data2);
    }

    #[test]
    fn test_http_simple_decode() {
        let mut obfs = HttpSimpleObfs::new("example.com".to_string(), 80, String::new());

        // Simulate HTTP response
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nactual data here";
        let (decoded, feedback) = obfs.client_decode(response).unwrap();
        assert_eq!(decoded, b"actual data here");
        assert!(!feedback);
    }

    #[test]
    fn test_http_simple_decode_incomplete() {
        let mut obfs = HttpSimpleObfs::new("example.com".to_string(), 80, String::new());

        // Incomplete header
        let response = b"HTTP/1.1 200 OK\r\n";
        let (decoded, feedback) = obfs.client_decode(response).unwrap();
        assert!(decoded.is_empty());
        assert!(!feedback);
    }

    #[test]
    fn test_http_simple_decode_subsequent() {
        let mut obfs = HttpSimpleObfs::new("example.com".to_string(), 80, String::new());

        // First decode strips header
        let response = b"HTTP/1.1 200 OK\r\n\r\nfirst";
        let (decoded, _) = obfs.client_decode(response).unwrap();
        assert_eq!(decoded, b"first");

        // Second decode passes through
        let response2 = b"second data";
        let (decoded2, _) = obfs.client_decode(response2).unwrap();
        assert_eq!(decoded2, b"second data");
    }

    #[test]
    fn test_http_post_encode() {
        let mut obfs = HttpPostObfs::new("example.com".to_string(), 443, String::new());
        let data = b"test data";
        let encoded = obfs.client_encode(data).unwrap();

        let header_str = String::from_utf8_lossy(&encoded);
        assert!(header_str.starts_with("POST /"));
        assert!(header_str.contains("Content-Type: multipart/form-data; boundary="));
    }

    #[test]
    fn test_http_mix_encode() {
        let mut obfs = HttpMixObfs::new("example.com".to_string(), 80, String::new());
        let data = b"test data";
        let encoded = obfs.client_encode(data).unwrap();

        let header_str = String::from_utf8_lossy(&encoded);
        // Should be either GET or POST
        assert!(
            header_str.starts_with("GET /") || header_str.starts_with("POST /"),
            "Expected GET or POST, got: {}",
            &header_str[..20.min(header_str.len())]
        );
    }

    #[test]
    fn test_http_simple_with_extra_param() {
        let mut obfs =
            HttpSimpleObfs::new("default.com".to_string(), 443, "custom.com".to_string());
        let data = b"test";
        let encoded = obfs.client_encode(data).unwrap();
        let header_str = String::from_utf8_lossy(&encoded);
        assert!(header_str.contains("Host: custom.com:443\r\n"));
    }

    #[test]
    fn test_http_simple_overhead() {
        let obfs = HttpSimpleObfs::new("example.com".to_string(), 80, String::new());
        assert_eq!(obfs.get_overhead(), 0);
        assert!(!obfs.need_feedback());
    }

    #[test]
    fn test_find_crlfcrlf() {
        assert_eq!(find_crlfcrlf(b"foo\r\n\r\nbar"), Some(3));
        assert_eq!(find_crlfcrlf(b"no header"), None);
        assert_eq!(find_crlfcrlf(b"\r\n\r\n"), Some(0));
    }

    #[test]
    fn test_random_boundary_length() {
        let boundary = random_boundary();
        assert_eq!(boundary.len(), 32);
        assert!(boundary.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_random_user_agent() {
        let ua = random_user_agent();
        assert!(!ua.is_empty());
        assert!(ua.starts_with("Mozilla"));
    }
}
