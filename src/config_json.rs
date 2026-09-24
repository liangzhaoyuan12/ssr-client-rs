//! Minimal JSON parsing for SSR client configuration files.
//!
//! Supports both the flat form:
//! ```json
//! { "server": "...", "server_port": 8388, "password": "...", ... }
//! ```
//! and the ssr-n form with a nested `client_settings` object. No external
//! dependency is used so the client builds on loongarch64 without fetching crates.

use crate::config::SsrClientConfig;
use crate::crypto::{CipherType, ObfsType, ProtocolType};

/// A parsed JSON value (only the subset needed for config files).
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null` literal.
    Null,
    /// `true` or `false` literal.
    Bool(bool),
    /// Number literal (JSON has a single numeric type; integers and floats
    /// both land here and are range-checked on conversion).
    Num(f64),
    /// String literal with JSON escapes already decoded.
    Str(String),
    /// Array value (`[ ... ]`), elements kept in source order.
    Arr(Vec<Json>),
    /// Object value (`{ ... }`) as ordered key/value pairs; `get` returns the
    /// first entry when a key is duplicated.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Look up a key in an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Interpret as a string: `Some` only for `Json::Str`, `None` otherwise.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Interpret as a port/`u16` config value: accepts an integral `f64` in
    /// `0..=u16::MAX` or a decimal string; `None` for other variants, negative
    /// or fractional numbers, or values that would saturate on cast.
    /// Used for `server_port`/`listen_port` (cf. `ssr-n/src/config_json.c`).
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            // Range-check: f64 -> u16 saturates in Rust (70000 would become
            // 65535, a silently valid port). Only integral in-range values convert.
            Json::Num(n) => {
                if n.fract() == 0.0 && *n >= 0.0 && *n <= u16::MAX as f64 {
                    Some(*n as u16)
                } else {
                    None
                }
            }
            Json::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Interpret as a timeout/`u32` config value: accepts an integral `f64` in
    /// `0..=u32::MAX` or a decimal string; `None` for other variants, negative
    /// or fractional numbers, or values that would saturate on cast.
    /// Used for `*_timeout` fields (cf. `ssr-n/src/config_json.c`).
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            // Same saturation guard as as_u16 (negative -> 0, huge -> u32::MAX).
            Json::Num(n) => {
                if n.fract() == 0.0 && *n >= 0.0 && *n <= u32::MAX as f64 {
                    Some(*n as u32)
                } else {
                    None
                }
            }
            Json::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Interpret as a boolean: `Some` only for `Json::Bool`, `None` otherwise.
    /// Used for the `udp` flag (cf. `ssr-n/src/config_json.c`).
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Parser {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    fn expect_byte(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at offset {}", c as char, self.pos))
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        match self.peek().ok_or("unexpected end of input")? {
            b'{' => self.parse_obj(),
            b'[' => self.parse_arr(),
            b'"' => Ok(Json::Str(self.parse_string()?)),
            b't' => self.parse_lit("true", Json::Bool(true)),
            b'f' => self.parse_lit("false", Json::Bool(false)),
            b'n' => self.parse_lit("null", Json::Null),
            _ => self.parse_num(),
        }
    }

    fn parse_lit(&mut self, lit: &str, val: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(format!("invalid literal at offset {}", self.pos))
        }
    }

    fn parse_num(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while self.pos < self.bytes.len()
            && matches!(
                self.bytes[self.pos],
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
            )
        {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| e.to_string())?;
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("invalid number '{s}'"))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        while let Some(c) = self.bytes.get(self.pos).copied() {
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = *self.bytes.get(self.pos).ok_or("bad escape")?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.pos..self.pos + 4)
                                .ok_or("bad \\u escape")?;
                            let hs = std::str::from_utf8(hex).map_err(|e| e.to_string())?;
                            let cp = u32::from_str_radix(hs, 16)
                                .map_err(|_| "bad \\u hex".to_string())?;
                            self.pos += 4;
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        other => {
                            return Err(format!("unknown escape \\{}", other as char));
                        }
                    }
                }
                _ => {
                    // Collect raw UTF-8 bytes through to the next special char.
                    let start = self.pos - 1;
                    let mut end = self.pos;
                    while end < self.bytes.len()
                        && self.bytes[end] != b'"'
                        && self.bytes[end] != b'\\'
                    {
                        end += 1;
                    }
                    out.push_str(
                        std::str::from_utf8(&self.bytes[start..end]).map_err(|e| e.to_string())?,
                    );
                    self.pos = end;
                }
            }
        }
        Err("unterminated string".to_string())
    }

    fn parse_arr(&mut self) -> Result<Json, String> {
        self.expect_byte(b'[')?;
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err("expected ',' or ']' in array".to_string()),
            }
        }
    }

    fn parse_obj(&mut self) -> Result<Json, String> {
        self.expect_byte(b'{')?;
        let mut fields = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            let key = self.parse_string()?;
            self.expect_byte(b':')?;
            let val = self.parse_value()?;
            fields.push((key, val));
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err("expected ',' or '}' in object".to_string()),
            }
        }
    }
}

/// Parse a JSON document.
pub fn parse_json(text: &str) -> Result<Json, String> {
    let mut p = Parser::new(text);
    let v = p.parse_value()?;
    Ok(v)
}

/// Build a client config from SSR-style JSON.
///
/// Top-level fields are read first; if a `client_settings` object is present,
/// its `server`, `server_port`, `listen_address` and `listen_port` override the
/// defaults (matching the ssr-n config layout).
pub fn config_from_json(text: &str) -> Result<SsrClientConfig, String> {
    let root = parse_json(text)?;
    let obj = match &root {
        Json::Obj(_) => &root,
        _ => return Err("config root must be a JSON object".to_string()),
    };

    let mut cfg = SsrClientConfig::default();

    if let Some(v) = obj.get("server").and_then(Json::as_str) {
        cfg.server = v.to_string();
    }
    if let Some(v) = obj.get("server_port").and_then(Json::as_u16) {
        cfg.server_port = v;
    }
    if let Some(v) = obj.get("listen_address").and_then(Json::as_str) {
        cfg.listen_address = v.to_string();
    }
    if let Some(v) = obj.get("listen_port").and_then(Json::as_u16) {
        cfg.listen_port = v;
    }
    if let Some(v) = obj.get("password").and_then(Json::as_str) {
        cfg.password = v.to_string();
    }
    if let Some(v) = obj.get("method").and_then(Json::as_str) {
        cfg.method = CipherType::from_name(v).map_err(|e| e.to_string())?;
    }
    if let Some(v) = obj.get("protocol").and_then(Json::as_str) {
        cfg.protocol = ProtocolType::from_name(v).map_err(|e| e.to_string())?;
    }
    if let Some(v) = obj.get("protocol_param").and_then(Json::as_str) {
        cfg.protocol_param = v.to_string();
    }
    if let Some(v) = obj.get("obfs").and_then(Json::as_str) {
        cfg.obfs = ObfsType::from_name(v).map_err(|e| e.to_string())?;
    }
    if let Some(v) = obj.get("obfs_param").and_then(Json::as_str) {
        cfg.obfs_param = v.to_string();
    }
    if let Some(v) = obj.get("udp").and_then(Json::as_bool) {
        cfg.udp = v;
    }
    if let Some(v) = obj.get("idle_timeout").and_then(Json::as_u32) {
        cfg.idle_timeout = v;
    }
    if let Some(v) = obj.get("connect_timeout").and_then(Json::as_u32) {
        cfg.connect_timeout = v;
    }
    if let Some(v) = obj.get("udp_timeout").and_then(Json::as_u32) {
        cfg.udp_timeout = v;
    }

    // ssr-n style nested settings override the flat/top-level values.
    if let Some(cs) = obj.get("client_settings") {
        if let Some(v) = cs.get("server").and_then(Json::as_str) {
            cfg.server = v.to_string();
        }
        if let Some(v) = cs.get("server_port").and_then(Json::as_u16) {
            cfg.server_port = v;
        }
        if let Some(v) = cs.get("listen_address").and_then(Json::as_str) {
            cfg.listen_address = v.to_string();
        }
        if let Some(v) = cs.get("listen_port").and_then(Json::as_u16) {
            cfg.listen_port = v;
        }
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_config() {
        let text = r#"{
            "server": "1.2.3.4",
            "server_port": 8388,
            "listen_address": "127.0.0.1",
            "listen_port": 1080,
            "password": "pw",
            "method": "aes-256-cfb",
            "protocol": "auth_aes128_sha1",
            "obfs": "tls1.2_ticket_auth",
            "udp": true,
            "idle_timeout": 120
        }"#;
        let cfg = config_from_json(text).unwrap();
        assert_eq!(cfg.server, "1.2.3.4");
        assert_eq!(cfg.server_port, 8388);
        assert_eq!(cfg.listen_port, 1080);
        assert_eq!(cfg.password, "pw");
        assert_eq!(cfg.method, CipherType::AES256CFB);
        assert_eq!(cfg.protocol, ProtocolType::AuthAES128SHA1);
        assert_eq!(cfg.obfs, ObfsType::TLS12TicketAuth);
        assert!(cfg.udp);
        assert_eq!(cfg.idle_timeout, 120);
    }

    #[test]
    fn client_settings_override_top_level() {
        let text = r#"{
            "password": "pw",
            "method": "aes-256-cfb",
            "protocol": "auth_aes128_sha1",
            "obfs": "tls1.2_ticket_auth",
            "client_settings": {
                "server": "example.com",
                "server_port": 8388,
                "listen_address": "0.0.0.0",
                "listen_port": 1080
            }
        }"#;
        let cfg = config_from_json(text).unwrap();
        assert_eq!(cfg.server, "example.com");
        assert_eq!(cfg.server_port, 8388);
        assert_eq!(cfg.listen_address, "0.0.0.0");
        assert_eq!(cfg.listen_port, 1080);
        assert_eq!(cfg.password, "pw");
    }

    #[test]
    fn parses_escapes_and_nested_arrays() {
        let v = parse_json(r#"{"a": "x\"y\\z", "b": [1, 2.5, true, false, null]}"#).unwrap();
        assert_eq!(v.get("a").unwrap().as_str().unwrap(), "x\"y\\z");
        match v.get("b").unwrap() {
            Json::Arr(items) => assert_eq!(items.len(), 5),
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(parse_json("{").is_err());
        assert!(parse_json(r#"{"a": }"#).is_err());
        assert!(config_from_json("[1,2]").is_err());
    }
}
