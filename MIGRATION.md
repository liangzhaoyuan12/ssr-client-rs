# SSR-N → Rust 客户端库迁移大纲

## 一、项目定位

- **产出**: `ssr-client-rs` — 一个 Rust lib crate（`crate-type = ["lib"]`）
- **不做的**: 不编译二进制，不做服务端，不做 daemon
- **用途**: 供其他项目（如 GTK4 应用、Tauri 应用）作为依赖调用
- **运行时**: tokio 异步（替换 libuv 事件循环）
- **配置方式**: 调用方直接构造 struct，不需要 JSON 解析

## 二、SSR-N 完整特性清单（需迁移）

### 2.1 加密方法（28 种）

| 编号 | 名称 | iv_size | key_size | Rust 方案 |
|------|------|---------|----------|-----------|
| 0 | none | 0 | 16 | 透传 |
| 1 | table | 0 | 16 | 手动实现（查表法） |
| 2 | rc4 | 0 | 16 | `rc4` crate |
| 3 | rc4-md5-6 | 6 | 16 | `rc4` + MD5 派生 |
| 4 | rc4-md5 | 16 | 16 | `rc4` + MD5 派生 |
| 5 | aes-128-cfb | 16 | 16 | `aes` + `cipher` (CFB 模式) |
| 6 | aes-192-cfb | 16 | 24 | `aes` + `cipher` (CFB 模式) |
| 7 | aes-256-cfb | 16 | 32 | `aes` + `cipher` (CFB 模式) |
| 8 | aes-128-ctr | 16 | 16 | `aes` + `cipher` (CTR 模式) |
| 9 | aes-192-ctr | 16 | 24 | `aes` + `cipher` (CTR 模式) |
| 10 | aes-256-ctr | 16 | 32 | `aes` + `cipher` (CTR 模式) |
| 11 | bf-cfb | 8 | 16 | `blowfish` crate |
| 12 | camellia-128-cfb | 16 | 16 | `camellia` crate 或手动 |
| 13 | camellia-192-cfb | 16 | 24 | `camellia` crate 或手动 |
| 14 | camellia-256-cfb | 16 | 32 | `camellia` crate 或手动 |
| 15 | cast5-cfb | 8 | 16 | 手动实现（Rust 无现成 crate） |
| 16 | des-cfb | 8 | 8 | `des` crate 或手动 |
| 17 | idea-cfb | 8 | 16 | 手动实现 |
| 18 | rc2-cfb | 8 | 16 | 手动实现 |
| 19 | seed-cfb | 16 | 16 | 手动实现 |
| 20 | salsa20 | 8 | 32 | `salsa20` crate |
| 21 | chacha20 | 8 | 32 | `chacha20` crate |
| 22 | chacha20-ietf | 12 | 32 | `chacha20` crate |
| 23 | aes-128-gcm | 0 | 0 | `aes-gcm` crate |
| 24 | aes-192-gcm | 0 | 0 | `aes-gcm` crate |
| 25 | aes-256-gcm | 0 | 0 | `aes-gcm` crate |
| 26 | chacha20-ietf-poly1305 | 0 | 0 | `chacha20poly1305` crate |
| 27 | xchacha20-ietf-poly1305 | 0 | 0 | `xchacha20poly1305` crate |

**密钥派生**: 所有加密方法使用 `EVP_BytesToKey`（MD5 迭代）从密码派生 key 和 iv，需手动实现。

### 2.2 协议（14 种）

| 编号 | 名称 | 说明 | 复杂度 |
|------|------|------|--------|
| 0 | origin | 透传，无协议层 | 低 |
| 1 | verify_simple | 简单 HMAC 验证 | 低 |
| 3 | auth_simple | 简单认证 | 低 |
| 4 | auth_sha1 | SHA1 HMAC 认证 | 中 |
| 5 | auth_sha1_v2 | SHA1 HMAC v2 | 中 |
| 6 | auth_sha1_v4 | SHA1 HMAC v4 | 中 |
| 7 | auth_aes128_md5 | AES128 + MD5 认证 | 高 |
| 8 | auth_aes128_sha1 | AES128 + SHA1 认证 | 高 |
| 9 | auth_chain_a | 链式协议 a | 极高 |
| 10 | auth_chain_b | 链式协议 b | 极高 |
| 11 | auth_chain_c | 链式协议 c | 极高 |
| 12 | auth_chain_d | 链式协议 d | 极高 |
| 13 | auth_chain_e | 链式协议 e | 极高 |
| 14 | auth_chain_f | 链式协议 f | 极高 |

**协议层接口**（每个协议插件实现两个核心函数）：
- `client_pre_encrypt(plaindata) -> framed_data` — 发送前封装
- `client_post_decrypt(framed_data) -> plaindata` — 接收后解封

**auth_chain_a~f 差异**：
- 每个版本的 HMAC 计算方式、数据分片策略、IV 生成逻辑不同
- auth_chain_a 是基础版本，b~f 在 a 的基础上逐步增加特性（如多用户支持、更快的 IV 生成等）
- C 代码约 600 行，是整个项目最复杂的部分

### 2.3 混淆（6 种）

| 编号 | 名称 | 说明 | 实现方式 |
|------|------|------|----------|
| 0 | plain | 透传，无混淆 | 直接返回 |
| 1 | http_simple | HTTP GET 请求伪装 | 手动构建 HTTP 请求 |
| 2 | http_post | HTTP POST 请求伪装 | 手动构建 HTTP POST |
| 3 | http_mix | HTTP 混合（随机 GET/POST） | 随机选择 |
| 4 | tls1.2_ticket_auth | TLS 1.2 ticket 认证伪装 | 手动构建 TLS ClientHello + HMAC ticket |
| 5 | tls1.2_ticket_fastauth | TLS 1.2 ticket 快速认证 | 在 ticket_auth 基础上简化握手 |

**混淆层接口**（每个混淆插件实现四个核心函数）：
- `client_encode(buf) -> encoded_buf` — 发送前混淆
- `client_decode(buf) -> decoded_buf` — 接收后还原
- `client_pre_encrypt(plaindata) -> framed_data` — 协议层前封装（仅协议插件使用）
- `client_post_decrypt(framed_data) -> plaindata` — 协议层后解封

**tls1.2_ticket_auth 工作原理**：
- 不是标准 TLS 连接，是自定义的 ClientHello 伪装
- 用 HMAC-MD5 生成 ticket，附加在 TLS 记录中
- 服务端验证 ticket 后才开始数据传输

### 2.4 传输层

| 特性 | SSR-N 实现 | Rust 方案 |
|------|-----------|-----------|
| SOCKS5 本地代理 | libuv 回调 | tokio TcpStream + 手动解析 |
| TCP 隧道 | libuv | tokio TcpStream |
| UDP 中继 | libuv | tokio UdpSocket |
| WebSocket 升级 | 手动 RFC6455 | `tokio-tungstenite` 或手动 |

### 2.5 辅助功能

| 功能 | SSR-N 实现 | Rust crate |
|------|-----------|-----------|
| Base64 编解码 | 手动 | `base64` |
| CRC32 | 手动 | `crc32fast` |
| HMAC-SHA1/MD5 | mbedTLS | `hmac` + `sha1` + `md-5` |
| MD5 哈希 | mbedTLS | `md-5` |
| Buffer 管理 | 自定义 buffer_t | `bytes::BytesMut` |
| DNS 缓存 | 手动 | 手动（简单 HashMap + TTL） |
| 随机数 | libsodium | `rand` |

## 三、Rust 模块结构

```
src/
├── lib.rs                  # 公开 API 入口，re-export 核心类型
├── config.rs               # SsrClientConfig 结构体（纯 struct，无 JSON）
├── error.rs                # 统一错误类型 SsrError
│
├── crypto/                 # 加密层
│   ├── mod.rs
│   ├── cipher_env.rs       # CipherEnv — 统一加密环境（管理 key/iv/enc_ctx）
│   ├── stream.rs           # 流加密 (CFB/CTR/RC4/Salsa20/ChaCha20)
│   ├── aead.rs             # AEAD 加密 (GCM/Poly1305)
│   ├── table.rs            # table 算法
│   └── bytes_to_key.rs     # EVP_BytesToKey 密钥派生
│
├── protocol/               # 协议层
│   ├── mod.rs              # Protocol trait + 工厂函数
│   ├── origin.rs           # origin (透传)
│   ├── verify_simple.rs    # verify_simple
│   ├── auth_simple.rs      # auth_simple
│   ├── auth_sha1.rs        # auth_sha1 / auth_sha1_v2 / auth_sha1_v4
│   ├── auth_aes128.rs      # auth_aes128_md5 / auth_aes128_sha1
│   └── auth_chain.rs       # auth_chain_a~f（最复杂，单文件 600+ 行）
│
├── obfs/                   # 混淆层
│   ├── mod.rs              # Obfs trait + 工厂函数
│   ├── plain.rs            # plain (透传)
│   ├── http_simple.rs      # http_simple / http_post / http_mix
│   └── tls_ticket.rs       # tls1.2_ticket_auth / tls1.2_ticket_fastauth
│
├── relay/                  # 数据管道
│   ├── mod.rs
│   ├── tcp_relay.rs        # TCP 收发 + 编解码管线
│   └── udp_relay.rs        # UDP 中继
│
├── socks5/                 # SOCKS5 协议解析
│   ├── mod.rs
│   └── parser.rs           # s5_ctx 等价物
│
├── tunnel/                 # 隧道管理
│   ├── mod.rs
│   └── tcp_tunnel.rs       # TCP 隧道 (替换 client.c)
│
├── websocket/              # WebSocket 支持
│   └── mod.rs              # RFC6455 升级握手
│
├── local/                  # 本地代理服务器
│   ├── mod.rs              # SsrClient 主结构
│   └── api.rs              # 公开 API: start / stop / get_status
│
└── utils/                  # 工具函数
    ├── mod.rs
    ├── buffer.rs           # buffer_t 等价 (BytesMut 封装)
    ├── hash.rs             # MD5/SHA1/HMAC
    ├── base64.rs           # Base64
    ├── crc32.rs            # CRC32
    └── sockaddr.rs         # 地址类型
```

## 四、公开 API 设计

```rust
/// SSR 客户端配置 — 调用方直接构造，不需要 JSON 解析
pub struct SsrClientConfig {
    /// 远端服务器地址
    pub server: String,
    /// 远端服务器端口
    pub server_port: u16,
    /// 本地监听地址
    pub listen_address: String,
    /// 本地 SOCKS5 监听端口
    pub listen_port: u16,
    /// 加密密码
    pub password: String,
    /// 加密方法名（如 "aes-256-cfb"）
    pub method: String,
    /// 协议名（如 "auth_aes128_sha1"）
    pub protocol: String,
    /// 协议参数
    pub protocol_param: String,
    /// 混淆名（如 "tls1.2_ticket_auth"）
    pub obfs: String,
    /// 混淆参数
    pub obfs_param: String,
    /// 是否启用 UDP 中继
    pub udp: bool,
    /// 连接空闲超时（秒）
    pub idle_timeout: u32,
    /// 连接超时（秒）
    pub connect_timeout: u32,
    /// UDP 超时（秒）
    pub udp_timeout: u32,
}

/// SSR 客户端主结构
pub struct SsrClient { ... }

impl SsrClient {
    /// 创建客户端实例
    pub fn new(config: SsrClientConfig) -> Result<Self, SsrError>;

    /// 启动本地 SOCKS5 代理（异步，阻塞直到调用 stop）
    pub async fn start(&self) -> Result<(), SsrError>;

    /// 停止客户端
    pub async fn stop(&self) -> Result<(), SsrError>;

    /// 获取本地监听端口
    pub fn local_port(&self) -> u16;

    // 可选：TCP/UDP 直通 API（不做 SOCKS5，直接建立代理连接）
    // pub async fn connect_tcp(&self, target: TargetAddr) -> Result<TcpStream>;
    // pub async fn connect_udp(&self) -> Result<UdpSocket>;
}
```

## 五、依赖 crate

| 用途 | crate | 说明 |
|------|-------|------|
| 异步运行时 | `tokio` | 替换 libuv |
| 流加密 | `aes` | AES CFB/CTR |
| 流加密 | `cipher` | CFB/CTR 模式 traits |
| 流加密 | `rc4` | RC4 算法 |
| 流加密 | `chacha20` | ChaCha20 |
| 流加密 | `salsa20` | Salsa20 |
| 流加密 | `blowfish` | Blowfish (bf-cfb) |
| AEAD | `aes-gcm` | AES-GCM |
| AEAD | `chacha20poly1305` | ChaCha20-Poly1305 |
| AEAD | `xchacha20poly1305` | XChaCha20-Poly1305 |
| 哈希 | `md-5` | MD5 |
| 哈希 | `sha1` | SHA1 |
| 哈希 | `sha2` | SHA256 (可选) |
| HMAC | `hmac` | HMAC |
| 摘要 | `digest` | 统一 digest traits |
| WebSocket | `tokio-tungstenite` | WebSocket (可选，或手动) |
| Buffer | `bytes` | BytesMut |
| Base64 | `base64` | Base64 编解码 |
| CRC32 | `crc32fast` | CRC32 |
| 随机数 | `rand` | 随机数生成 |
| 错误处理 | `thiserror` | 错误派生宏 |
| 日志 | `log` | 日志 facade |

**可能需要手动实现的加密**（Rust 生态无现成 crate 或 crate 不成熟）：
- cast5-cfb
- idea-cfb
- rc2-cfb
- seed-cfb
- camellia-cfb（如有 `camellia` crate 可用则直接用）

## 六、开发阶段

### Phase 1: 基础框架（可编译）
1. Cargo.toml 依赖配置（lib crate）
2. `error.rs` — SsrError 统一错误类型
3. `config.rs` — SsrClientConfig 结构体
4. `crypto/types.rs` — CipherType、ProtocolType、ObfsType 枚举
5. `utils/` — hash、base64、crc32、sockaddr、buffer

### Phase 2: 加密层
6. `crypto/bytes_to_key.rs` — EVP_BytesToKey 密钥派生
7. `crypto/stream.rs` — 流加密（CFB/CTR/RC4 等）
8. `crypto/aead.rs` — AEAD 加密
9. `crypto/table.rs` — table 算法
10. `crypto/cipher_env.rs` — 统一加密环境
11. 单元测试：用已知向量验证每种加密方法

### Phase 3: 协议层
12. `protocol/mod.rs` — Protocol trait 定义
13. `protocol/origin.rs` — origin 透传
14. `protocol/verify_simple.rs` — verify_simple
15. `protocol/auth_simple.rs` — auth_simple
16. `protocol/auth_sha1.rs` — auth_sha1 / auth_sha1_v2 / auth_sha1_v4
17. `protocol/auth_aes128.rs` — auth_aes128_md5 / auth_aes128_sha1
18. `protocol/auth_chain.rs` — auth_chain_a~f（最复杂）
19. 单元测试

### Phase 4: 混淆层
20. `obfs/mod.rs` — Obfs trait 定义
21. `obfs/plain.rs` — plain 透传
22. `obfs/http_simple.rs` — http_simple / http_post / http_mix
23. `obfs/tls_ticket.rs` — tls1.2_ticket_auth / tls1.2_ticket_fastauth
24. 单元测试

### Phase 5: 传输层 + 代理
25. `socks5/parser.rs` — SOCKS5 协议解析
26. `relay/tcp_relay.rs` — TCP 编解码管线
27. `relay/udp_relay.rs` — UDP 中继
28. `tunnel/tcp_tunnel.rs` — tokio TCP 隧道
29. `local/api.rs` — SsrClient start/stop

### Phase 6: 集成测试 + 文档
30. 集成测试
31. 完善错误处理和日志
32. 编写 README 和使用示例

**注**: WebSocket 支持在 Phase 5 的 tunnel 模块中一并实现。

## 七、数据流

```
用户数据 → SOCKS5 解析 → 协议层 pre_encrypt → 加密层 encrypt → 混淆层 encode → 发送到服务器

服务器响应 → 混淆层 decode → 加密层 decrypt → 协议层 post_decrypt → 回送给用户
```

## 八、关键难点

1. **auth_chain_a~f** — 最复杂的协议变体，每个版本的 HMAC 计算、数据分片、IV 生成逻辑都不同，C 代码约 600 行，需仔细逐行翻译
2. **tls1.2_ticket_auth** — 不是标准 TLS，是自定义的 ClientHello 伪装，用 HMAC 生成 ticket，需手动构建 TLS 记录
3. **bytes_to_key** — EVP_BytesToKey 的 MD5 迭代密钥派生，多个加密方法依赖它
4. **UDP 中继** — 需要完整的 SOCKS5 UDP ASSOCIATE 实现 + 代理 UDP 数据包
5. **无 Rust crate 的加密** — cast5-cfb、idea-cfb、rc2-cfb、seed-cfb 在 Rust 生态中可能没有现成 crate，需要手动实现 CFB 模式
6. **协议兼容性** — 必须与 SSR-N 服务端完全兼容，一个 bit 的差异都会导致连接失败
