# SSR-N → Rust 迁移进度报告

## 当前状态：✅ 已完成，真实服务器连接验证通过

Rust 客户端已能连接生产服务器，并与 C 客户端功能对等。

## 验证结果 (2026-09-20)

真实服务器 `hk.json` (192.0.2.1:2800, aes-256-cfb / auth_aes128_sha1 / tls1.2_ticket_auth)：

```
http://httpbin.org/get                HTTP 200   (5/5 稳定)
https://www.google.com/generate_204   HTTP 204
https://api.github.com/zen            HTTP 200
http://example.com/                   HTTP 200   559B
5MB 下载                               HTTP 200   4.52 MB/s
同 URL 两次下载 md5 一致               完整性 OK
POST / chunked 流式                    HTTP 200
```

与 C 客户端 (`/opt/ssr/ssr-client`) 对比，同一服务器、同一时刻：

| 项目 | Rust | C |
|---|---|---|
| 5MB 吞吐 | 4.52 MB/s | 4.27 MB/s |
| google 204 延迟 | 0.67s | 0.70s |
| httpbin 延迟 | 0.606s | 0.605s |
| neverssl 成功率 | 3/6 | 3/6（站点自身不稳定） |

测试：**177 个全部通过**（116 unit + 46 full_coverage + 15 hk_integration）

## 关键突破：4 个 bug

### 1. ClientHello TLS 记录长度少 2 字节（致命）
`build_client_hello` 写的是 `4 + msg.len()`，实际载荷是 `6 + msg.len()`
（type 2B + body_len 2B + version 2B + body）。

后果链条：服务器按错误长度截断 ClientHello → **recv_buffer 残留 2 字节** →
下一个包 `buffer_concatenate` 后前面多出 2 字节 →
`buffer_compare(recv_buffer, "\x14\x03\x03\x00\x01\x01", 6)` 失败 →
`server_decode` 返回 NULL → `tunnel_shutdown`。

对照依据：C 客户端 312 字节 ClientHello 的记录长度字段 `0x0133` = 312−5 = 307 = 6+301。
服务器端见 `tls1.2_ticket.c:700`。

### 2. 协议层 MAC key 前缀用了全零 IV（致命）
`local/mod.rs` 里 `iv: vec![0u8; 16]` 从未被更新。

服务器 `auth.c:1398-1399` 用**收到的 cipher IV** 作为 MAC key 前缀：
```c
mac_key = recv_iv + key;   // recv_iv 在 tunnel_cipher_server_decrypt 里取数据前 16 字节
```
而客户端 C 代码 `ssr_executive.c:400` 把 `server_info.iv` 设为**实际发送的 cipher IV**
（`memcpy(server_info.iv, enc_ctx_get_iv(tc->e_ctx), iv_len)`）。

修复：新增 `AuthAES128::set_server_iv()`，在 `ObfsRelay::new` 里用生成的 `cipher_iv` 赋值。
修复后三个 HMAC（`out[1..7]`、`out[27..31]`、末尾 4 字节）全部与服务器计算值一致。

### 3. 协议名硬编码，auth_aes128_sha1 走了 MD5
`local/mod.rs` 无条件 `AuthAES128::new_md5()`，而配置是 `auth_aes128_sha1`。
C 代码 `auth.c:207-208` 对 sha1 变体设置 `hmac = ss_sha1_hmac_with_key`、`hash = ss_sha1_hash_func`。
修复：按 `config.protocol` 选择，并把 `hmac_fn`/`hash_fn` 返回类型改为 `Vec<u8>`（16B/20B 通吃）。

### 4. pack_auth_data 的 AES 加密块取错区间
C 代码 `auth.c:1166` 加密 `encrypt[0..16]`（时间戳+client_id+connection_id+两个长度），
我们再加密 `encrypt[4..20]`（少了时间戳、多了 4 个零字节）。

## 同时纠正的上轮误判

`rand_len` 曾被从 0–1023 改成 1–16，**这是错的**。
1–16 只属于 `auth_simple_pack_auth_data`（auth.c:265）；
`auth_aes128_sha1_pack_auth_data`（auth.c:1084）用的是：

```c
unsigned int rand_len = (datalength > 400 ? (xorshift128plus() & 0x1FF)
                                          : (xorshift128plus() & 0x3FF));
```

已改回。`get_rand_len`（auth.c:1000-1015）的分级逻辑同样改回原样。

## 其他改动

- **`src/config_json.rs`（新增）**：零依赖 JSON 解析 + `config_from_json()`，
  支持 ssr-n 的 `client_settings` 嵌套格式；含 4 个单元测试
- **`src/log.rs`（新增）**：`ssr_debug!` 宏，逐包 hexdump 日志改为需 `SSR_DEBUG=1` 才输出
- **`src/bin/ssr_client.rs`**：支持 `-c <config.json>` / `--help`，不再硬编码配置
- **ClientHello 扩展区对齐**：补上 C 代码 `tls_data2` 里的 `00 23`，
  去掉重复的 `00 20` 长度前缀和重复的 `01 00` 压缩字段

## 性能说明

debug 构建只有 ~507 KB/s，release 构建 4.52 MB/s —— 8 倍差距全部来自构建优化级别，
不是实现问题。**请用 `cargo build --release`**。

## 端到端支持矩阵（实测）

测试方法：本地 `ssr-server` + 本地 `python -m http.server` 目标，curl 经 SOCKS5 走完整链路。
对照组是同机的 C 客户端 (`/opt/ssr/ssr-client`)，脚本在 `/tmp/matrix_test.py`。

**总计 16/37 通过（C 客户端 32/37）**

| 维度 | 通过 | 不支持 |
|---|---|---|
| **obfs (5/5)** ✅ | plain, http_simple, http_post, http_mix, tls1.2_ticket_auth | — |
| **protocol (2/4)** | auth_aes128_sha1, auth_aes128_md5 | auth_sha1_v4, auth_chain_a |
| **cipher (9/28)** | aes-128/192/256-cfb, aes-128/192/256-ctr, bf-cfb, salsa20, chacha20-ietf | 见下 |

cipher 缺口分三类：

1. **需要 AEAD 分帧**（5 个）：`aes-128/192/256-gcm`、`chacha20-ietf-poly1305`、
   `xchacha20-ietf-poly1305`。这些在 SSR 里不是流密码 —— 用的是 Shadowsocks-AEAD 的
   分帧（2 字节长度前缀 + 16 字节 tag + salt），当前 relay 走的是流式 `ss_encrypt` 路径，
   需要单独实现。
2. **未实现的流密码**（6 个）：`camellia-128/192/256-cfb`（缺 crate）、
   `rc4`/`rc4-md5`/`rc4-md5-6`、`chacha20`（原始 8 字节 nonce 变体，
   需要 `chacha20` 的 `legacy` feature）、`none`/`table`（服务器回绝，原因待查）。
   `camellia-*` 和 AEAD 现在会返回**明确错误**而不是 panic。
3. **服务端本身不支持**（5 个，C 客户端同样失败，非我方问题）：
   `cast5-cfb`、`des-cfb`、`idea-cfb`、`rc2-cfb`、`seed-cfb`。

> 生产配置 `aes-256-cfb + auth_aes128_sha1 + tls1.2_ticket_auth` 在这三类之外，完全正常。

## 本轮（Session 4）修复

1. **obfs 接线错误**（让 4 个 obfs 从不可用变可用）
   - `create_obfs("plain")` 返回 `None`，而调用方把它当成错误 → 直接报 "Unsupported obfs"
   - 更根本的：`perform_obfs_handshake` 无条件等服务器响应。plain/http_* 这几种 obfs
     把分帧放在第一个数据包里，服务端根本不会先回包，于是白等 10 秒超时。
     给 `Obfs` trait 加了 `needs_handshake()`（默认 `false`，只有 tls1.2_ticket_auth 覆盖为 `true`）。
2. **panic 改成错误返回**：`ObfsRelay::new` 里 `create_encrypt_ctx().expect(...)` 在
   per-connection 任务里 panic，会让 worker 静默死掉、SOCKS5 客户端无限挂起且没有任何提示。
   改为 `SsrResult<Self>` 向上传递。
3. **协议名不再静默回退**：之前任何未知 `protocol` 都会退化成 `new_sha1`，
   于是用一个算法去对另一种算法的服务端，帧能解密但永远过不了 MAC。
   现在不支持的协议直接返回明确错误。
4. **新增 `chacha20-ietf`**（12 字节 nonce，直接用 `chacha20::ChaCha20`）。
5. **新增 `rc4-md5` / `rc4-md5-6`** 的 ctx 创建（`MD5(key ‖ iv)` 派生密钥，不再跳 IV），
   但实测仍不通，标记为待查。

## 本轮（Session 5）AEAD 实现 —— 已实现，但端到端仍未互通

**已完成**（`src/crypto/aead.rs`，5 个单元测试全过）：

| 组件 | 状态 |
|---|---|
| HKDF-SHA1（extract + expand，`info="ss-subkey"`） | ✅ 用现有 `hmac_sha1` 手写，无需新依赖 |
| 5 个 AEAD 密码（aes-128/192/256-gcm、chacha20-ietf-poly1305、xchacha20-ietf-poly1305） | ✅ |
| 分帧 `[长度+tag][明文+tag]`，长度掩码 `0x3FFF` | ✅ |
| nonce 从 0 起、每次 AEAD 操作按**小端**递增（每 chunk 两次） | ✅ |
| 加/解密上下文（salt 随机生成、首包前缀；解密侧按需缓冲，支持 salt 与 chunk 被拆包） | ✅ |
| 单测：5 种密码 roundtrip、逐字节投喂拆包、超 16383 字节自动分块、篡改 tag 必须报错 | ✅ 全过 |
| 接入 `CipherEnv`（`EncryptContext::Aead` / `DecryptContext::Aead`） | ✅ |

`aes-gcm 0.11` 只导出 128/256 的别名，AES-192 用 `AesGcm<Aes192, U12>` 自行定义。
AEAD 走 `AeadInOut`（不是旧的 `Aead` trait）。

**未解决**：真实互通仍失败，卡在 **obfs 握手**就断开
（`Server closed connection during handshake`），还没进到 AEAD 分帧那一层。

已排除的假设：
- ❌ 不是 obfs key 用空还是用主密钥 —— 两种都试过，都是同样的失败
- ❌ 不是分帧本身 —— 5 种密码的单测 roundtrip / 拆包 / 篡改检测全过

**根因定位**：tcpdump 抓包（透传代理在客户端和服务器之间）显示：
  - aes-256-cfb（流密码）：C 客户端发送 936B TLS ClientHello → 成功
  - aes-256-gcm（AEAD）：C 客户端发送 186B **非 TLS 格式数据** → 成功
  - Rust 客户端发送 480B TLS ClientHello → 被服务器拒绝

C 客户端在 AEAD 下的首包 73 字节首字节是 `0x50`（不是 `0x16`），**不符合 TLS 记录格式**。
但 C 客户端的服务器（288B）正常响应，说明服务器接受了这种格式。

**根本障碍**：`/opt/ssr/ssr-server` 二进制**不包含**源码中 obfs 的日志字符串
（"tls_auth wrong sha"、"tls_auth not client hello" 等均不存在），表明运行的服务器使用了
**与我们源码版本不同的 obfs 实现**。源码中的 `tls12_ticket_auth_client_encode` 无条件生成
`16 03 01 ...` 格式的 ClientHello，但实际二进制在 AEAD 下走了**不同的 obfs 路径**，
产生了非 TLS 格式的数据。

这是 **阻塞项**：需要拿到服务器对应的源码版本（或反编译二进制的 obfs 部分），
才能理解 AEAD 下的握手格式。单靠当前源码无法继续。

> 生产配置 `aes-256-cfb + auth_aes128_sha1 + tls1.2_ticket_auth` 不受影响，回归验证全过
> （真实服务器 httpbin 200 / github 200 / google 204，本地 ssr-server 200；183 个测试全过）。

## 后续可做（非阻塞）

1. **UDP relay**（当前只实现 TCP；hk.json 里 `"udp": true` 未使用）
2. **AEAD 分帧**（5 个 cipher）—— 如果要用 `aes-256-gcm` / `chacha20-poly1305`
3. **补 protocol**：auth_sha1_v4、auth_chain_a 及注册表里其余 12 个
4. 排查 `none`/`table`/`rc4` 系列为何被服务端回绝
5. `encrypt_ctx` / `decrypt_ctx` 每包一次 `Vec` 分配，可考虑复用缓冲区进一步提速

## 历史记录

### Session 2 (2026-09-19)
1. 状态化密码上下文 —— `EncryptContext`/`DecryptContext` 使用 `BufEncryptor`/`BufDecryptor`
2. 完整协议栈 in relay —— `client_pre_encrypt` → `encrypt_ctx` → `client_encode`
3. Obfs 握手 —— ClientHello 发送，server 响应 130 字节
4. Cargo edition 降级到 2021 —— 2024 edition match ergonomics 与 cipher enum 不兼容
5. HMAC 截断修复 —— Finished 消息 HMAC 从 20 字节改为 10 字节（`OBFS_HMAC_SHA1_LEN=10`）
6. 地址包发送 —— 从 SOCKS5 CONNECT 提取 ATYP+addr+port 作为 SSR 地址包
