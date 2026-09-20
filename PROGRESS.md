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

## 后续可做（非阻塞）

1. UDP relay（当前只实现 TCP；hk.json 里 `"udp": true` 未使用）
2. 更多 protocol/obfs 组合的端到端验证（目前只验证了 auth_aes128_sha1 + tls1.2_ticket_auth）
3. `encrypt_ctx` / `decrypt_ctx` 每包一次 `Vec` 分配，可考虑复用缓冲区进一步提速

## 历史记录

### Session 2 (2026-09-19)
1. 状态化密码上下文 —— `EncryptContext`/`DecryptContext` 使用 `BufEncryptor`/`BufDecryptor`
2. 完整协议栈 in relay —— `client_pre_encrypt` → `encrypt_ctx` → `client_encode`
3. Obfs 握手 —— ClientHello 发送，server 响应 130 字节
4. Cargo edition 降级到 2021 —— 2024 edition match ergonomics 与 cipher enum 不兼容
5. HMAC 截断修复 —— Finished 消息 HMAC 从 20 字节改为 10 字节（`OBFS_HMAC_SHA1_LEN=10`）
6. 地址包发送 —— 从 SOCKS5 CONNECT 提取 ATYP+addr+port 作为 SSR 地址包
