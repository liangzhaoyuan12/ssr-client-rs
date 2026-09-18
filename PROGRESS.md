# SSR-N → Rust 迁移进度报告

## 当前状态：Phase 2 基本完成，2个测试失败待修

## 已完成的文件

### Phase 1: 基础框架 ✅
- `Cargo.toml` — 全部依赖配置（cipher 0.5, aes 0.9, cfb-mode 0.9, aes-gcm 0.11, chacha20poly1305 0.11 等）
- `src/lib.rs` — 公开 API 入口，re-export 核心类型
- `src/error.rs` — SsrError 统一错误类型（thiserror 派生）
- `src/config.rs` — SsrClientConfig 结构体（纯 struct，无 JSON）
- `src/crypto/mod.rs` — 加密模块入口
- `src/crypto/types.rs` — CipherType(28种)、ProtocolType(14种)、ObfsType(6种)、TargetAddr 枚举
- `src/utils/mod.rs` — 工具模块入口
- `src/utils/hash.rs` — MD5/SHA1/HMAC
- `src/utils/base64.rs` — Base64 编解码
- `src/utils/crc32.rs` — CRC32
- `src/utils/buffer.rs` — BytesMut 封装
- `src/utils/sockaddr.rs` — 地址类型

### Phase 2: 加密层 🔧 (编译通过，2个测试失败)
- `src/crypto/bytes_to_key.rs` — EVP_BytesToKey MD5 迭代密钥派生 ✅ 测试通过
- `src/crypto/table.rs` — Table 替换表密码 ✅ 测试通过
- `src/crypto/stream.rs` — 流加密 ✅ 编译通过，blowfish_cfb 测试失败
- `src/crypto/aead.rs` — AEAD 加密 + HKDF ✅ 编译通过
- `src/crypto/cipher_env.rs` — 统一加密环境 ✅ 编译通过

## 待修复的测试失败
1. `test_blowfish_cfb_roundtrip` — Blowfish CFB IV 长度问题（需要 8 字节 IV）
2. `test_cipher_env_chacha20` — ChaCha20 密钥/IV 长度问题

## 待完成的 Phase
- Phase 3: 协议层（origin, verify_simple, auth_simple, auth_sha1/v2/v4, auth_aes128, auth_chain_a~f）
- Phase 4: 混淆层（plain, http_simple/post/mix, tls1.2_ticket_auth/fastauth）
- Phase 5: 传输层（SOCKS5 parser, TCP/UDP relay, TCP tunnel, local/api）
- Phase 6: 集成测试 + 文档

## 已读取的 C 源码（供后续迁移参考）
- 加密层：encrypt.c/h, aead.c/h, ssr_cipher_names.c/h
- 协议层：auth.c/h, auth_chain.c/h（auth_output.json 保存了完整内容）
- 混淆层：obfs.c/h, http_simple.c/h, tls1.2_ticket.c/h, verify.c/h
- 传输层：socks5.c/h, tunnel.c/h, udprelay.c/h（ssr_n_file_contents.json 保存了完整内容）
- Executive：ssr_executive.c/h, ssrutils.c/h, common.h, shadowsocks.h

## 关键依赖版本（已验证可编译）
```
aes = "0.9"
cipher = "0.5"
cfb-mode = "0.9"
ctr = "0.10"
aes-gcm = "0.11"
chacha20poly1305 = "0.11"
rc4 = "0.2"
chacha20 = "0.10"
salsa20 = "0.11"
blowfish = "0.10"
des = "0.9"
md-5 = "0.10"
sha1 = "0.10"
hmac = "0.12"
hkdf = "0.12"
```

## 关键技术笔记
1. cipher 0.5 使用 `hybrid-array::Array` 而非 `GenericArray`
2. `new_from_slices`（双参数）用于 CFB/CTR，`new_from_slice`（单参数）用于 RC4
3. aes-gcm 0.11 的 Nonce 类型是 `Array<u8, U12>`（非泛型）
4. chacha20poly1305 0.11 的 Nonce/Tag 是具体类型（非泛型）
5. InOutBuf 不支持 `From<&mut Vec<u8>>`，需要用 `(&mut buf[..]).into()`
6. USTC 镜像与 crates.io 的 cipher 版本冲突已解决（统一使用 crates.io 版本）
