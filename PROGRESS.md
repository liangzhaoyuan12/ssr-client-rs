# SSR-Client-RS 进度报告

## 当前状态

### ✅ Phase 4: 真实服务器连通 (commit 2afd58f)
- 生产配置 aes-256-cfb + auth_aes128_sha1 + tls1.2_ticket_auth 完全可用
- httpbin 200, google 204, github 200, 5MB 4.52 MB/s (C: 4.27 MB/s)

### ✅ Phase 5: 矩阵测试 + obfs 修复 (commit 4485872)
- 183 个测试通过
- chacha20-ietf 支持
- obfs needs_handshake() trait 方法

### ✅ Phase 6: AEAD 实现 (commits 7f40c0d + ddc99b5)
- AEAD 模块: HKDF-SHA1, 5 种密码, SIP004 分帧
- **关键发现**: ssr_executive.c:175-179 — AEAD 下协议和混淆自动降级为 plain + origin
- AEAD 本地测试通过: aes-256-gcm + plain + origin → HTTP 200
- EOF drain 修复 + 跳过 feedback 等待

### ✅ auth_sha1_v4 端到端 (commits 4138f7b + a8b269e)
- **根因1**: set_server_iv 对所有 auth 协议是 no-op → HMAC key 使用 zeros(16)+key(32) 而非 cipher_iv(16)+key(32)
- **根因2**: ss_hmac_key 返回 80 字节但 C 只用 iv_len+key_len=48 字节
- **根因3**: client_post_decrypt 错误处理 auth header — 客户端只收到 pack_data，不收 pack_auth_data
- **根因4**: get_rand_len 对 >1300 返回 0，C 始终 ≥ 1
- E2e 验证: auth_sha1_v4 + plain + aes-256-cfb → HTTP 200
- 所有 183 测试通过 (122 lib + 46 full_coverage + 15 hk_integration)

### 🔧 auth_chain_a 端到端 (进行中)
- 服务端拒绝数据包 — 原因: encrypt_buffer/decrypt_buffer 是空操作
- RC4 加密未实现 — auth_chain_a 使用独立的 RC4 密码上下文
- 需要实现: stateful RC4 加密/解密 + AES-128-CBC 认证头

### 未开始
- auth_chain_b-f 端到端测试
- UDP relay
