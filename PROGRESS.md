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

### 🔧 Phase 7: 协议扩展 (进行中)
- 所有协议已注册到选择器 (auth_sha1_v4, auth_sha1_v2, auth_sha1, auth_simple, auth_chain_a-f)
- auth_sha1_v4 修复:
  - data_offset = rand_len + 6 (之前错误)
  - CRC32 是 4 字节 LE (之前只有 2 字节)
  - HMAC key 填充到 80 字节匹配 C 的 ss_sha1_hmac
  - pack_data 不填充随机数据 (C 代码也不填充)
  - client_post_decrypt data_start 修正
- **auth_sha1_v4 端到端仍失败**: 服务端拒绝数据包
  - 单测 roundtrip 通过, 但与 C 服务端不互通
  - 可能原因: CRC32 计算差异 / HMAC 数据范围差异 / recv_iv 使用差异

### 未开始
- auth_chain_a-f 端到端测试
- UDP relay

## 关键架构理解

### AEAD 降级 (ssr_executive.c:175-179)
AEAD 密码自动切换: obfs→plain, protocol→origin. 直接 salt(32)+AEAD(data).

### HMAC Key 填充 (obfsutil.c:64-80)
C 的 ss_sha1_hmac 分配 80 字节: [iv(16)][key(N)][zeros(64-N)]

### auth_sha1_v4 数据格式
```
[len(2)][CRC32(4)][zeros(2)][rand_len(1|3)][gap(zeros)][timestamp(4)][client_id(4)][conn_id(4)][data][HMAC(10)]
```

## 测试结果
- 122 lib 单测通过 (无回归)
- AEAD 端到端: ✅ httpbin 200 / github 301
- auth_sha1_v4 端到端: ❌ 服务端拒绝
