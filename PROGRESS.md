# SSR-Client-RS 进度报告

## 当前状态

### ✅ auth_sha1_v4 端到端 (commit 4138f7b)
- 所有 183 测试通过 (122 lib + 46 full_coverage + 15 hk_integration)
- E2e 验证: auth_sha1_v4 + plain + aes-256-cfb → HTTP 200

### 🔧 auth_chain_a (commit c5b8f61)
- RC4 加密已实现 (stateful rc4::Rc4)
- auth header (pack_auth_data) 格式仍不正确
- 服务端在 tunnel_stage_initial 拒绝 — 需要修复 pack_auth_data 格式

### 未开始
- auth_chain_b-f
- UDP relay
