# SSR-Client-RS 进度报告

## 当前状态

### ✅ auth_sha1_v4 端到端 (commit 4138f7b)
- 所有 183 测试通过 (122 lib + 46 full_coverage + 15 hk_integration)
- E2e 验证: auth_sha1_v4 + plain + aes-256-cfb → HTTP 200

### 🔧 auth_chain_a (commit 7fb6243)
- RC4 加密已实现 (stateful rc4::Rc4)
- AES-128-CBC 加密块已加入 pack_auth_data
- bytes_to_key 密钥派生已修正
- last_client_hash 已存储, init_rc4 已调用
- **仍失败**: tunnel_stage_initial 拒绝 — auth header 格式仍有问题
- 需要逐字节对比 C 客户端的 auth header 输出

### 未开始
- auth_chain_b-f
- UDP relay
