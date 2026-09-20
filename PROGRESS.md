# SSR-N → Rust 迁移进度报告

## 当前状态：173个测试通过，真实连接调试中

## Session 2 进展 (2026-09-19)

### 已完成
1. **状态化密码上下文** — `EncryptContext`/`DecryptContext` 使用 `BufEncryptor`/`BufDecryptor`
2. **完整协议栈 in relay** — `client_pre_encrypt` → `encrypt_ctx` → `client_encode`
3. **Obfs握手成功** — ClientHello发送，server响应130字节
4. **Cargo edition 降级到2021** — 2024 edition match ergonomics与cipher enum不兼容
5. **173/173 测试通过** — 112 unit + 46 full_coverage + 15 hk_integration
6. **HMAC截断修复** — Finished消息HMAC从20字节改为10字节（匹配C代码OBFS_HMAC_SHA1_LEN=10）
7. **地址包发送** — 从SOCKS5 CONNECT请求提取ATYP+addr+port作为SSR地址包

### 当前问题
Server拒绝CCS+Finished+pack_data。已排除：
- ✅ ClientHello格式正确（server响应130字节）
- ✅ HMAC截断为10字节
- ✅ 地址包格式正确（ATYP+addr+port=7字节）

### 待排查
1. C客户端的完整流程：发送CCS+Finished后还做了feedback交换（tunnel_stage_ssr_server_feedback_arrived）
2. HMAC key是否正确匹配（server_info.key + client_id）
3. pack_data中的加密数据格式

### 下一步
1. 用Python复现C客户端完整握手流程，逐字节对比
2. 检查server端client_decode的HMAC验证路径
