# SSR-Client-RS 进度报告

## 当前状态

### ✅ auth_sha1_v4 端到端 (commit 4138f7b)
- 所有 183 测试通过
- E2e: auth_sha1_v4 + plain + aes-256-cfb → HTTP 200

### ✅ auth_chain_a 端到端 (commit 9457264)
- RC4 加密已实现 (stateful rc4::Rc4)
- AES-128-CBC 加密块已加入 pack_auth_data (无填充, 零 IV, 匹配 C 代码)
- bytes_to_key 密钥派生已修正
- last_client_hash 已存储, init_rc4 已调用
- overhead=4 已设置 (之前默认为0)
- **关键修复**: pack_auth_data 现在调用 pack_client_data 处理数据部分, 而不是直接复制原始数据
- **已验证**: auth header HMAC 匹配, AES-CBC 解密显示 overhead=4, 时间戳检查通过
- **E2e**: SOCKS5 连接已建立, 数据可通过隧道传输
- **待验证**: httpbin.org 返回 HTTP/0.9 格式 (可能是数据格式问题, 需进一步调试)

### 未开始
- auth_chain_b-f
- UDP relay
