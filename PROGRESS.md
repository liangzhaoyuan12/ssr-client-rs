# SSR-Client-RS 进度报告

## 当前状态

### ✅ auth_sha1_v4 端到端 (commit 4138f7b)
- E2e: auth_sha1_v4 + plain + aes-256-cfb → HTTP 200

### ✅ auth_chain_a 端到端 (commit 68f89e4)
- **E2e 已验证**（本地 ssr-server, auth_chain_a + plain + aes-256-cfb）:
  - httpbin.org/ip → JSON 200 (origin 120.235.59.214)
  - example.com → 完整 HTML
  - httpbin.org/bytes/65536 → code=200 size=65536 (多帧下行)
- 本会话修复的 bug（全部对照 ssr-n/src/obfs/auth_chain.c 逐行验证）:
  1. `client_post_decrypt` 删除错误的 auth header 跳过块（客户端从不收 auth header,
     该块把 >=36 字节响应的头36字节和尾4字节丢弃 → HTTP/0.9/空响应）
  2. 包长 `data_len+rand_len+4`（原 +2，每帧截断）
  3. data_len 异或键用 `last_server_hash`（原来错用 last_client_hash）
  4. HMAC 密钥 recv_id 逐包更新（原来循环外只建一次）
  5. 收包只推进 `last_server_hash`（原来同时污染 last_client_hash）
  6. `pack_auth_data` 存 hmac2 到 last_server_hash（C line583，服务端首包异或键）
  7. rand_len/start_pos 必须 reinit `random_client/random_server` 后共用同一条
     PRNG 流（C shift128plus_init_from_bin_datalen → get_rand_start_pos）
  8. unit_size 用 `server_info.overhead`（C line621），非 client_over_head
  9. **RC4 初始化移到 pack_auth_data 内、pack_client_data 之前**（C line589-595）;
     原来在 pack_auth_data 返回后才 init，地址包以 encrypt_ctx=None 明文发出，
     服务端解出乱码地址直接丢弃连接
- relay: 等首个本地数据后 address+data 合并为一次 client_pre_encrypt
- 保留了 SSR_DEBUG=1 门控的 `[acapostd]` 诊断日志
- 所有183 测试通过

### 下一阶段已知问题（auth_chain_b-f 动手前先读）
1. `AuthChainB::get_rand_len` 用一次性 rng，未 reinit `inner.local.random_client`
   → start_pos 与服务端错位（与 A 已修的同型 bug）
2. `AuthChainB` 及 C/D/E/F 的 overhead 用 `client_over_head`(客户端恒0)，
   应为 `server_info.overhead`(4)（C b line1164）
3. **结构性**: C 的通用 `pack_client_data` 经 `local->get_tcp_rand_len` 回调
   分发到 b/c/d/e/f 变体; 我们的 `AuthChainA::pack_client_data` 硬编码 A 的
   `get_rand_len` → B 的尾包、C/D/E/F 全部分包都会用错 rand_len 算法。
   需要引入分发机制（如 context 内存储回调）
4. C/D/E/F 的 data_size_list 初始化/分支逻辑尚未逐行对照 C 校验

### 未开始
- auth_chain_b-f
- UDP relay
