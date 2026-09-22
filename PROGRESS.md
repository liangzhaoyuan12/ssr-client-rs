# SSR-Client-RS 进度报告

## 当前状态

### ✅ auth_sha1_v4 端到端 (commit 4138f7b)
- E2e: auth_sha1_v4 + plain + aes-256-cfb → HTTP 200

### ✅ auth_chain_a 端到端 (commit 68f89e4)
- E2e: httpbin JSON 200 / example.com HTML / bytes/65536 code=200
- 修复清单（9 项，对照 C 逐行验证）见 commit message 68f89e4
- 核心教训: client_post_decrypt 从不处理 auth header; RC4 init 必须在
  pack_auth_data 内 pack_client_data 之前; rand_len 与 start_pos 必须共用
  reinit 后的同一条 PRNG 流

### ✅ auth_chain_b 端到端 (commit 4a826ee)
- **结构重构**: 引入 C 同构的 `get_tcp_rand_len` 分发机制 —
  `RandLenFn` 回调 + `RandLenCtx`(overhead + subclass contexts),
  pack_client_data / client_post_decrypt 走通用路径按变体分发
- `find_pos` 改为显式 lower_bound（C auth_chain_find_pos 语义;
  Rust binary_search 重复值时返回任意命中）
- `rand_len_b`: overhead 用 server_info(4) 而非 client_over_head(0);
  PRNG reinit 移入回调内（各变体的 datalength 守卫属于回调: A>1440, B>=1440）
- `AuthChainB::client_pre_encrypt` 委托通用 inner 路径（C 从不覆盖它）
- **E2e 已验证**（本地 ssr-server, auth_chain_b + plain + aes-256-cfb, 端口18390/19904）:
  - httpbin.org/ip → JSON 200
  - httpbin.org/bytes/102400 → code=200 size=102400
  - example.com → HTML
- 所有183 测试通过

### ✅ auth_chain_c 端到端 (commit 619219d)
- `rand_len_c` 按 C auth_chain.c:1270-1297 移植: **无条件 reinit PRNG**（C 注释
  "must init random in here to make sure output sync"，与 A/B 的守卫前 reinit 不同）
- AuthChainC::new 装回调 + 删自定义2000分块循环（委托 inner 通用路径）
- init_data_size 与 C 对照确认 (list_len = next()%24+12)
- 删除 C/D/E 从未被调用的旧 associated get_rand_len/find_pos 死代码
- **E2e 已验证**（端口18391/19905）: httpbin JSON 200 / bytes/102400 code=200
  （下行1456 分块多帧 + 跨读拼包正常）

### ✅ auth_chain_d 端到端 (commit 5331984)
- `rand_len_d` 按 C auth_chain.c:1368-1388 移植: 守卫 `other >= list0.last()`
  **先于 reinit** 且直接返回 0（与 C/E 的无条件 reinit 相反，也无 >1440 阶梯）
- AuthChainD::new 装回调；init_data_size 的 append-until->=1300/64 patch 循环
  与 C check_and_patch 对照确认；删自定义 client_pre_encrypt；c_ctx 字段移除
- **E2e 已验证**（端口18392/19906）: httpbin JSON 200 / bytes/102400 code=200

### ✅ auth_chain_e/f 端到端 (commit 2272da4)
- `rand_len_e` 按 C auth_chain.c:1405-1429 移植: 无条件 reinit（同 C 变体），
  尾部选择用 find_pos **最小值**（无 next() 随机，d/b/c 有随机选择）
- **F 复用 E 的回调**（C f_new_obfs 只换 salt，无自己的 get_rand_len）——
  AuthChainF::new 也装 rand_len_e；删 E/F 自定义 client_pre_encrypt
- F `#N#` interval 解析对齐 C (auth_chain.c:1500-1518): 数字位数 >2 才生效
  (l>2)、strtoll base0 (0x 十六进制/前导0 八进制)、正数且 !=LLONG_MAX；+单测
- F 的时间换 key init (server_key XOR 大端 time_key → from_bin 前16字节) 与 C 对照
- **E2e 已验证**: auth_chain_e+aes-256-cfb（端口18393/19907）与
  auth_chain_f+aes-128-cfb（端口18394/19908, param #86400#）均
  httpbin JSON 200 / bytes/102400 code=200
- **C 服务端 bug 发现**: ssr-server 在 auth_chain_f + key_len>16 的方法
  (如 aes-256-cfb) 启动即 SIGBUS —— auth_chain_f_set_server_info 把
  key_len(32) 字节 memcpy 进16字节栈缓冲; aes-128-cfb (key_len=16) 正常。
  我方客户端取 min(16) = C 的意图行为
- 所有184 测试通过

### ✅ UDP relay 端到端 (当前)
- `src/local/udp_relay.rs`: SOCKS5 UDP ASSOCIATE 中继，对照 C
  udp_ssr_client.c 移植:
  - 请求: `[RSV|FRAG|ATYP|ADDR|PORT|DATA]` → strip 3 字节 →
    `client_udp_pre_encrypt` → `encrypt_udp` → 按 (app, target) 会话
    socket 发往服务端; FRAG!=0 / 端口5353(mDNS) / 超大包丢弃
  - 响应: 解密 → `client_udp_post_decrypt` → 剥 SS 地址头 →
    回给应用的地址头 = **app 自身地址**（C udp_ssr_client.c:240
    `incoming_addr`，怪异但逐字节照抄）
  - 会话表按 (app_addr, target) 复用远端 socket，空闲超时
    `udp_timeout` 后移除
- `CipherEnv::encrypt_udp/decrypt_udp`: 单报文加解密 —— 流密码每包
  随机 IV（RC4 iv_len=0 无 IV）; AEAD = `salt||seal(nonce=0)||tag`
- 协议层 UDP 钩子: trait 默认 identity; AuthAES128 = `plain||uid(4LE)||
  hmac_md5(user_key, plain||uid)`; AuthChain A 实现
  `auth_chain_a_client_udp_pre_encrypt`（rc4+b64+rand+auth3+uid4+mac1）,
  B–F 委托 inner
- `create_protocol()` 从 handle_connection 提取复用（含 AEAD→origin
  降级）; `extra_param = protocol_param` 对齐 C ssr_executive.c:416
- `handle_connection` 新增 CMD_UDP_ASSOCIATE 分支: 回复 TCP 连接
  local_addr（=UDP 中继绑定端口）, `udp:false` 时回 0x07
- **E2e 已验证**（本地 ssr-server "udp":true + Python SOCKS5 客户端
  → 本地 echo 回环, /tmp/test_udp_e2e.py）:
  - auth_chain_a + aes-256-cfb (18396/19912) ✓
  - auth_aes128_sha1 + aes-256-cfb (18397/19913) ✓
  - origin + aes-128-gcm AEAD (18398/19914) ✓
  - 每组含: ASSOCIATE 应答 / IPv4 echo / 会话复用二连发 / domain 目标
- 所有186 测试通过

### 未开始
- 无 —— GOALS.md 有序阶段 (AEAD → auth_sha1_v4 → auth_chain_a–f →
  UDP relay) 全部完成
