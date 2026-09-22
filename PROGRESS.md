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

### 下一阶段已知问题（auth_chain_d-f 按 B/C 的套路做）
1. D/E/F 的 new() 需装 `rand_len_fn` + 把 data_size_list 初始化挪进 `rand_len_ctx.c`
   （D/E 的 struct 仍有独立 c_ctx 字段，F 需要新写）
2. D/E/F 的自定义 `client_pre_encrypt` 覆盖删除、委托 inner（同 B/C 已做）
3. 逐行对照 C 的回调:
   - D: auth_chain_d_get_rand_len + check_and_patch (last>=1300, max64)
   - E: auth_chain_e_get_rand_len（find_pos 取最小值分支）
   - F: auth_chain_f_get_rand_len + 时间换 key 的 init (key_change_interval)
4. F 的 init_data_size 现实现含 `#N#` 时间参数解析，需对照 C 校验

### 未开始
- auth_chain_d-f
- UDP relay
