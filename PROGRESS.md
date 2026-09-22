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

### 下一阶段已知问题（auth_chain_c-f 按 B 的套路做）
1. C/D/E/F 构造时未设 `rand_len_fn`/`rand_len_ctx` → 仍走 A 回调（分发机制
   已就绪，只需 new() 里安装 + 把各自 data_size_list 初始化挪进 ctx.c）
2. C/D/E/F 的自定义 `client_pre_encrypt` 覆盖应删除、委托 inner（同 B 已做）
3. C/D/E/F 的 data_size_list 初始化/分支逻辑尚未逐行对照 C
   （C: auth_chain_c_get_rand_len line1218+, D/E/F 各自版本）
4. E 的 `get_rand_len` 有已知 unused rng warning（line873, 改造时一并处理）

### 未开始
- auth_chain_c-f
- UDP relay
