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

### ✅ T1 测试资产入库（GOALS.md 新阶段，2026-09-22）
- 旧的 UDP e2e 资产在 /tmp（会被清理），已入库:
  - `tests/e2e/test_udp_e2e.py` — 参数化 SOCKS5 UDP 测试（环境变量
    SOCKS_PORT/ECHO_PORT 注入；含 IPv4 echo、会话复用、domain 目标、
    app-addr 响应头断言）
  - `tools/e2e_udp.sh` — 自包含驱动脚本: mktemp 生成配置 → 起服务端/客户端
    → 轮询端口 → 跑测试 → 清理；`--all` 跑三组已知良好组合
- 修复: 本机 ss 不认 `-tcp` 长选项（只认 `-t`），wait_port 改用 `-lnt`/`-ulnt`
- **验收**: `tools/e2e_udp.sh --all` → UDP_E2E_ALL_PASS，RC=0
  - aes-256-cfb+auth_chain_a (18396/19912) ✓
  - aes-256-cfb+auth_aes128_sha1 (18397/19913) ✓
  - aes-128-gcm+origin (18398/19914) ✓
- 注意: 第二组 teardown 时 C 服务端收到 SIGTERM 后段错误退出（bash 报
  "段错误"），**测试已 PASS 之后**发生，属服务端退出路径噪音，非我方 bug；
  记录备查

### 进行中 / 未开始（GOALS.md T→Q→R→P→M）
- [x] T1 测试资产入库（见上）
- [x] T2 边界与负面测试（见下"T2 记录"，net +47 用例）
- [x] T3 proptest 属性测试（见下"T3 记录"）
- [x] T4 e2e 矩阵脚本（见下"T4 记录"；**全矩阵 39/51 PASS + 12 SKIP, 0 FAIL**）
- [x] T5 异常恢复（见下 T5 记录，4/4 --ignored 全绿） / [ ] T6 soak
- [ ] Q1-Q10 代码质量（基线: 35 warning / 138 unwrap / 5 unsafe / 无 release profile）
- [ ] R1-R6 运行占用（基线未测）
- [ ] P1-P5 性能（无 benchmark）
- [ ] M1-M5 主线合入（无 CI / CHANGELOG / LICENSE）
- 门禁 G1-G12 见 GOALS.md；全绿才 push

### ✅ T2 边界与负面测试（2026-09-22）
- 落点: `tests/full_coverage.rs` mod `edge_cases`，47 个用例
  - SOCKS5 解析: 空/1字节/错版本/截断 method list/截断 domain/截断 ipv6
  - UDP 数据报: 空/3字节/截断头/未知 atyp/FRAG=1 必须暴露给中继/mDNS 5353
    必须可解析供中继丢弃/端口 0 与 65535 往返/255 字节域名往返/70000 字节
    超 MTU 载荷不 panic/空载荷
  - base64: 非法字符/单字符坏长度/空往返/全 256 字节二进制往返
  - JSON 配置: 截断/垃圾输入/根非对象/缺字段回落默认/错类型不 panic/
    端口越界
  - CipherEnv: 未知方法/截断 IV 解密/空解密/AEAD 走流 API 报错/空加密往返
  - 协议层: 空 pre_encrypt/空 post_decrypt/0..8 字节 post/UDP 钩子空输入/
    截断回喂——全部不 panic
- **发现 1 个真 bug 并修复**: `Json::as_u16/as_u32` 对 f64 直接 cast，
  Rust 饱和转换使 `server_port: 70000` 静默变 65535（合法端口）——
  已改为 fract()==0 且区间检查，越界返回 None 回落默认
- 2 个断言按 C 行为修正（非代码 bug）: auth_chain/auth_aes128 空输入
  返回 Ok(empty) 而非 Err —— C (auth_chain.c:644, auth.c:1251) 空输入
  0 字节无错误，TCP 分片重组依赖此路径
- 验证: `cargo test` → **189 passed / 0 failed** (125+93+15)

### ✅ T3 proptest 属性测试（2026-09-22）
- dev-dependency 加 `proptest`（loong64 拉取编译均成功，未启用降级方案）
- 落点: `tests/proptest_roundtrip.rs`，6 条属性 × 64 cases/条:
  1. 15 种流密码 `decrypt(encrypt(x)) == x`（任意 0..2048 字节 × 随机方法）
  2. AuthChainA pre_encrypt 不 panic 且 framing 只增不减
  3. AuthChainA post_decrypt 任意字节不 panic
  4. AuthAES128 + SHA1V4 post_decrypt 任意字节不 panic
  5. UDP 钩子 pre/post 任意字节不 panic + pre 不缩载荷
  6. UDP 数据报 build→parse 往返（任意 payload×port×三种地址类型）
- AEAD 方法不入流测试（走 context API，encrypt/decrypt 路径按设计报错）
- 验证: `cargo test` → **239 passed / 0 failed** (125+93+15+6)

### ✅ T4 e2e 矩阵脚本 + 发现并修复 set_server_iv 分派 bug（2026-09-23）
- 重写 `tools/matrix_test.py` 按 GOALS T4 组合策略:
  三轴（cipher 21 实现 + 8 SKIP / protocol 14 / obfs 6）+ UDP 轴（委托
  e2e_udp.sh），每例独立起停双端、结果写 `tests/e2e/RESULTS.md` +
  `matrix_results.json`（含日期与服务端 sha256）
- **修复脚本自身 2 个 bug**: ①目标 http.server PID 混入每例 kill 列表
  （首个用例后全部 connection refused）→ 拆 _target_pid；②des-cfb 服务端
  mbedTLS 不支持 → 归入 SKIP 表
- **矩阵首跑暴露真实回归（重大发现）**: auth_aes128 系 + 全部 obfs 轴
  失败；C 客户端同配置 404 成功 → 实锤我方 bug
  - 根因: `AuthAES128::set_server_iv` 是 inherent 方法（2afd58f），
    从未进 `impl Protocol` → `Box<dyn Protocol>` 动态分派走 trait 默认
    no-op → server_info.iv 恒空 → HMAC key 缺 cipher IV 前缀 →
    服务端 tunnel_stage_initial 拒包（SSR_DEBUG 抓到 `iv=` 空字节）
  - 修复: 在 `impl Protocol for AuthAES128` 覆写 set_server_iv；
    修后 `iv=f2bbf249…` 非空，同配置 404 与 C 客户端一致
- **矩阵 27/51 → 35/51 → 39/51 PASS + 12 SKIP, 0 FAIL（2026-09-23 终态）**;
  最后 8 例根因对照 C 源码全部修复/定性（f484417）:
  1. table: `encrypt_in_place` 把 Table 当 no-op（TCP 状态路径明文上线）→
     改在 `encrypt_ctx`/`decrypt_ctx` 应用 TableCipher
  2. rc4-md5/rc4-md5-6: `iv_size()` 曾返回 0，但 C 表 iv=16/6 且
     enc_iv_len 用 ss_cipher_iv_size（encrypt.c:1317-1321）→ IV 从未上线；
     会话密钥还被错截 6 字节（C setkey 用完整 16 字节 md5(key||iv)）
  3. chacha20: C 用 libsodium 原版 8 字节 nonce，我方补零成 12 字节走
     IETF → 改用 `chacha20::ChaCha20Legacy`（features=["legacy"]）
  4. verify_simple/auth_simple/auth_sha1/auth_sha1_v2: `--ref-c` 对照证明
     C 客户端同样 FAIL —— C 服务端没给这 4 个协议挂 server_post_decrypt
     （仅 v4/aes128/chain 挂；ssr_executive.c:649 NULL 即跳过解帧）→
     按 GOALS 控制规则记 PROTOCOL_SKIP
- `cargo test` 239 passed / 0 failed（无回归）

### ✅ T5 异常与恢复测试 + 实现 TCP idle_timeout 回收（2026-09-23）

- **实现 `idle_timeout` 回收**（此前配置存在但 TCP 路径未用；C 用 uv_timer，
  tunnel.c:158，每次 recv 重启、到期关 socket）:
  - `ObfsRelay` 新增 `idle_timeout` 字段（handle_connection 传入 config）
  - 流式 relay 循环 `tokio::select!` 加 idle 分支；上下行有数据即 reset
  - 首包等待取 `min(10, idle_timeout)`（idle 更紧时尊重 idle；0=禁用，保持原 10s）
- **`tests/resilience.rs`** 4 场景，均 `#[ignore]`（起真实 ssr-server），
  `cargo test --test resilience -- --ignored` **4/4 全绿**:
  1. `server_kill_client_survives_and_recovers` — kill -9 服务端：已建连接
     干净关闭（EOF/RST）、客户端进程不死、重启后新连接端到端成功
  2. `idle_timeout_reclaims_silent_connection` — idle=2s：静默连接在
     1.5~6s 内被 EOF 回收（验证非立即关、非不关）
  3. `hundred_concurrent_connections_all_succeed` — 100 并发隧道全 roundtrip
  4. `half_close_write_shutdown_settles_cleanly` — 本地 shutdown(Write)
     后 relay 传播 FIN、干净 EOF 收尾，客户端不死
- **坑**: C 服务端把 `idle_timeout:0` 解析成 0ms 立即触发的 uv_timer
  （config_json.c:149 ×1000），测试服务端配置固定 30s，仅被测客户端用场景值
- 回归: `cargo test` 239 passed + 4 ignored；全矩阵 39/51+12SKIP 无回归；
  `tools/e2e_udp.sh --all` UDP_E2E_ALL_PASS；release 构建 0 error

### ✅ T6 长稳 soak + R1 基线 + T7 回归确认（2026-09-23，Phase T 收官）

- **`tools/resource_probe.sh`**（T6 采样 + R1 基线复用同一脚本）:
  - 单发模式: `resource_probe.sh <pid>` → `rss_kb= fd= threads=`（soak 每 30s 调）
  - `--idle` 模式: 启动客户端空闲测量并断言 R1 目标
  - **R1 基线实测（hk.json，release 构建）**: idle RSS **3616KB**（≤20MB PASS）、
    线程 **5**（≤nproc+4=8 PASS）、空闲 CPU **0.00%**（PASS）、fd=11
- **`tools/soak_test.sh`**（T6）: 本地 64KB 文件每 2s curl 过 SOCKS5（TCP）+
  test_udp_e2e.py 每 30s 循环（UDP，每次新建会话压测 create/teardown，
  轮换 echo 端口），warmup 后每 30s 采样，断言 RSS 增长 ≤10MB、
  fd 回基线、无 panic、流量 0 失败
  - **600s 完整跑 SOAK_PASS**: TCP **298 ok/0 fail**、UDP **20 ok/0 fail**、
    RSS 3856→4640KB（增长 **784KB** ≤10MB）、fd 11→11、panic **0**
  - 90s 冒烟（SOAK_DURATION=90 WARMUP=30）亦 PASS，可用于 CI 快测
- **T7 回归确认（全部绿）**:
  - `cargo test` → **239 passed / 0 failed / 4 ignored**（基线 186 → 239，
    T 阶段净增 53: T2 边界 + T3 proptest + UDP/iv 相关）
  - `tools/e2e_udp.sh --all` → UDP_E2E_ALL_PASS
  - `tools/matrix_test.py` → **39/51 PASS + 12 SKIP, 0 FAIL**，
    结果表 `tests/e2e/RESULTS.md`（含日期 + 服务端 sha256[:12]=d70342262c45）
  - `tests/resilience.rs -- --ignored` → 4/4（T5）
  - 备注: GOALS G8/T4 写的是 `matrix_test.sh`，实际实现为
    `tools/matrix_test.py`（Python 三轴驱动，功能等价，以 .py 为准）
- **Phase T 全部 7 项完成**。GOALS.md T1-T7 勾选已同步。

### ✅ Q1 编译告警清零（2026-09-23，Phase Q 起点）

- **`cargo build` 35 → 0 warning**（debug 与 release 均 0，0 error），按 GOALS
  分三类逐类处理、每类跑 `cargo test` 验证无行为变化:
  1. **unused import/variable/mut（12）**: 删 TcpRelay/Protocol/XorShift128Plus/
     RngCore/get_s5_head_size 等未用 import、`spawn_session_task` 未用 `server`
     参数（连同调用点）、4 处 unnecessary mut、`header_length` 未读初值
  2. **deprecated from_slice/clone_from_slice（14）**: aead.rs 11 处
     `Nonce/Tag::from_slice` → `try_from` + map_err 错误分支（GOALS 禁 unwrap）；
     auth_chain/auth_aes128 3 处 `aes::Block::clone_from_slice` →
     定长数组用 `From<[u8;16]>`（hybrid-array 无失败分支），decrypt 切片用
     `try_from ... else break`（仅畸形尾块可达，原实现会 panic）
  3. **dead code（10）**: 删 udp_relay 只写不读的 `config` 字段、tls_ticket
     4 个 ClientHello 内联字节的重复 static、只写不读的 `server_port` 字段
     （C 侧同样不读，`new()` 参数保留 `_server_port` 维持 API）、
     `rng_range` 标 `#[cfg(test)]`（仅测试用）、auth_chain 8 个只写字段
     （构造后从不读取，解构点均用 `..`）、auth_sha1_v4 `has_recv_header`
- **回归全绿**: `cargo test` 239/0；矩阵 39/51+12SKIP 0 FAIL；UDP e2e
  ALL_PASS；resilience 4/4 —— e2e 证明字节行为未变
- clippy 基线（Q2 输入）: `cargo clippy --all-targets` = **58 warnings**
  （Top: manual !Range::contains ×9、useless format! ×5、empty line after
  doc comment ×5、repeat().take() ×3…）
