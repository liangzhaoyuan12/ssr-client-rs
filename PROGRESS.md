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

### ✅ Q2 clippy 清零（2026-09-23）

- **基线 58 → 0**: `cargo clippy --all-targets -- -D warnings` **rc=0**
- 处理顺序（GOALS: correctness → perf → style，多数自动修）:
  1. `cargo clippy --fix --all-targets --allow-dirty --allow-staged` 自动应用
     ~37 条（Range::contains、useless format!、repeat().take()、Default impl、
     单 pattern match→if let、lifetimes elide、unnecessary mut/parens…）
  2. 手修 16 条:
     - 文件头 `///` doc 后空行（5 处）→ 改 `//`（挂在 `pub mod` 后的悬空 doc）
     - `large_enum_variant` ×2: **Box `Aead(AeadEncryptCtx)`**；Box 后仍报 →
       真正最大变体是 **Blowfish（~4KB S-box 状态）**，按 clippy 建议
       `Box<BlowfishCFB{Enc,Dec}>`，4192→~1KB
     - `&mut Vec` → `&mut [_]`（encrypt/decrypt_in_place 签名）
     - table.rs 两处 index 循环 → `iter().enumerate()` / `iter_mut()`
       （字节行为不变，e2e 兜底）
     - `Shift128plusCtx::next` → `next_u64`（避免混淆 Iterator::next；
       auth_chain.rs 有自己的同名 struct，两处定义 + 51 调用点同步）
     - 测试重复 `#[test]` 属性 ×2 去重、resilience 未读 `cli_port` 字段删除
- **测试数 239 → 237 的说明**: 两个 `#[test]` 各写了两遍，rustc 把同一 fn
  注册两次；去重后 `--list` 确认两测试各存 1 份、0 failed，覆盖未变
- **固化**: Cargo.toml 加 `[lints.rust] warnings = "deny"`（rustc 1.97 ≫ MSRV
  1.74），今后任何新 rustc warning 直接构建失败
- **e2e 回归（字节级）**: 矩阵 39/51+12SKIP 0 FAIL（覆盖改过的
  table/blowfish/aead 路径）、UDP e2e ALL_PASS、resilience 4/4、
  `cargo test` 237/0；release 构建 0 warning 0 error

### ✅ Q3 rustfmt 统一（2026-09-23）

- **基线**: `cargo fmt --all -- --check` 238 处 diff（散布 38 文件，多数为单行
  函数体、超长行、枚举紧凑写法）
- **执行**: `cargo fmt --all` 一次完成；再查 `-- --check` **exit 0**（GOALS 完成标准）
- **diff 规模**: 38 files, +1297 / −615
- **纯格式验证（三重）**:
  1. `cargo fmt --all -- --check` rc=0
  2. 字符串字面量多重集 vs HEAD: **sha256 完全一致**
     （`git show HEAD:<f>` 逐文件提取 `"..."` → uniq -c → 对比）
  3. 数值/协议常量（`[0-9a-fA-F]{4,}`、`Nu8`、`Nusize`）vs HEAD: **sha256 完全一致**
- **回归全绿**: `cargo build` 0 warning 0 error、`cargo test` **237/0**、
  `clippy --all-targets -- -D warnings` rc=0、release 0 warning、
  矩阵 39/51+12SKIP 0 FAIL、UDP e2e ALL_PASS、resilience 4/4

### ✅ Q4 生产路径 panic 清零（2026-09-23）

- **门禁脚本**: `tools/check_panic_paths.sh` — 扫 src/ 下
  `unwrap()/expect()/panic!/unreachable!`，awk 排除首个 `#[cfg(test)]`
  之后的测试块与 `src/bin/`（bin 允许 fail-fast）；白名单机制就位但
  **0 条**——全部逐处改造，没有留任何例外
- **基线 39 → 0**（GOALS 写的 138 是把测试/误报一起数了；真实生产路径 39 处），
  分 6 类:
  1. `config_json.rs` 解析器方法名 `fn expect` 假阳性 ×5 → 改名 `expect_byte`
  2. `local/mod.rs` `decrypt_ctx.as_mut().unwrap()` ×3 → `Option::insert()` 返回值
  3. `aead.rs` "set above" ×2 + `cipher_env.rs` key_len ×1 → `ok_or_else(SsrError)?`
  4. `cipher_env.rs` `unreachable!` ×2 → `encrypt_in_place/decrypt_in_place`
     改返 `SsrResult<()>`，AEAD 分支返回 `SsrError::Crypto`（调用点加 `?`）
  5. `utils/hash.rs` HMAC expect ×4 → `let Ok(...) else` + `debug_assert!` +
     返回全零 MAC（hmac-0.12 接受任意 key 长度，else 分支不可达）
  6. 结构性转 Result（网络数据路径返回 SsrError）:
     - `auth_chain.rs`: `rc4_once`/`init_rc4`/`pack_auth_data` → SsrResult；
       `new_from_slice().expect` ×3 → `map_err(SsrError::Crypto)?`；
       AES `unwrap` ×1 → `map_err?`；4 个 `rand_len_*.expect` →
       `let Some(..) else` + `debug_assert!` + `return 0`（与 datalength≥1440
       分支同义：无 padding）；`from_bin` try_into×4 → 数组解构（长度编译期固定）
     - `auth_aes128.rs`: `aes_128_cbc_encrypt/decrypt` → SsrResult（`map_err?`），
       `pack_auth_data` → SsrResult，测试调用点补 `.unwrap()`
     - `udp_relay.rs`: Mutex `lock().unwrap()` ×8 →
       `unwrap_or_else(PoisonError::into_inner)`（毒化恢复，单线程事件循环内
       不会实际发生，但消除 panic 点）
- **完成标准双达标**: 脚本 **exit 0**；`cargo test` **237/0**
- **回归全绿**: fmt --check 0、clippy -D warnings rc=0、release 0 warning、
  矩阵 39/51+12SKIP 0 FAIL、UDP e2e ALL_PASS、resilience 4/4

### ✅ Q5 unsafe 审计（2026-09-23）

- **5 处全部删除**（`grep -rn 'unsafe ' src` = 0，GOALS 完成标准第一条即达）
- 对象: `auth_chain.rs` 的 `unsafe impl Send for AuthChain{A..E}` ×5
- **判定依据（能删则删）**:
  1. 原 SAFETY 注释声称"contain raw pointers (for C FFI compatibility)"——
     **与代码不符**: `grep -rn '\*const\|\*mut' auth_chain.rs` = 0，五个 struct
     只含 GlobalData/ServerInfo/Context（全是普通所有权字段）
  2. 实测删除后 `cargo build` 0 error——类型本就自动实现 Send，
     unsafe impl 纯属冗余（历史遗留的防御性写法）
  3. `cargo test --no-run`（含 tokio::spawn 的 Send 检查路径）0 error，
     clippy -D rc=0——没有编译器层面依赖这些 impl 的地方
- **无保留条目**: 0 处 unsafe → 0 条 SAFETY 注释需要
- **回归全绿**: build/test 237-0、fmt 0、panic 脚本 rc=0、release 0 warning、
  矩阵 39/51+12SKIP 0 FAIL、UDP e2e ALL_PASS、resilience 4/4

### ✅ Q6 发布构建配置（2026-09-23）

- Cargo.toml 增加:
  ```toml
  [profile.release]
  opt-level = 3
  lto = "thin"
  codegen-units = 1
  strip = "symbols"
  ```
  `panic = "abort"` **不设**（库 crate，交给下游决定）——GOALS 原文要求
- **体积（GOALS 要求记录前后值）**:
  - 前: `target/release/ssr_client` = **1,819,664 字节**（1.8M）
  - 后: `target/release/ssr_client` = **1,184,576 字节**（1.2M）
  - **−635,088 字节 / −34.9%**
- **回归全绿（新二进制实测）**: cargo test 237/0、矩阵 39/51+12SKIP 0 FAIL、
  UDP e2e ALL_PASS、clippy -D rc=0、fmt 0、panic 脚本 rc=0、
  release 0 warning、二进制冒烟启动正常（读 hk.json 监听 1080）
- 注: thin LTO + CGU=1 改变了全部 crate 的编译指纹，release 全量重建耗时明显变长（本机约 1 分钟级），属预期

### ✅ Q7 公共 API 文档与示例（2026-09-23）

- **`#![warn(missing_docs)]`** 加入 src/lib.rs（配合 [lints.rust] warnings=deny，
  缺文档即构建失败，基线 **239 处**）
- **239 → 0**，3 个并行子任务分片完成（crypto 133 / protocol 47 / 其余 59）:
  - crypto: 方法写语义 + `# Errors` + C 对应（enc_table_init/enc_ctx_new_instance/
    cipher_context_set_iv/create_aead_cipher_ctx/ss_encrypt_all…），枚举变体带线上
    方法名字符串（aes-256-cfb → ss_cipher_*、ssr_cipher_names.h）
  - protocol: 结构体/new/字段 + C 对应（auth_chain.c:1087、auth.c:1601-1624、
    obfsutil.c:35-44 xorshift128plus…，行号均实测标注）
  - lib/socks5/config_json/utils/error/obfs/local: crate 级 `//!` 总览、SOCKS5
    常量字节语义引 RFC1928 §3/§4/§6、Json 取值访问器错误条件、SsrError 各变体
    产生条件
  - 全部为**纯新增**（git diff: +N/−0），doc 行 ≤100 字符
- **修 1 处坏 intra-doc link**: `decrypt_udp` 的 `[`encrypt_udp`]` →
  `[`Self::encrypt_udp`]`（rustdoc broken-intra-doc-links 在 -D warnings 下报错）
- **完成标准**:
  1. `cargo doc --no-deps` **exit 0、0 warning** ✓
  2. `cargo build --example socks5` 通过；实测
     `./target/debug/examples/socks5 hk.json` 打印
     `SOCKS5 listening on 0.0.0.0:1080 -> SSR 192.0.2.1:2800`，
     SIGINT 优雅退出 exit=0 ✓
- **回归全绿**: cargo build/test 237-0、clippy -D rc=0、fmt 0、
  panic 脚本 rc=0、矩阵 39/51+12SKIP 0 FAIL、UDP e2e ALL_PASS、resilience 4/4

### ✅ Q8 错误处理审计（2026-09-23）

**三类全库搜索结果与处置**:

1. `let _ =`（6 处）→ 处置后生产路径 **0** 处吞错:
   - `local/mod.rs` `remote_write.shutdown()`（客户端 EOF 后发 FIN）——
     **真吞错，已修**: 改 `if let Err(e)` + ssr_debug 日志（drain 照常，不中断）
   - `udp_relay.rs` `let _ = is_aead`——**死参数链，已清**: `spawn_session_task`
     的 `is_aead` 形参/UdpRelay 字段/调用点参数/丢弃语句四处全删
     （该值只在 `bind()` 里创建 protocol 时用一次）
   - `auth_chain.rs`/`auth_aes128.rs` `let _ = salt`——协议 trait `set_salt`
     的占位参数（salt 在构造函数注入），非错误，保留
   - 其余 2 处在 `#[cfg(test)]` 内（`let _ = ....unwrap()` 断言副作用），不计
   - `bin/ssr_client.rs` `signal::ctrl_c().await.ok()`——**真吞错，已修**:
     改 `if let Err(e)` + eprintln
2. `.ok()`（4 处生产）→ 逐处判定**非网络错误吞错**:
   - `sockaddr.rs resolve`: 返回类型即 `Option<SocketAddr>`（文档化的 API 语义），
     DNS 失败 = None，调用方 0 处（未被使用，保留 API）
   - `config_json.rs as_u16/as_u32`: 类型访问器，JSON 值类型不符 = None
     （Q7 已写入 doc 的错误条件）
   - `auth_chain.rs:1181`: strtol 镜像，解析失败 = None（对应 C strtol 语义）
3. `.unwrap_or_default()`（5 处）→ 全部是
   `SystemTime::now().duration_since(UNIX_EPOCH)`（时钟回拨防御），
   与 C 的 `time()` 语义一致，**非错误处理**，保留

**io::Error 源链 / API 形态**:
- `SsrError::Io(#[from] std::io::Error)` — thiserror source 链完整；
  `relay/mod.rs`、`local/mod.rs` 的 `write_all(...).await?` 等直接 `?` 传播走这条链
- 需要上下文的 66 处 `map_err(|e| ... format!("... {e}"))` 全部**内嵌原始错误文本**
  （操作+地址+错误三要素），无一处丢弃 `e`
- **无 `Box<dyn Error>` / anyhow**（全库 grep 0 命中；`Box<dyn Protocol/Obfs>`
  是内部 trait object，非错误类型）

**SsrError 变体覆盖核查**（构造点计数，含 helper）:
| 变体 | 构造点 | | 变体 | 构造点 |
|---|---|---|---|---|
| Crypto | 85 | | Connection | 13 |
| Socks5 | 21+6 | | Protocol | 25 |
| Obfs | 1 | | InvalidCipherMethod | 5 |
| Io | 隐式 `?`（8+ 处 await?） | | InvalidProtocol/InvalidObfs | 1/1 |
| **Timeout** | **2（本次接通）** | | Other/InvalidArgument | 0（helper 保留） |
- **修复**: 超时误用 `Connection` 变体 ×2（握手读响应、TCP connect 超时）
  → 改 `SsrError::Timeout`，`Timeout` 变体从 0 使用变为按语义使用
- `Timeout`/`InvalidArgument` helper 与 `Other` 暂无构造点——保留为
  公共 API 的合法变体（下游匹配需要），不算漏洞

**门禁**: fmt 0、clippy -D rc=0、cargo test 237-0、panic 脚本 rc=0、
`cargo doc --no-deps` 0、矩阵 39/51+12SKIP 0 FAIL、UDP e2e ALL_PASS、resilience 4/4

### ✅ Q9 依赖审计（2026-09-23）

**逐个 grep 确认后的处置**:
- **移除 3 个未使用依赖**:
  - `hkdf` —— 全库 0 引用（`aead.rs` 的 HKDF-SHA1 是基于 hmac_sha1 手写的，
    doc 注释明说 "no extra crate feature is needed"）
  - `tokio-test` —— 0 引用
  - `sha2` —— 0 引用（SSR 协议族只用 MD5/SHA1/HMAC；grep 'Sha2|sha2' 全库空）
- **保留（确认在用）**: aes/cipher/rc4/chacha20legacy/salsa20/blowfish/des/
  cfb-mode/ctr/aes-gcm/chacha20poly1305/md-5/sha1/hmac/digest/bytes/
  base64/crc32fast/rand/thiserror/log + dev: hex/proptest
- **tokio features 收窄**: `full` →
  `["net", "rt-multi-thread", "macros", "io-util", "time", "sync", "signal"]`
  —— 按实际用到的模块统计（time 10、net 8、spawn/rt 6、io 6、select/macros、
  sync 2、signal 2、join 2；#[tokio::main]/#[tokio::test] 需要 macros+rt）
- **rust-version = "1.82"**: 实测所用最新 std API 为
  `std::iter::repeat_n`（1.82 稳定，auth_aes128 PKCS7 pad + 2 测试）；
  其余下位 API（let-else 1.65、is_some_and 未用）均低于此；本机 rustc 1.97.0
- **cargo update**: 0 个包变更（"8 unchanged dependencies behind latest"
  为 semver 兼容范围内的保守锁定，不盲目升大版本），跑全测 237/0
- **cargo audit**（本机新装 cargo-audit，advisory-db 直连拉取成功）:
  ```
  Loaded 1264 security advisories
  Scanning Cargo.lock for vulnerabilities (96 crate dependencies)
  rc=0  → 0 vulnerabilities
  ```
  （proxychains4 路径对 git-over-https 反而失败，直连成功，记录备查）

**回归全绿**: build/test 237-0、clippy -D rc=0、fmt 0、panic 脚本 rc=0、
cargo doc 0、矩阵 39/51+12SKIP 0 FAIL、UDP e2e ALL_PASS、resilience 4/4、
release 1,184,520 字节（移除依赖后 −44 字节）

### ✅ Q10 Cargo.toml 发布元数据（2026-09-23）

- `[package]` 补齐 6 项:
  - `description`: byte-compatible SSR client library …
  - `license = "GPL-3.0-or-later"` —— **依据上游**: ssr-n/LICENSE 为 GPLv3，
    且源码头 "either version 3 … or (at your option) any later version"
    （shadowsocks-libev 血统）→ or-later；移植库必须同许可证
  - `repository = "https://cnb.cool/liangzhaoyuan12/ssr-client-rs"`（git remote 实测）
  - `readme = "README.md"`、`keywords = [shadowsocksr, ssr, proxy, socks5,
    cryptography]`、`categories = [network-programming, cryptography]`
- **LICENSE 文件**: 直接复制 `ssr-n/LICENSE`（GPLv3 全文 675 行）到仓库根，
  与 license 字段一致 —— 同时满足 M3 的 "LICENSE 与 Cargo.toml 一致"
- **CHANGELOG.md** 新建: Keep a Changelog 格式 + **0.x semver 兼容性承诺**
  （0.x 允许 breaking、1.0 起严格 semver；字节级协议兼容算 feature 走 patch）
  + 0.1.0 首发条目（功能范围、已知限制 cast5/idea/rc2/seed 未实现与
  AEAD hk 待复核、4 个协议的 server 侧 SKIP 说明）—— 同时满足 M3 内容要求
- **最强验证 `cargo package --allow-dirty` rc=0**: 元数据完整、LICENSE 被打包、
  打包产物独立重编译通过（`--list` 4173 行含 LICENSE/CHANGELOG/README）
- **门禁**: build 0/0、clippy -D rc=0、fmt 0、panic 脚本 rc=0、cargo doc 0、
  cargo test 237/0（元数据阶段无代码变更，Q9 的矩阵 39/51 0 FAIL 结果仍有效）

### ✅ R1 基线测量（2026-09-23，Phase R 开工，先测后改）

**脚本**: `tools/resource_probe.sh --idle [-c cfg] [-w warmup] [-m measure]`
（T6 期间所建，R1 复用；单发模式供 soak 循环调用）

**Phase R 正式基线**（Q10 后的 release 构建，hk.json，nproc=4）:

| 指标 | 实测 | 目标 | 结果 |
|---|---|---|---|
| 空闲 RSS | **3488 KB**（3.4MB） | ≤ 20480 KB | **PASS**（占预算 17%） |
| 线程数 | **5** | ≤ nproc+4 = 8 | **PASS** |
| 空闲 CPU | **0.00%** | ≤ 0.5%（=0） | **PASS** |
| fd 总数 | **11** | 基线（供 R2/R6 对比） | 记录 |

- 命令输出: `idle_rss_kb=3488 (<=20480) PASS / threads=5 (<=8) PASS /
  idle_cpu_pct=0.00 PASS / fd=11`，`probe_rc=0`
- 与 T6 期基线（3616KB）同量级，Q6 LTO+strip 后略降 128KB
- **R3 目标随之锚定**: 600s 负载增长 ≤10MB（T6 已实测 +784KB，见上）
- 该基线为 R2 fd 泄漏、R6 回收完整性的对比基准（fd=11、RSS=3488KB）

### ✅ R2 fd 泄漏测试（2026-09-23）

**新脚本 `tools/fd_leak_test.sh`**（R2 门禁，可重复跑，失败留日志）:
- TCP: 本地 HTTP 源（64KB blob）× **500 次** connect→transfer→close 过
  SOCKS5 代理，断言结束后 client fd **== 基线 11**
- UDP: 单 app socket 向 relay 发 **100 个不同目标端口**的数据报
  （SessionKey=(源地址,目标字节) → 恰好 100 个会话），断言:
  1. 峰值 fd = 基线+100（会话创建 100% 可见）
  2. 等 `udp_timeout`+6s 后 fd **回落 == 11**（udp_relay 淘汰逻辑清空会话表）
- Env 旋钮: TCP_CYCLES / UDP_SESSIONS / UDP_TIMEOUT（冒烟用小值）

**正式跑（默认 500/100/4s）结果，连续 3 次全过**:
```
baseline_fd=11
tcp_cycles=500 failures=0
after_tcp_fd=11 (== baseline 11) PASS
sent=100
peak_fd=111 (baseline 11, delta +100)      ← 每会话恰 1 fd
after_udp_fd=11 (== baseline 11) PASS      ← 淘汰后精确回基线
FD_LEAK_PASS tcp=500 udp=100 baseline=11   rc=0
```
- 冒烟（20/10/3s）2 次亦全过
- 与 T6 soak 断言（600s fd 11→11）、T5 resilience 互补，共同覆盖
  GOALS "纳入 T5/T6 断言"要求
- 跑法: `bash tools/fd_leak_test.sh`（依赖 /opt/ssr/ssr-server、curl）

### ✅ R5 二进制体积（2026-09-23）

| 阶段 | 字节数 | 说明 |
|---|---|---|
| 基线（Q6 profile 前） | **1,819,664** | 默认 release（无 LTO/strip） |
| Q6 profile 后 | **1,184,520** | thin LTO + CGU=1 + strip=symbols |
| **缩减** | **−635,144 = −34.9%** | 目标 ≥30% ✅，绝对值 1.13MB < 5MB ✅ |

- `size target/release/ssr_client`（GOALS 要求记录 text/data/bss）:
  ```
  text     data     bss       dec       hex     filename
  1095829  29416    392       1125637   112d05  target/release/ssr_client
  ```
  文件 1,184,520 字节（含 ELF 头/对齐），text+data+bss=1,125,637
- ELF: LoongArch64 PIE, dynamically linked（`file` 确认）

### ✅ R6 资源回收完整性（2026-09-23）

**完成标准三项**: T5 全绿（resilience 4/4）✅ + T6 全绿（soak
SOAK_PASS，fd 11→11）✅ + R1 达标（RSS 3488KB/线程5/CPU 0%）✅

**stop() 干净退出实测**（release + hk.json）:
```
before_sigint: pid=… threads=5 fd=11
kill -INT → exited=yes exit_code=0
after: leftover_proc=no listeners_1080=0   → R6_STOP_CLEAN
```
- 进程 **exit 0**（非信号杀死）→ `ctrl_c` handler 调 `client_ref.stop()`
  → Notify 广播 → accept 循环退出 → 主函数自然返回
- 端口 1080 监听释放、无残留进程/线程（进程整体退出）
- 连接中断/超时路径的释放由 T5 用例覆盖（kill -9 恢复、idle 回收、
  半关闭 FIN 传播，4/4 绿）
- 附带验证 Q8 修复生效: ctrl-c 等待失败会打印而非静默（此处无失败）

### ✅ R4 热路径分配审计（2026-09-23）

**grep 分诊**（`to_vec()` 75 处 + `.clone()` 9 处 in src/{crypto,relay,protocol}）:

| 类别 | 位置 | 判定 |
|---|---|---|
| 每连接一次（非热） | `local/mod.rs:197-198` local_buf/remote_buf（8KB，循环外一次）、`relay/mod.rs:57,75` 上下行 buf | ✅ 已复用，无 per-packet 大 Vec |
| 每包 1 次（结构性） | `stream.rs`/`cipher_env.rs` 的 `plaintext.to_vec()`（encrypt/decrypt 返回 `Vec<u8>`） | 保留：与 C `ss_encrypt_all/ss_decrypt_all` 的 calloc 语义一致；消除需改 API 为 `encrypt_into(&mut Vec)` —— P3 数据驱动决策 |
| 每连接冷路径 | `user_key.clone()`/`server_info.clone()`（init 一次）、`data_size_list` 构造（一次）、`iv_cache.insert(iv.to_vec())`（每 IV 一次） | ✅ 不在热路径 |
| 每包小分配 | `auth_aes128` md5/sha1/hmac 的 `.to_vec()`（16-20B） | 记录为 P3 候选（C 侧同样 malloc） |

**分配次数对比数据（计数插桩，GOALS 验收项）** — 新增 `tests/alloc_count.rs`
（`#[global_allocator]` 计数器包 System，单 test fn 防并发污染）:
```
R4 alloc baseline (64KB, aes-256-cfb, 200 iters):
  one-shot encrypt+decrypt: 4 allocs/roundtrip (196640 B avg)
  stateful encrypt+decrypt: 2 allocs/roundtrip
```
- 4 ≈ 输入拷贝 + 密文输出 + IV前缀 + 解密输出（每次 64KB 级别分配）
- 断言上限 ≤16 作为回归护栏（P3 优化后必须下降且 e2e 字节不变）
- **BytesMut 评估**: `utils/buffer.rs` 的 `SsrBuffer`（BytesMut 封装）
  全库 **0 引用**（仅定义文件自见）——预分配方案实际未接入；
  现行热路径已用固定 8KB 缓冲复用，R3 达标证明无 per-packet 大分配问题，
  接入 BytesMut 留给 P3 按数据决定（避免无数据的盲改）

**R3 验收数据**: 见 R3 记录（10 分钟 64KB 传输 soak SOAK_PASS）

### ✅ R3 负载内存增长（2026-09-23，带序列重跑版）

**方法**: `tools/soak_test.sh`（本 R4 前为其加了每 30s 打印采样行），
600s 持续 64KB 分块传输（TCP curl 2s/次 + UDP e2e 30s/次），warmup 60s。

**序列**（release + hk.json，基线取 warmup 结束点 t=60s）:
```
baseline t+60s: 3888KB fd=11
t+90..t+601s (30s 粒度, 19 点): 4064 → 4496 KB，fd 恒定 11（瞬时 13 为连接建立瞬间），线程恒 5
tcp: 298 ok / 0 fail    udp: 20 ok / 0 fail    panics: 0    → SOAK_PASS
```

**增长与斜率（GOALS 验收: 总增长 ≤10MB、warmup 后斜率 ≈0）**:
| 指标 | 值 | 判定 |
|---|---|---|
| 总增长 | **608 KB**（3888→4496） | ≤10MB ✅（仅 5.9% 用量） |
| 全序列线性拟合 | 56.3 KB/min | —（被前段爬升主导） |
| 前半段 t+60~361 | ~80 KB/min | 分配器 arena/缓存预热 |
| **末段 t≥361** | **≈12 KB/min** | 下降趋势明显 |
| **末 90s（t+511~601）** | **16KB/90s ≈ 10.7 KB/min，且 6 点中 4 点持平** | **饱和平台** ✅ |

- 形状判定: **饱和型曲线而非线性泄漏** —— 斜率逐段递减
  （80 → 12 → 平台），末段 RSS 在 4464~4496 间 4 次持平；
  若为泄漏应呈恒定正斜率且不回落持平
- fd 全程恒定 11（R2 结论一致），0 panic，298+20 流量 0 失败
- 首轮（无序列）对照: 4176→4592 = +416KB，同量级，两轮互证
- 链接: 分配基线见 R4（64KB 往返 4/2 allocs），R2 fd 结论互证

### ✅ P1 criterion 基准建立（2026-09-23）

**交付**: dev-dep `criterion = "0.5"`（ustc 镜像本地缓存，loong64 无阻）+
三个 `[[bench]] harness=false` 目标 + **BENCH.md**（76 项、含日期/机器/
频率/方法/噪声带，回归对照自此有基线）:

| bench | 项数 | 口径 |
|---|---|---|
| `benches/cipher_throughput.rs` | 42（21 方法×2） | 1MiB/次；encrypt=持久 ctx 流式，decrypt=每块新建 ctx（含 IV/salt 拆分） |
| `benches/protocol_overhead.rs` | 22（14 pre + 8 post） | 1440B/包；pre 热身一次连接头；post 用 iter_batched 把组帧留在计时外 |
| `benches/obfs_overhead.rs` | 12（6×2） | 1440B/包；稳态=HTTP 头已发/已剥、TLS 0x04+0x08（合成服务端 HMAC 响应驱动） |

**关键数字**（Loongson-3A5000@2.3GHz，±10% 噪声带）:
- cipher: salsa20 399 / chacha20-ietf 348 / aes-128-ctr 117 / aes-256-cfb
  **22** / des-cfb 21 MiB/s（enc）——CFB 走 RustCrypto 软实现，P2 对标 C
  的重点观察项；none 15.8 GiB/s（memcpy 基线）
- protocol pre: origin 148ns … auth_chain ~12.5µs；post: origin 415ns …
  auth_sha1 ~8.7µs
- obfs: encode 193~481ns；decode 239ns~2.1µs（1440B 拷贝占大头）

**过程中确认的两个协议事实**（记入 BENCH.md 脚注 + 此处）:
1. **`impl Protocol` 缺 `AuthAES128::init_user_key` override**——trait 默认
   空实现，经 `Box<dyn Protocol>` 调用是 no-op；producer 靠 pack 内部
   inherent 调用补救，**纯收包实例会 user_key 为空 → HMAC 全错**。生产
   relay 同实例先发后收所以未暴露；bench 构造已改为具体类型先 inherent
   init。→ **M4 API 冻结复核项**（考虑给 trait impl 补 override）
2. **auth_chain 无 client 自环**：pre 走 client 哈希链、post 走 server
   哈希链，只有真 server（ssr-n `server_pre_encrypt`）能产 post 认的帧
   （探针实证同实例首帧即 Err）；full_coverage 的 chain 测试也只测 pre。
   → chain post 标 n/a，真实方向由 e2e 矩阵覆盖（39/51 全 PASS）

**另发现 CHANGELOG 已知限制漏报**：camellia-128/192/256-cfb 同样未实现
（bench skip + matrix CIPHER_SKIP 8 项一致）——M3 时补正。
门禁: fmt 0、clippy -D rc=0、cargo test 全绿、panic 脚本 rc=0、0 warning

### ✅ P2 对标 C 客户端（2026-09-23）

**新脚本 `tools/bench_vs_c.sh`**（同机同配置回环 64MiB×3 取中位；wall 用
curl time_total，CPU 用 /proc/PID/stat utime+stime 差；结果自动追加
BENCH.md §4）。

配置: aes-256-cfb / auth_aes128_sha1 / tls1.2_ticket_auth（hk.json 同款
实际组合）+ 本地 ssr-server（d70342262c45）+ 随机 64MiB HTTP 源。

| client | throughput | median wall | CPU |
|---|---|---|---|
| C (/opt/ssr/ssr-client, 988974dcdfa5) | 14.6 MiB/s | 4.385 s | 99.9% |
| **Rust** (release, ecd9b44095fa) | **15.1 MiB/s** | **4.249 s** | **79.8%** |

**判定（GOALS P2 双目标）**:
- 吞吐 rust/C = **103.4%** ≥ 90% ✅（反超 C 3.4%）
- CPU rust/C = **0.80×** ≤ 1.5× ✅（比 C 省 20% CPU——C 打满一核，
  Rust 未满；单流即饱和链路上 C CPU≈wall，Rust 更省）
- 三轮方差极小（C 4.38/4.40/4.39、Rust 4.22/4.26/4.25）→ 中位可信

注: P1 的 cipher 微基准（aes-256-cfb 22 MiB/s 软实现）与端到端 15.1
MiB/s 不矛盾——端到端受协议层+obfs+拷贝链路综合限制，微基准的 CFB
数字留作 P3 若真优化 cipher 的对照点。

### ✅ P3 热路径优化（2026-09-23）

**附带修复（阻塞 P3 时发现的生产缺陷）**:
- `tls_ticket.rs` 握手验证 `header_length - 10` **usize 下溢 panic**——服务端
  首字节非 0x14/0x16 时必崩（Q4 宏 grep 盲区：裸算术不匹配）。C 同一下溢
  `tls1.2_ticket.c:446`（size_t 下溢喂超大 length）。修复：`header_length < 10`
  → 落到既有校验失败出口 `Ok((Vec::new(), false))`（C 意图行为的内存安全实现）。
  同类裸减法专项审计 29 处全查：其余均有前置长度检查（≥76、out_size 构造保证等）。
- **BENCH.md 基线污染发现**：初跑 obfs decode 数字被并行 clippy 抢核干扰
  （同 filter 单跑 175ns vs 并发 1.96µs，11×）。三 bench 已空载重跑，
  §1-§3 全部替换为干净值并在文首标注。

**实施（按 GOALS 优先级 = 协议层每包分配）**:
1. `AuthChainAContext`/`AuthAES128` 增 `hmac_key_buf` 复用缓冲
   （user_key||pack_id/recv_id 每包 key 拼接不再分配；长度可变故不能栈化，
   server_info.key 可达 32B）——chain pre+post、aes128 pack_data+post 共 6 处。
2. chain `pack_client_data`: rnd 中转 `collect::<Vec>` → 直填 `out`
   （省 1 alloc）；`encrypt_buffer` 中转 to_vec → copy 进 out 后 RC4 in-place
   （keystream 序列等价，省 1 alloc；`encrypt_buffer` 因唯一调用点移除而删除）。
3. post 侧 key clone 同样走复用缓冲。

**前后对比**（criterion，噪声带 ±10%；只记有意义项）:

| bench | before | after | Δ |
|---|---:|---:|---:|
| pre/auth_aes128_md5 | 6.362 µs | 6.005 µs | **−5.6%** |
| pre/auth_aes128_sha1 | 5.028 µs | 4.712 µs | **−6.3%** |
| post/auth_aes128_md5 | 6.091 µs | 5.813 µs | −4.6% |
| post/auth_aes128_sha1 | 4.735 µs | 4.442 µs | **−6.2%** |
| pre/auth_chain_a | 12.820 µs | 12.076 µs | **−5.8%** |
| pre/auth_chain_c | 12.804 µs | 12.067 µs | **−5.8%** |
| pre/auth_chain_b/d/e/f | ~12.4 µs | ~11.9 µs | −3.6~−3.8% |
| origin/verify/sha1/simple | — | — | ±10% 噪声内（路径未动） |

分配计数（alloc_count）: **auth_chain pre 5→2、auth_aes128 pre 6→4 /包**。

**经数据判定不做（<5%）**:
- **cipher 每包分配**（优先级1）: stateful 往返仅 2 allocs，1440B 包的
  to_vec ≈70ns vs aes-256-cfb 加密 63µs/包 = **0.11%**，改 encrypt_into
  API 的收益不足 5% → 不做。
- **obfs 拼包拷贝**（优先级3）: encode 单 alloc（195ns/包）在每包总预算
  （cipher 63µs + protocol 5-12µs）中占 **≈0.3%**，改 Obfs trait 返回借用
  的端到端收益 <5% → 不做（P2 端到端已 103% 优于 C）。

**门禁**: cargo test **238/0**、clippy -D rc=0、fmt check 0、panic script 0、
matrix **39/51+12SKIP 0 FAIL**、e2e_udp ALL_PASS、resilience **4/4**。

### ✅ P4 并发扩展性（2026-09-23）

**新脚本 `tools/concurrency_test.sh`**（1/8/64/100 档、分层 CPU 采样
client/server/origin、fd/RSS 跟踪；METHOD 环境变量支持对照实验）。

**曲线**（进 BENCH.md §5）: 1流15.1 → 8流149.1(9.9×) → 64流146.7(**9.7×**)
→ 100流144.4(9.6×)。**GOALS 64流≥8× 达标（实测 9.7×）**。

**判定链**:
- 单流 15.1 是**流控限制**非算力限制（8流即放大 9.9×）；聚合在 8 流达峰
  = 全机 4 核算力墙（client+server+curl+源），4 核即可承载 8× ——GOALS 的
  12 核前提在本机已满足（预算核算：aes 软实现 22MiB/s/核，解密 149MiB/s
  ≈0.68 核 + 系统/协议开销 ≈0.15 核 = 实测 0.83 核 ✓ 自洽）。
- **无锁竞争热点**（GOALS "才优化" 的反面判定）: client CPU 全档 83-85%
  恒定（per-MiB 成本不变）、吞吐随档位**不跌落**、fd 结束回基线 10、
  RSS 100 流峰值 8.8MiB —— 无任何 Mutex 争用特征 → **不做锁优化**。
- 对照: `method=none` 双端连不通（server 拒绝）→ 手写 cfg 的 method
  键确实被两端读取（排除"没加密所以快"的解释）。
- 过程发现①: CPU% 首版公式漏除 wall（440% 假值）——已修为 /wall。
- 过程发现②: origin CPU 列采到 http.server 包装 PID（读数 0），已在
  BENCH.md 注明为已知缺陷（该列不参与判定）。
- 过程发现③（重要）: **曾疑 P1 cipher micro 与宏观矛盾**（client 实测
  0.83核@149MiB/s vs micro 22MiB/s）——分账后自洽: aes 解密 149/22≈0.68核
  占实测 0.83 核的 82%，其余为 syscall/协议/tls；micro 独占复测
  47.9ms/MiB 稳定复现 22.2 MiB/s，**两套数据都真**，无需修 bench。

**门禁**: 无代码改动（仅工具脚本+文档），238 测试/clippy/fmt/panic
script/matrix 39/51 0 FAIL 基线未动；进程已清理。
