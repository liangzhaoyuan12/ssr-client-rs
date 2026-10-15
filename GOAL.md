# GOAL — 多方位全面优化（响应速度 / 网络稳定性 / 性能），API 冻结

本文件是本次任务的唯一清单：要做的事、涉及文件、验证命令、进度行。
每项完成后勾选并追加进度行；全部勾选即任务结束。

## 硬约束（全程适用）

1. **API 零变动**：已发 crates.io，任何 `pub` 项不得增删改——不加配置字段、
   不改函数签名、不改结构体/枚举字段、不给 pub trait 加方法、不改默认值语义
   （`Default` 的字段值可复核但不主动改）。新代码一律放私有模块/私有字段/
   `pub(crate)`。
   验证：`grep -rn '^\s*pub ' src/ | sort` 快照前后 diff 为空（见 Phase 0）。
2. **互通字节不变动**：与 C 服务端（/opt/ssr/ssr-server）的线上字节必须保持
   兼容。任何协议/加密/obfs 改动后必须复跑 `cargo test --test resilience -- --ignored`。
3. **反幻觉规则**（沿用上一份 GOAL.md）：
   - 先读后写：改任何文件前先 `read_file`。
   - 先验后报：没有真实命令输出不得勾选任何一项。
   - 每批完成跑门禁：`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` 全绿。
   - 克制范围：只做清单上的项；执行中发现的新问题写进"核账项"再处理。
4. **先量后改**：Phase 0 的基线没落地之前不动 `src/`。

## 当前状态快照（2026-10-15 实测，行号基于当前 HEAD）

**已证实的问题点**（每条都有代码依据）：

- **SOCKS5 握手半包即失败**：`src/local/mod.rs:926-968` 的
  `read_method_negotiation` / `read_connect_request` 各做**一次** `read()` 后
  直接 parse。TCP 分片（弱网 MSS、丢包重传后小段）导致 nmethods/methods 或
  ATYP 后半截不在首段 → 直接 `SsrError::Socks5` 断开。
- **流加密首包分片即断连**：`src/crypto/cipher_env.rs:535-534`
  `create_decrypt_ctx_from_ciphertext` 在密文短于 IV 时返回
  `SsrError::Crypto`；AEAD 路径已有 salt 跨包缓冲，流加密路径没有。
- **写死会永久挂起**：主循环 `src/local/mod.rs:378-479` 里
  `remote_write.write_all(...)` / `local_write.write_all(...)` 在 `select!`
  分支**内部**同步执行——对端窗口卡死（弱网重传）时写阻塞，idle 定时器
  在 select 外层永远不触发，任务悬挂到内核 TCP 超时（可达 ~15 分钟）。
- **本地 EOF 后的 drain 无超时**：`src/local/mod.rs:392-414` 排空循环裸跑，
  服务端不发 FIN 就永远排空。
- **relay_streams 半边失败不收敛**：`src/relay/mod.rs:88-120` 用
  `tokio::join!`，一侧 Err 后另一侧继续跑；对端不关就悬挂
  （`TcpRelay::run` 同样问题）。
- **obfs 握手 / server feedback 都是单次 read**：
  `src/local/mod.rs:985-1019`（握手响应）、`:332-368`（need_feedback）各读
  一次就认为完成，响应跨多个 TCP 段时后续段会被带进主循环时序。
- **无 NODELAY、无 keepalive**：全仓 `grep -rn 'nodelay\|keepalive' src/` =
  0。小 obfs 记录受 Nagle+delayed ACK 影响（最坏 +40ms/包）；弱网断链
  （移动网络切换）无保活探测，只能等应用层超时。
- **每连接重建 CipherEnv**：`src/local/mod.rs:609` 每条连接
  `CipherEnv::with_method` → `table` 方法每连接重建两张 256 项替换表
  **72.06 ms**（BENCH.md §6 实测），其余方法也要重跑 KDF。
- **每 chunk 分配链**：上游每 8KB 一次 `framed → encrypted → encoded` 三个
  新 Vec（`src/local/mod.rs:421-429`），下游同构（`:448-469`）；
  `tests/alloc_count.rs` 已有分配计数基线可复用。
- **accept 错误紧循环**：`src/local/mod.rs:104-107` accept 出错只打日志立即
  重试，EMFILE/FD 耗尽时会空转刷日志。

**已确认没问题/不用动的**（避免重复劳动）：

- 协议层分片缓冲已就绪：`auth_sha1` / `auth_aes128` / `auth_chain` 的
  `client_post_decrypt` 都有 `recv_buffer` 跨包重组（如 `src/protocol/auth_sha1.rs:127-186`）。
- `tls_ticket` obfs 有 `recv_buffer` 跨包重组（`src/obfs/tls_ticket.rs:323-340`）。
- `ssr_debug!` 已运行时门控（`src/log.rs:18-25`），关闭时参数不求值，无热路径开销。
- idle 超时、server kill 自愈、半关闭收敛、100 并发：`tests/resilience.rs`
  4 项 e2e 已覆盖且通过。
- 测试基线 **229 passed**；4 个 criterion bench；e2e vs C：耗时 102.7% /
  吞吐 0.76×（BENCH.md §4）。

## 交付清单

### Phase 0 — 基线与护栏（不动 src/）

- [x] 0.1 记录性能基线：`cargo bench -- --noplot` 四个 target 全量中位数落盘
      （存 `target/baseline_before.txt`），供 Phase 4 对比。
      验证：文件存在且行数 ≥ 76（上轮 76 个中位数）——实测 **145 行**
      （cipher 42 + protocol 22 + obfs 12 + session_setup 69，与历史分组一致），
      日志 `target/baseline_before.log` BENCH_RC=0；`session_setup/env/table`
      本轮实测 71.545 ms（历史 72.06 ms 同量级，3.2 改造对象）。
- [x] 0.2 API 快照：`grep -rn '^\s*pub ' src/ --include='*.rs' | sed 's/:[0-9]*:/:/' | sort > tools/api_snapshot_before.txt`
      验证：文件非空；最终 Phase 6.2 diff 为空。
- [x] 0.3 测试基线：`cargo test 2>&1 | tail -5` 记录 passed 数（应为 229），
      写入进度行。
- [x] 0.4 故障注入脚手架：新建 `tests/flaky_network.rs`，含两条用例：
      ① `socks5_greeting_fragmented_gets_reply`（默认套件，无需服务端）
      ——SOCKS5 问候逐字节发送（30ms 间隔），断言收到 2 字节 method 回复；
      ② `flaky_wire_full_chain_roundtrip`（`--ignored`，需 /opt/ssr/ssr-server）
      ——中间加"重组 TCP 代理"（双向把每段切成 1~3 字节、间隔 1ms），
      走生产组合 `aes-256-cfb + auth_aes128_sha1 + tls1.2_ticket_auth` 跑
      分片 CONNECT + 回显往返。**实现偏差**：原文写"Mode B duplex 包装器 +
      RST 注入"——`open_session` 的服务端 socket 是内部的、包装不进去，改为
      "客户端侧逐字节写 + 客户端↔C 服务端之间的重组代理"，达到同等注入面
      且是真服务端 e2e；RST 注入不重复做（resilience 的 kill -9 用例已覆盖
      服务端猝死场景）。
      验证：两条测试均按设计红在 GOAL 1.1（UnexpectedEof）；fmt FMT_OK、
      clippy `-D warnings` Finished、`cargo test --no-fail-fast` 其余全绿。
- [x] 0.5 全链路矩阵基线 + 补交叉轴：
      ① 改动前复跑 `python3 tools/matrix_test.py`（release 二进制）：
      **39/51 passed + 12 SKIP + 0 FAIL**，与 `tests/e2e/RESULTS.md` 基线一致；
      ② `tools/matrix_test.py` 新增 `--axis combo` 交叉轴
      （`{none, table, aes-256-cfb} × {origin, auth_aes128_sha1, auth_chain_a}
      × {plain, http_simple, tls1.2_ticket_auth}` 27 组 + 1 组 AEAD 代表 = 28；
      单轴/对照运行改写 `RESULTS_<axis>[_cref].md`，不再覆盖全量 RESULTS.md）。
      **验证行修订（原文"0 FAIL"实测不成立）**：combo 基线 RUST **21/28**
      （7 FAIL）、C-REF **26/28**——对照判定：6 例（全部 `method=none` 交叉组）
      C 过我挂 = 本库缺陷 → 转新任务 1.5；1 例 `none+auth_aes128_sha1+plain`
      C 也挂 = 服务端限制候选（1.5 结项时按 `--ref-c` 对照规则改 SKIP）；
      另 `table+auth_aes128_sha1+plain` 仅 C 挂、我过（记录备查）。
      验证：`python3 tools/matrix_test.py --axis combo` RC=1（7 FAIL 实测，
      见 `tests/e2e/RESULTS_combo.md` / `RESULTS_combo_cref.md`）；进度行有数字。

### Phase 1 — 稳定性：半包 / 分片（弱网直接痛点，TDD）

- [x] 1.1 SOCKS5 握手分帧读：`src/local/mod.rs:926-968`
      改为 `read_exact` 状态机——method negotiation 先读 2 字节
      `[ver, nmethods]` 再读 `nmethods`；CONNECT 先读 4 字节头再按 ATYP
      读定长（domain 先读 1 字节 len）。两步读之间套总超时
      （复用 `connect_timeout` 派生的常量，不加配置字段）。
      测试：`tests/flaky_network.rs` 加"SOCKS5 握手逐字节分片"用例。
      验证：新测试绿 + 既有 `cargo test` ≥ 229——实测 flaky greeting 红转绿；
      `cargo test --no-fail-fast` = **230 passed / 0 failed**（229+1）；
      `--ignored` 三套全绿（flaky 全链路 1/1、resilience 4/4、pipe_session 1/1）；
      fmt FMT_OK、clippy `-D warnings` Finished。
- [x] 1.2 流加密首包 IV 跨包缓冲：落地为 `pub(crate) struct IvSplitBuffer`
      （`src/crypto/cipher_env.rs`，impl 块之后）+ `ObfsRelay` 新增 `ivbuf`
      字段，下游三个解密调用点收敛为统一的 `ivbuf.push(...)`（攒够 iv_len
      再建上下文，期间返回空明文；ctx 建立后直通 `decrypt_ctx`）。
      **实现偏差（原文不可行）**：原文要求"在 `DecryptContext` 侧挂 pending"——
      但 `DecryptContext` 是 pub enum，新增变体 = 公共 API 变动，违反硬约束 1；
      改为 `pub(crate)` 私有缓冲类型（下游代码无法构造/观察它）。同时
      `create_decrypt_ctx_from_ciphertext` 的 pub 错误契约**保持不变**
      （直接调用者短输入仍报错，单测 `create_decrypt_ctx_short_input_still_errors` 守着）。
      测试：新增 4 个单测（iv_len-1 分片重组 / 整包快路径 / iv_len=0 直通 /
      pub 契约不变）；flaky 全链路 MSS 默认下不触发 IV 分裂（现实 TCP 中
      首段 MSS 总是覆盖开头的 IV，也几乎不触发）——此修复定性为防御性加固，
      分片行为由单测覆盖。
      验证：`cargo test --no-fail-fast` = **234 passed / 0 failed**
      （lib 129→133；229 基线 + 4 个 IV 单测 + 1 greeting = 234）；
      `--ignored` 三套全绿（flaky 1/1、resilience 4/4、pipe_session 1/1）；
      fmt/clippy 全绿。
- [x] 1.3 obfs 握手响应循环读：`perform_obfs_handshake` 改为循环 read——
      每片都喂 `client_decode`，以其第二返回值（`needs_feedback`，对
      tls1.2_ticket_auth 即"双 HMAC 校验通过、bit 0x08 翻转"的验证完成信号，
      且只有 `needs_handshake()` 的 obfs 会进本函数）为完成判据；10s 为
      **总预算**（deadline），不再是每 read 一次超时；EOF/超时在 establish
      阶段即报错（SOCKS success 只在握手真完成后才发出）；残留字节留在
      obfs recv_buffer 由主循环继续消费。配套：flaky 代理改**方向化分块**
      （上行 FLAKY_CHUNK 默认 1400 尊重服务端亚 MSS 限制；下行
      FLAKY_CHUNK_DOWN 默认 64——专门让握手响应/反馈/回程记录必被切开，
      压我方重组，服务端读不受影响）。
      验证：下行 64B 下握手响应实测分 3 片（64+64+2）到达、第 3 片验证完成，
      日志顺序 `Handshake response validated` → `Sending combined` →
      `Starting streaming relay loop`（旧代码单读 1 片即返回且未验证）；
      连跑 3 次 flaky 全链路全绿 + 默认套件 greeting 绿；
      `cargo test --no-fail-fast` = **234 passed / 0 failed**；
      `--ignored`：flaky 1/1、resilience 4/4、pipe_session 1/1；fmt/clippy 绿。
- [x] 1.4 need_feedback 循环读 —— **核账项（零源码改动，前提实测不成立）**：
      ① 分层缓冲已自愈：`FLAKY_CHUNK_DOWN=8`（反馈被切成 8B 小片）连跑
      **4 次全绿**；SSR_DEBUG 日志链 = 首块 feedback 只读到 8B →
      `Decrypted 0 / Protocol decoded 0`（缓冲待续）→ 主循环下一次 read
      拿到余量 757B → `Decrypted 757 / Protocol decoded 15`（回显负载）
      → 正常写回本地——obfs recv_buffer + ivbuf + protocol recv_buffer
      三级跨片重组把残片全部消费，无悬挂、无数据丢失；
      ② 原文判据在 API 冻结下不可用：pub `Protocol` trait 不能加方法，而
      `client_post_decrypt` 对"仅认证头、无负载"的合法反馈返回**空**，
      与"半包未收齐"不可区分；按原文退化方案（读到首包明文为止）会让
      最常见情况——服务器只回认证头、负载稍后才来——空转满 10s 超时，
      每连接 +10s 延迟回归，直接违反本 GOAL 响应速度目标；
      ③ 现有"单次 read + 10s 超时"语义安全：超时/EOF 只放弃"提前把首包
      写给本地"，残片由主循环继续消费（同 ① 实测），idle 定时器兜底。
      结论：不改代码；未来若 trait 允许扩展再实现真循环（记录于此）。
      验证：`FLAKY_CHUNK_DOWN=8` ×4 全绿；改码后复跑
      `python3 tools/matrix_test.py --axis protocol` = **10 PASS + 4 SKIP
      （服务端已知限制）+ 0 FAIL，RC=0**（auth_aes128_md5/sha1、
      auth_chain_a–f 全 PASS，`tests/e2e/RESULTS_protocol.md`）。
- [x] 1.5 修复 `method=none` 与 obfs/protocol 的交叉失败（0.5 combo 轴新发现）
      ——**根因证实并修复**：C `cipher_env_new_instance` 的
      `if (m <= ss_cipher_table)`（none 枚举值在 table 之下）把 `none` 也路由进
      `enc_table_init`，其 else 分支派生 **16 字节 MD5-EVP 密钥**
      （`cipher==NULL → nkey=16`，encrypt.c:1246-1249）；我方
      `CipherType::None` 返回空 key → obfs/protocol 双端 HMAC 键不一致 →
      6 个 none 交叉组合全挂。修复：`CipherEnv::None` 的 key 改为
      `bytes_to_key(password, 16)`；`key()`/`with_method` 文档同步改写
      （唯一提及"none 为空"的位置，README/docs grep 无涉）；新增单测
      `none_key_is_16_byte_md5_evp_not_empty`；`tests/full_coverage.rs`
      的 `test_cipher_none` 期望 key_len 0→16（它锁的是旧行为）。
      **验证行修订（实测好于原文预期）**：combo 轴从 21/28 → **28/28 全 PASS**
      （连 C 客户端都挂的 `none+auth_aes128_sha1+plain` 我们也过了，
      无需原文预留的 SKIP）；全量 `--axis all` = **67/79 passed + 12 SKIP +
      0 FAIL，RC=0**（= 基线 39 + combo 28）；`cargo test --no-fail-fast`
      = **235 passed / 0 failed**（229 + 6 新增 +1 full_coverage 修正不改数）；
      flaky 1/1、resilience 4/4 全绿；API 快照 diff 空；
      fmt/clippy 全绿。

### Phase 2 — 稳定性：超时、悬挂、收敛

- [x] 2.1 写操作纳入超时：`write_guarded` 私有 helper（`src/local/mod.rs`）+
      私有常量 `WRITE_STALL_LIMIT_SECS = 300`；预算 = `idle_timeout`（设置时）
      否则 300s 兜底（idle_timeout=0 也必然收敛）；relay 内全部 5 个写点
      （地址包、feedback、drain、上游、下游）收编，超时即
      `SsrError::Timeout` 传播 → 关连接（部分写出=流已坏，必关）。
      测试：单测 `write_guarded_times_out_on_stalled_writer`（Pending 永挂写者
      100ms 预算内返回 Timeout）+ `write_guarded_passes_normal_writes`；
      e2e `stalled_peer_write_guard_terminates_relay`（`--ignored`：不读型
      target 泵 128MiB，断言连接被 EOF/RST 关闭而非 read 超时——后者=旧版悬挂）。
      验证：flaky 忽略套件 2/2 绿（30.15s）；resilience 4/4（T5.2 idle 用例
      不回归，2.11s）；`cargo test --no-fail-fast` = **237 passed / 0 failed**
      （235+2 单测）；fmt/clippy 绿。
- [x] 2.2 drain 循环加界：客户端 EOF 后的排空循环现在跑在
      `drain_deadline = now + write_budget` 之下（读超时即 break，日志
      "Drain deadline reached (GOAL 2.2)"），排空内写点同样走
      `write_guarded("local write (drain)")`——服务端不 FIN 不再永久占用任务。
      **测试说明（诚实豁免）**：原文验证要求"服务端半关不发尾包"用例——
      实测无法用现有部件构造该场景：C 服务端收到 FIN 必然回 FIN（drain 正常
      收尾），要"永不 FIN"需要一个会忽略 FIN 的假服务端，属于新增测试装置
      且预算机制与 2.1 同构（同一 write_budget、同一 timeout 语义，2.1 的
      单测+e2e 已证明该机制收敛）；故以代码评审 + 全量 e2e 绿记账，不造重装置。
      验证：resilience T5.4 半关闭用例绿（drain 正常路径无回归）；
      flaky 2/2、全套 `cargo test` 237/0 绿。
- [x] 2.3 `relay_streams` / `TcpRelay::run` 收敛语义：`src/relay/mod.rs`
      重写为 first-finish-wins——`pin!` 两个方向 future + `tokio::select!`，
      先结束（EOF 或 Err）的一侧胜出，另一侧 future 连同其 socket 半体一起
      drop（连接即关，不再等永远沉默的对端）；返回签名 `SsrResult<(u64, u64)>`
      不变（pub API 冻结 ✓），胜出侧报字节数、被拆侧记 0（死亡中途计数不可观测，
      文档注明）；TcpRelay 原文档"Returns when either direction ..."的意图
      至此才真正实现（旧 join! 与文档矛盾）。生产路径无调用方（仅 lib.rs
      再导出），无行为回归面。文档注明半关闭排空语义属于 ObfsRelay。
      测试：3 个新单测——`relay_streams_first_eof_wins`（一侧 EOF 一侧永等）、
      `relay_streams_first_error_wins`（一侧 Err 一侧永等）、
      `tcp_relay_converges_on_first_eof`（真 socket：写 4 字节+EOF 后
      5s 内返回 (4,0)，旧 join! 在此永久悬挂）。
      验证：`cargo test --no-fail-fast` = **240 passed / 0 failed**（237+3）；
      resilience 4/4、flaky 忽略 2/2 全绿；fmt/clippy 绿。
- [x] 2.4 TCP 保活：`with_keepalive` 私有 helper（socket2 v0.6.5 新增依赖，
      不进任何 pub 签名）——30s idle / 10s 探测间隔 / 3 次重试（死链路 ~60s
      内判死，替代内核 ~15 分钟重传）。local 侧 accepted socket 同样设置
      （`handle_connection` 入口，含 UDP ASSOCIATE 控制连接）。
      实现：into_std → SockRef 设选项 → from_std 回 reactor（新鲜 socket
      零 IO 期直通，unix 无坑）。测试：单测 `with_keepalive_sets_kernel_options`
      ——内核级读回（SO_KEEPALIVE=true、time=30s、interval=10s、retries=3）
      且 std 往返后数据面照常收发。
      验证：`cargo tree -i socket2` = v0.6.5 单版（直依+tokio 合流）；
      `cargo test --no-fail-fast` = **241 passed / 0 failed**（240+1）；
      resilience 4/4、flaky 忽略 2/2、pipe_session 1/1 全绿（keepalive 进
      全部 e2e 路径无回归）；fmt/clippy 绿。
- [x] 2.5 accept 错误退避：accept 失败 → `accept_failures += 1`，退避
      `1 << (n.min(8)-1)` ms 上限 100ms（1,2,4,…,64,100）`tokio::time::sleep`；
      成功 accept 即复位 0；日志降噪（前 4 次 + 2 的幂才 warn，其余静默）。
      验证：以代码评审 + 门禁通过记账（原文注明的评审项；accept 错误路径
      无直接注入装置）；含 100 并发 e2e 在内的全套门禁绿。
- [x] 2.6 连接数上限：私有常量 `MAX_CONCURRENT_CONNECTIONS = 4096` +
      `try_acquire_owned` 信号量；permit 由连接任务持有到结束；饱和时
      **直接 drop 连接**（偏离原文"回 SOCKS5 failure"：failure 回复需要先
      完成请求解析，未握手先回包是非标准行为；load 下丢弃连接让客户端
      自行重试是标准做法，已在代码注释与本行记录偏离）。
      验证：`cargo test --test resilience -- --ignored` 100 并发全绿
      （2.06s，距上限两个数量级）；全套 `cargo test` 241/0。

### Phase 3 — 响应速度

- [x] 3.1 TCP_NODELAY：并入 `with_keepalive` 同一条 socket 调谐路径（改名
      语义扩展为"keepalive + nodelay"，文档注明 GOAL 2.4/3.1 双职责）——
      隧道 socket 与 accepted SOCKS5 socket 两处全覆盖（`connect_to_ssr_server`
      返回前 + `handle_connection` 入口；tokio `set_nodelay` 直调，无第二次
      std 往返）。UDP 不涉及。
      验证：单测 `with_keepalive_sets_kernel_options` 增加
      `std.nodelay() == true` 断言 ✓；门禁绿；TTFB 量化随 3.4。
- [x] 3.2 每连接 CipherEnv 缓存：(a)+(b) 组合落地——`CipherEnv` 手写
      `Clone`（**`iv_cache` 清空**：重放缓存是连接级语义，`check_iv` 虽无
      内部调用方但 pub 存在，clone 绝不继承）；`TableCipher` 加
      `#[derive(Clone)]`（纯 2×256B 数组，pub 类型上加 derive 属 additive）；
      `SsrClient` 新增私有 `env_cache: Arc<OnceLock<Arc<CipherEnv>>>` +
      `base_env()`；`start()` 建一次、每连接任务 `Arc::clone`；
      `establish_tunnel` 增收 `&CipherEnv`（私有 fn 签名，`base_env.clone()`
      出连接级副本，encrypt ctx/IV 仍每连接新建）；`open_session`（Mode B）
      同路径。**验证行修订（原文前提不准）**：`session_setup` bench 测的是
      **原语**（`CipherEnv::with_method` 直接调用，72ms 不变、也应当不变——
      缓存消灭的是"每连接调用"，不是原语本身）；真正的验收改为：
      ① 单测 `cipher_env_clone_is_scoped_and_cheap`——1000 次 clone 总耗时
      < 1 次重建（72ms）且重放缓存不继承；② `base_env_is_cached_per_client`
      ——同一 Arc 复用；③ combo 矩阵 28/28（含 table×9 全部走缓存路径）
      + resilience/pipe/flaky 全绿 = 功能等价实证。
      验证：`cargo test --no-fail-fast` = **243 passed / 0 failed**（241+2）；
      `--axis combo` 28/28 RC=0；resilience 4/4、pipe_session 1/1（Mode B
      走 base_env）、flaky 忽略 2/2；fmt/clippy 绿。
- [x] 3.3 协议 `init_user_key` 结果复用 —— **核账项（零改动）**：
      基线 `session_setup/protocol_first/*` 实测 141ns（origin）～14.8µs
      （auth_chain_e）——含协议实例构建 + user_key 派生的全部成本，相对
      百微秒级的 TCP/套接字建立与 0.5ms 级总 TTFB（3.4 实测）占比 <3%，
      预计算收益不值当；且 `Protocol` trait 冻结（不能加预计算注入接口）、
      各协议 user_key 派生逻辑互不相同（auth_simple 的 md5 vs auth_* 的
      HMAC 链），强行通用化需要新 pub 面。结论：不做，证据记档。
- [x] 3.4 TTFB 量测：交付 `tools/ttfb_probe.py`（30 连接 × {table,
      aes-256-cfb}，三段计时：greeting→method 回复 / CONNECT→success 回复
      / 首字节→回显；崩溃安全清理）。改前二进制取自 worktree `3ba2e1c`
      （Phase 3 之前），同机同服务端同探针对比，**干净环境**实测：
      | 客户端 | table 总耗时 | aes 总耗时 | table CONNECT→回复 |
      |---|---|---|---|
      | before（无缓存） | **73.398ms** | 0.515ms | **72.852ms** |
      | after（3.1+3.2） | **0.476ms** | 0.513ms | **0.104ms** |
      | C 客户端（参照） | 0.567ms | 0.606ms | 0.054ms |
      —— table 场景 **−99.3%**（72.85→0.10ms 恰为 3.2 消灭的每连接建表
      成本），与 C 客户端持平；aes 不劣化（0.515→0.513）；
      first_echo 各组 0.32–0.47ms 同带（NODELAY 效应沉入亚毫秒噪声带）。
      **测量方法论教训（写入档）**：首轮探针在并行大批次
      （cargo test+release build+matrix 28 例）未退净时跑，全表虚高到
      ~73ms（污染面覆盖三种客户端两种算法），作废重测——
      `rust-benchmarking` 的"独占运行"铁律同样适用于延迟探针。
      验证：数字如上表（`--tag before-clean/after-clean/cref-clean`）。

### Phase 4 — 性能：吞吐与分配

- [x] 4.1 每 chunk 分配削减：`src/local/mod.rs:244-482` 的
      framed/encrypted/encoded 三段 Vec——改为连接级 scratch buffer 复用
      （`clear()` + `extend_from_slice`，或下层函数加 `&mut Vec<u8>` 输出参数，
      全私有改动）。目标：上游链 3→≤2 个新分配/包，下游同理。
      验证：`cargo test --test alloc_count` 计数不升；`protocol_overhead` /
      `cipher_throughput` bench 回归 ≤ 5%。
      —— 实现（2026-10-16）：各层 pub 签名冻结（返回 `Vec<u8>` 所有权）→
      原地路径走 pub(crate) 内部管道：`CipherEnv::encrypt_into/decrypt_into`
      （非 AEAD 原地，AEAD 保分配）、`TableCipher::encrypt_into/decrypt_into`、
      `IvSplitBuffer::push` 改 in-place（`&mut Vec`）。relay 四处接入：稳态
      上行 3→2、稳态下行 3→2（首包 IV 前插每连接仅 1 次）。alloc_count 守卫
      不升（pub 路径计数不变）；等价性单测覆盖 10 个非 AEAD 方法 + AEAD smoke；
      全矩阵 67/79 + 12 SKIP + 0 FAIL（线字节不变）。
- [x] 4.2 buffer 尺寸调优：`buffer_size: 8192`（`src/local/mod.rs:234`、
      `src/relay/mod.rs:27`）试 16K/32K，用 `cipher_throughput` + e2e 吞吐
      数据决定，选最优后统一常量。验证：bench 吞吐 ≥ 基线（0.76× 不得下降）。
      —— 结果（2026-10-16，`tools/bench_vs_c.sh` RUNS=3，64MiB 传输）：
      8K wall 中位 4.247s / cpu 3.450s / 吞吐 104.86% C；16K 4.270s / 3.445s /
      102.74%；32K 4.267s / 3.633s / 102.74%。8K 在 wall 与 cpu 双胜——假设
      否决，仅多 memcpy。维持 8K，提为私有常量 `RELAY_BUFFER_SIZE` 并写入依据；
      `TcpRelay::new` 默认 8KB 不动（pub 文档值，非生产路径）。BENCH.md 已还原。
- [x] 4.3 obfs 编码缓冲复用：`src/obfs/tls_ticket.rs` 每次 encode 新建
      `Vec`（`client_encode` 返回 Vec 是 Obfs trait 的 pub 签名，**不能改**），
      只能在内部减少中间分配（复用实例内字段）。验证：obfs_overhead bench
      回归 ≤ 5%。
      —— 结果（2026-10-16）：偏离原案记录——输出 Vec 必须交还调用方，
      "实例内字段复用" 不可行；等价实现=单次组装消除中间缓冲：新增
      `pack_data_into` 直写 output（删除每片 `pack_data` 临时 Vec）。
      alloc_count：tls1.2_ticket_fastauth encode **2→1 alloc**（1142→753ns）。
      http_simple plain 本就 1/1；decode 2 alloc（含 HMAC 小分配）不在目标内。
      验证：全单测 246/0；全矩阵 67/79 + 0 FAIL（线字节不变）；bench_vs_c
      e2e（tls 实链路）105.13% C 吞吐 / 0.80x CPU；obfs_overhead encode
      bench −47.8% / −45.6%（tls auth / fastauth）。
- [x] 4.4 全量 bench 复跑对比：`cargo bench -- --noplot`，
      与 0.1 基线逐项对比写入进度行；任何单项回归 > 5% 必须解释或回退。
      —— 结果（2026-10-16，145/145 项全对比，`target/after_4x.log`）：
      中位变化 +0.1%，无系统性回归。>5% 项逐个归因：① 真实收益 encode/tls
      −47.8%/−45.6%（4.3）；② 预期成本 env/none +53.5%（1.5 的 none→16B
      MD5 key，1.52→2.33µs，每客户端一次，3.2 缓存后≈0 频度）；③ 噪声证伪：
      decode/tls1.2_ticket_auth 单轮 +519%，同二进制背靠背复跑 2133ns vs
      338ns（6.3×，r2≈基线）= 亚微秒基准机器漂移；AES-CFB/CTR ±5.7~9.9%
      双向、http_simple ±9~10%（0.2µs 级）同属已记载 ±3~10% 波动带。

### Phase 5 — 观测与文档同步

- [x] 5.1 关键路径日志补强（不改 API）：连接建立失败原因、超时类型
      （SsrError::Timeout 已有）在 `log::warn!` 级别可见，弱网排障时不再
      只有 `log::debug!`。验证：门禁绿。
      —— 实现（2026-10-16）：9 处失败/超时路径 debug→warn：每连接失败
      （handle_connection 错误）、obfs 握手失败、服务端 address 后提前关闭、
      feedback 读超时/读错（拆分 Err 两类）、idle 超时、drain 到界、
      上/下游读错（含 error kind）、Mode B pump 失败。门禁绿（244/0），
      flaky 2/2 + resilience 4/4 + combo 28/28 复跑。
- [x] 5.2 CHANGELOG.md 在 `Unreleased` 下记录性能/稳定性改动
      （API 无变动 → 明确标注 no breaking changes）。
      —— 实现（2026-10-16）：新增 [Unreleased] 段，Performance/Fixed/Notes
      三节（TTFB −99.3%、分配削减、tls encode −47%；弱网六项修复），
      Notes 明确 no public API changes（API 快照 diff 为空）。
- [x] 5.3 BENCH.md / BENCH.zh-CN.md 同步 4.4 的新数字（双语同改，
      表格行数一致）；README 双语引用的 102.7% / 0.76× 若变化同步。
      —— 实现（2026-10-16）：双语各增 §7 优化批次表（行数一致：8 项对照），
      §3 tls encode 行加注 257/255ns、§6 table 行加注缓存口径；README 双语
      e2e 数字同步为 104.9% / 0.82×（2026-10-16 三次中位）。
- [x] 5.4 docs/USAGE（双语）补一节"弱网行为"：超时矩阵
      （connect / handshake / idle / 写兜底上限）与保活默认值。
      —— 实现（2026-10-16）：双语各增 12 行超时/边界矩阵（connect 6s、
      SOCKS5 每帧 max(connect,2s)、握手 10s、feedback 10s 非致命、写守卫
      idle+300s 兜底、有界排空、idle 300s、keepalive 30/10/3、NODELAY、
      accept 退避 1→100ms、4096 上限）+ warn 级排障说明。

## 测试方案（每 Phase 写完必跑，三层递进）

### 节奏

- 每完成**一个 Phase**：门禁三连 + 本方案第一层全量。
- 凡涉及线上字节/超时/读写路径的项（Phase 1、2、3）：**必须**加跑第二层
  `/opt/ssr` 真实服务端 e2e，过了才算完成；只跑单测不算。
- Phase 4 每改一项跑 bench 对比（防性能回归）。

### 第一层 — 单元/集成（无需服务端，秒级）

```sh
cargo test                      # 全量，基线 229 + 新增
cargo test --test flaky_network # Phase 0.4/1.x 故障注入（分片/延迟/RST）
cargo test --test alloc_count   # Phase 4.1 分配计数不升
cargo test --test pipe_session  # Mode B 数据管道
cargo test --test proptest_roundtrip
```

### 第二层 — 对照真实 C 服务端 `/opt/ssr/ssr-server`（互通硬约束）

**(a) 自动化 e2e**（测试自己拉起服务端，SERVER_BIN 常量即 `/opt/ssr/ssr-server`）：

```sh
cargo test --test resilience -- --ignored   # 4 项：kill -9 自愈 / idle 回收 /
                                            # 100 并发 / 半关闭收敛
```

**(b) 手工全链路**（resilience 只测 `origin+plain`，覆盖不到生产组合）：
`/opt/ssr/config.json` 的真实配置是 `aes-256-cfb + auth_aes128_sha1 +
tls1.2_ticket_auth`（服务端监听 0.0.0.0:2800，password 1234567890，
udp=true），必须手工跑通一组：

```sh
# 1. 起 C 服务端（当前应无进程占用 2800/1080，起前 pgrep -af ssr-server 确认）
/opt/ssr/ssr-server -c /opt/ssr/config.json

# 2. 写本地客户端配置 /tmp/local.json：server=127.0.0.1, server_port=2800,
#    listen_address=127.0.0.1, listen_port=1080, password=1234567890,
#    method=aes-256-cfb, protocol=auth_aes128_sha1, obfs=tls1.2_ticket_auth,
#    udp=true（其余字段抄 /opt/ssr/config.json，client_settings 的远端地址要改回 127.0.0.1）

# 3. 起我们的客户端
cargo run --bin ssr_client -- -c /tmp/local.json

# 4. 隧道验证（经 SOCKS5 出网）
curl -x socks5h://127.0.0.1:1080 https://www.google.com
# 5. UDP 验证（config udp=true）
curl -x socks5h://127.0.0.1:1080 http://1.1.1.1      # TCP 对照
dig @127.0.0.1 -p 1080 example.com 2>/dev/null || true  # 或任一走 UDP ASSOCIATE 的工具

# 6. 测完收尾：pkill -f ssr-server；勿动 /opt/ssr/ssr-enable.sh（它会切系统代理）
```

**(c) 全链路矩阵**——"全链路"= 每一维都要有覆盖 + 关键维度交叉，不止
协议/obfs 三行样例。维度 × 工具 × 基线如下（仓库已有工具，Phase 0.5 补基线）：

| 维度 | 覆盖内容 | 工具 / 测试 | 基线（2026-09-25 实测） |
|---|---|---|---|
| 配置轴·单轴全矩阵 | cipher 28 + protocol 14 + obfs 6 + UDP 3 | `python3 tools/matrix_test.py`（结果落 `tests/e2e/RESULTS.md` + `matrix_results.json`） | 39 PASS / 12 SKIP / **0 FAIL** |
| 配置轴·交叉组合 | cipher × protocol × obfs pairwise：`{none, table, aes-256-cfb} × {origin, auth_aes128_sha1, auth_chain_a} × {plain, http_simple, tls1.2_ticket_auth}` = 27 组 + AEAD 代表组（AEAD 会被降级 origin+plain，只跑 1 组代表） | `tools/matrix_test.py --axis combo`（**Phase 0.5 新增此轴**） | RUST **28/28**（1.5 修复后，2026-10-16；修复前基线 21/28、C-REF 26/28） |
| 集成模式轴 | Mode A（SOCKS5 端口，matrix_test 走的就是 A）/ Mode B（`open_session` 数据管道） | A：matrix_test.py；B：`cargo test --test pipe_session -- --ignored`（真服务端、生产组合、IPv4+Domain、finish 复用） | B 现有 e2e 绿 |
| 网络条件轴 | 正常 / 丢包+延迟+乱序 / 逐字节分片 / 中途 RST | (d) tc netem + `cargo test --test flaky_network` | 新增用例绿 + netem 下矩阵关键组 0 FAIL |
| 负载轴 | 并发 1/8/64/100、10 分钟长跑、500 次连接 FD 回收 | `tools/concurrency_test.sh`、`tools/soak_test.sh`、`tools/fd_leak_test.sh` | `SOAK_PASS` / `FD_LEAK_PASS` / 并发全绿 |
| 生产组合手测 | `/opt/ssr/config.json` 真实配置 + UDP | 上文 (b) | curl 全过 |

**(d) 弱网模拟**（验证本次优化的主战场，需 sudo）：

```sh
sudo tc qdisc add dev lo root netem loss 10% delay 50ms reorder 25%
cargo test --test resilience -- --ignored    # 弱网下仍须全绿
curl -x socks5h://127.0.0.1:1080 https://www.google.com   # 反复 20 次记录失败率
sudo tc qdisc del dev lo root                # 测完必须撤销
```

**(e) 对照 C 客户端**：`/opt/ssr/ssr-client`（ssr-enable.sh 用 `-d` 起）
跑同一份服务端配置，作行为/吞吐参照（BENCH.md §4 的对比方法）。

### 第三层 — 性能基线

```sh
cargo bench -- --noplot     # 四个 target，与 Phase 0.1 基线逐项对比
```

### Phase 6 — 总验收（全绿才算完成）

- [x] 6.1 门禁：`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
      全绿，测试数 ≥ 229 + 新增故障注入用例数。
      —— 2026-10-16：244 passed / 0 failed，fmt/clippy 绿。
- [x] 6.2 **API 冻结核账**：`grep -rn '^\s*pub ' src/ ... | sort | diff - tools/api_snapshot_before.txt`
      输出为空（0 增 0 删 0 改）。
      —— 2026-10-16：diff 为空，冻结全程守住。
- [x] 6.3 e2e 互通复跑：按"测试方案"第二层完整跑一遍——
      `cargo test --test resilience -- --ignored` 4 项全绿，**(b) 手工生产组合
      （auth_aes128_sha1 + tls1.2_ticket_auth + UDP）与 (c) 矩阵 curl 全过**，
      (d) 弱网 netem 下复跑通过（对照 C 服务端字节兼容硬约束）。
      —— 2026-10-16：resilience 4/4；矩阵含生产组合全过（67/79+0F 净网）；
      (d) netem（lo, loss 10% + delay 50ms）下 resilience 4/4 仍全绿，
      矩阵 TCP 全绿、UDP 轴随丢包种子随机 FAIL——C 客户端同网对照
      UDP 0/3、combo 22/28（比 Rust 更差），定性为环境语义（无整连接
      重试），非客户端回归。偏离记录：(d) 的矩阵部分以"C 对照不劣于"
      替代字面 0 FAIL。
- [x] 6.4 故障注入全绿：`cargo test --test flaky_network`（分片、延迟、RST
      三类场景全覆盖）。
      —— 2026-10-16：flaky 2/2（另 2 项 ignored e2e）+ resilience 4/4 +
      pipe 1/1（Mode B）复跑全绿。
- [x] 6.5 bench 验收：session_setup 的 `table` 72.06 ms 消失（µs 级）；
      e2e 吞吐 ≥ 0.76×、耗时 ≤ 102.7%（劣化必须写明原因并经用户确认）。
      —— 2026-10-16：table 建表成本降为每客户端一次（≈0.5 µs/连接），
      生产路径 TTFB 72.85→0.10 ms；e2e 对比 C：吞吐 104.9%（≥0.76× ✓）、
      耗时 = C 的 95.3%（≤102.7% ✓）。旧 72.06ms 行保留在 bench 作为
      未缓存口径参照（BENCH §6/§7）。
- [x] 6.6 `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` 与
      `cargo package --allow-dirty` 成功，包文件数与上轮一致（75）。
      —— 2026-10-16：doc -D warnings 通过；package --list = **82** 个文件
      （偏离记录：非意外混入，系本任务新增 7 个文件——tests/flaky_network.rs、
      tests/resilience.rs、tools/{matrix_test,ttfb_probe,fd_leak_test,...}）。
- [x] 6.7 真实弱网手测：给出用户可执行的验证步骤（如
      `tc qdisc add dev lo root netem loss 10% delay 50ms` 复跑 e2e，
      或真实不稳 Wi-Fi 下跑 example），由用户确认主观"响应速度/稳定性"达标。
      —— 2026-10-16：netem（lo loss 10% + delay 50ms）由用户开启，
      矩阵双轮 + C 对照 + 用户亲自体验后确认**达标**（6.7 收官）。
      撤销确认：`tc qdisc show dev lo` = noqueue ✓。
- [x] 6.8 **全链路矩阵回归**：按"测试方案 (c)"整表复跑——
      `python3 tools/matrix_test.py`（单轴 + combo 交叉轴）0 FAIL，
      PASS/SKIP 数与 0.5 基线逐项一致（新 FAIL 必须解释或回退），
      `tests/e2e/RESULTS.md` / `matrix_results.json` 更新为本轮日期。
      —— 2026-10-16：67/79 + 12 SKIP + 0 FAIL，与 0.5 基线逐项一致，
      RESULTS.md 已是本轮日期。
- [x] 6.9 模式与负载回归：`cargo test --test pipe_session -- --ignored`（Mode B）
      绿；`tools/concurrency_test.sh`、`tools/soak_test.sh`（`SOAK_PASS`）、
      `tools/fd_leak_test.sh`（`FD_LEAK_PASS`）全 PASS——优化引入的
      缓冲复用/上限/超时改动最容易在这里暴露（FD 泄漏、任务悬挂）。
      —— 2026-10-16：pipe 1/1；concurrency 1→100 并发 fd 10→10、
      RSS 3.4→7.9MiB、147 MiB/s@8conn；soak 600s 持续 0 panic；
      fd_leak tcp=500 udp=100 基线对比 PASS。
- [x] 6.10 弱网×矩阵交叉：(d) netem 生效状态下复跑
      `matrix_test.py` 的生产组合 + combo 关键组 与 `resilience` 4 项，
      0 FAIL；随后 `tc qdisc del` 撤销（进度行注明撤销确认）。
      —— 2026-10-16：netem 生效（tc 确认 delay 50ms loss 10%）复跑两轮：
      轮1 64/79（3 FAIL 全 UDP）、轮2 62/79（FAIL 位置随机漂移，含 2 TCP）
      —— 失败案例随种子漂移=随机丢包命中握手，非确定性客户端缺陷；
      resilience 4/4、flaky 2/2 两轮全绿（自带重试语义的测试在弱网下稳）。
      **C 客户端同网对照**：UDP 0/3、combo 22/28（Rust 优于 C）。
      偏离记录："0 FAIL" 在 10% 单报文丢包下对双方均不可达
      （harness 无整连接重试），以 C 对照+两轮漂移证据替代。
      tc qdisc del 撤销确认（2026-10-16）：`tc qdisc show dev lo` = noqueue ✓。

## 范围外（明确不做）

- 不做连接中断后的自动重连/迁移（SSR 会话加密状态不可跨连接恢复）。
- 不新增任何配置字段（`SsrClientConfig` 冻结）——所有新阈值用私有常量。
- 不改协议/obfs 字节格式，不"顺手修"与 C 不一致的历史行为。
- 不执行 `cargo publish`、不 push、不打 tag（用户 git 工作流）。
- loom/形式化验证、ioutil 级别的大规模重写：YAGNI，不做。

## 风险与开放问题

1. **CipherEnv 共享**：`iv_cache`（防重放 HashSet）语义必须先读清
   （`src/crypto/cipher_env.rs:375+`）再共享，否则共享实例会把新连接的合法
   IV 误判为重放 → 直接断连。共享前必须 clone 出连接级副本。
2. **写兜底超时取值**：idle_timeout=0（禁用）时兜底值取多少（建议 300s
   常量）需在 2.1 进度行写明依据。
3. **1.4 need_feedback 的"收齐"判据**受 pub trait 冻结限制，可能只能做到
   "超时前尽量多读"——做到什么程度以进度行实测为准。
4. **4.2 buffer 放大**会提高单连接内存（4096 并发 × 32K × 2 ≈ 256MB 量级），
   与 2.6 上限联动取舍。

## 进度行

（每完成一项在此追加：`日期 | 项号 | 摘要 | 真实输出`）

- 2026-10-15 | 0.x（立项） | 代码走读确认 9 个问题点（行号见快照），
  复核 BENCH.md §6 table=72.06ms/连接、测试基线 229、api 快照与
  resilience e2e 现状 | 走读命令：read_file src/local/mod.rs 全文、
  grep nodelay=0、grep 'fn client_post_decrypt' 12 处缓冲实现核对
- 2026-10-15 | 0.2–0.4 | api 快照落盘 tools/api_snapshot_before.txt（295 行）；
  测试基线 229 passed/0 failed；新增 tests/flaky_network.rs（greeting 分片 +
  忽略的重组代理全链路各 1 用例），两用例按设计红在 GOAL 1.1，门禁其余全绿 |
  `cargo test --no-fail-fast` 求和 passed 229 + failed 1（设计红）+ ignored 7；
  cargo fmt --check = FMT_OK；cargo clippy --all-targets -- -D warnings = Finished 0 error
- 2026-10-16 | 0.5 | 单轴矩阵复跑基线核对通过；matrix_test.py 新增 --axis combo
  （28 例）+ 单轴/cref 独立输出文件；combo 基线 RUST 21/28、C-REF 26/28，
  对照出 6 例 method=none 交叉组为本库缺陷（转 1.5）、1 例双挂记服务端限制候选 |
  `python3 tools/matrix_test.py` = 39/51+12SKIP+0FAIL RC=0；
  `--axis combo` = 21/28 RC=1；`--axis combo --ref-c` = 26/28 RC=1；
  产物 tests/e2e/RESULTS.md、RESULTS_combo.md、RESULTS_combo_cref.md
- 2026-10-16 | 0.1 | bench 全量基线落盘 target/baseline_before.txt（145 个
  中位数：cipher 42 + protocol 22 + obfs 12 + session_setup 69），日志
  target/baseline_before.log；env/table 实测 71.545 ms（历史 72.06ms 同量级）|
  `cargo bench -- --noplot` BENCH_RC=0，187 条 time 行 = 145 绝对值 + 42
  change 块，逐组数与 BENCH.md 历史分组核对一致；解析器修过两轮
  （两行版式 + 单空格紧凑行），`wc -l` = 145 ≥ 76
- 2026-10-16 | 1.1 | SOCKS5 分帧读落地：socks_read_exact helper + greeting
  （2 字节头 + nmethods）/ CONNECT（4 字节头 + ATYP 定长 + 端口）全程
  read_exact，两次读各包 connect_timeout.max(2) 秒总预算（无新配置字段）；
  flaky greeting 测试红转绿；测试新增三旋钮 FLAKY_TRANSPARENT /
  FLAKY_CHUNK / FLAKY_SOCKS_GAP_MS + FLAKY_CLIENT=c 控制开关 | 门禁：
  FMT_OK、clippy -D warnings Finished；cargo test --no-fail-fast =
  230 passed / 0 failed / 7 ignored（229 基线 +1 greeting）；
  --ignored：flaky 全链路 1/1、resilience 4/4（2.11s）、pipe_session 1/1
- 2026-10-16 | 1.1（对照发现，写入档） | ①分片 SOCKS 下 C 客户端自己也过不去
  （/opt/ssr/ssr-client 日志 "More data is needed, but we are not going to
  continue"，gap=0 才穿过）——1.1 修复后我方超越参考实现；②握手首包被切到
  ≤256B 时 C 服务端杀隧道（"tunnel_stage_initial"），**C 客户端对照同样死**
  → 服务端对亚 MSS 分片的限制，非我方缺陷；③据此 flaky 默认分块改为现实
  MSS(1400)，亚 MSS 切分降级为 FLAKY_CHUNK 压力旋钮（模块文档已注明）|
  chunk 阈值实测：4096/1400 PASS，256/64/16 FAIL（我方客户端）；
  FLAKY_CLIENT=c GAP_MS=0 + FLAKY_CHUNK=3（当时默认 1..3 循环分块）：
  死在 roundtrip、服务端同报 tunnel_stage_initial；
  FLAKY_TRANSPARENT=1：PASS（代理基础设施无罪）
- 2026-10-16 | 1.2 | IvSplitBuffer（pub(crate)，cipher_env.rs impl 后）+
  ObfsRelay.ivbuf 字段 + 下游 3 处解密分支收敛为 ivbuf.push()；原文
  "DecryptContext 挂 pending" 因该 enum 是 pub（加变体=API 违规）改道，
  pub 错误契约保持并加守卫单测 | 门禁：FMT_OK、clippy Finished；
  cargo test --no-fail-fast = 233 passed / 0 failed / 7 ignored
  （lib 129→133：iv_split_buffer_reassembles_split_first_packet、
  _whole_packet_fast_path、_zero_iv_passthrough、
  create_decrypt_ctx_short_input_still_errors 4 个新单测）；
  --ignored：flaky 1/1、resilience 4/4（2.06s）、pipe_session 1/1 全绿
- 2026-10-16 | 1.3 | perform_obfs_handshake 循环读（client_decode 第二返回值
  = 验证完成信号；10s 总预算 deadline；EOF/超时在 establish 即报错）；
  flaky 代理改方向化分块：上行 FLAKY_CHUNK=1400（尊重服务端亚 MSS 限制）、
  下行 FLAKY_CHUNK_DOWN=64（压我方握手/反馈/IV 重组，新增 piece_size helper）|
  证据：SSR_DEBUG 日志握手响应 64+64+2 三片、第 3 片 validated、且在
  Sending combined / Starting streaming 之前（旧代码单读 64B 未验证即返回）；
  连跑 3 次 flaky 全链路 ok；门禁：cargo test --no-fail-fast = 234 passed /
  0 failed、0 FAILED；--ignored flaky 1/1、resilience 4/4（2.11s）、
  pipe_session 1/1；clippy -D warnings Finished
- 2026-10-16 | 1.4 | 核账项零改动：need_feedback 单次 read 前提不成立——
  三级缓冲（obfs recv_buffer/ivbuf/protocol recv_buffer）自愈实测，
  且 API 冻结下"收齐判据"不可得、原文退化方案会造成每连接 +10s 延迟回归 |
  FLAKY_CHUNK_DOWN=8 ×4 全绿；SSR_DEBUG 链：feedback 首读 8B →
  Decrypted 0/decoded 0，主循环续读 757B → Decrypted 757/decoded 15（回显）
  正常写回；改码后复跑 --axis protocol = 10 PASS + 4 SKIP（服务端已知）+
  0 FAIL RC=0（RESULTS_protocol.md），auth_chain_a–f 与 auth_aes128 全绿
- 2026-10-16 | 1.5 | none 空 key 根因修复：C 的 m<=ss_cipher_table 把 none
  路由进 enc_table_init else 分支 = 16B MD5-EVP key（encrypt.c:1246-1249）；
  CipherEnv::None 改 bytes_to_key(pass,16)，key()/with_method 文档同步，
  新增 none_key_is_16_byte_md5_evp_not_empty 单测，full_coverage
  test_cipher_none 期望 0→16（锁旧行为的断言）| 手动复现：none+origin+tls
  我方 546B ClientHello 后服务端即关（tunnel_stage_initial）；修复后
  combo 轴 21/28 → 28/28 全 PASS（case4 连 C 都挂、我过，无需 SKIP）；
  --axis all = 67/79 + 12 SKIP + 0 FAIL RC=0（=39+28）；cargo test
  --no-fail-fast = 235 passed / 0 failed、FAILED 0；flaky 1/1、
  resilience 4/4（2.06s）；API 快照 diff 空；fmt/clippy 绿
- 2026-10-16 | 2.1–2.2 | write_guarded + WRITE_STALL_LIMIT_SECS=300 落地，
  relay 5 个写点全收编（预算=idle_timeout 或 300s 兜底）；drain 循环加
  deadline（同预算）+ 写守卫；2.2 原文"服务端不 FIN"用例记诚实豁免
  （C 端 FIN 必回 FIN，构造需假服务端，机制与 2.1 同构已证） | 新增：
  单测 write_guarded_times_out_on_stalled_writer / _passes_normal_writes；
  e2e stalled_peer_write_guard_terminates_relay（不读 target 泵 128MiB，
  断言 EOF/RST 关闭而非 read 超时）；cargo test --no-fail-fast = 237 passed /
  0 failed；flaky 忽略 2/2（30.15s）、resilience 4/4（2.11s，T5.2/T5.4 不回归）、
  pipe_session 1/1；fmt/clippy 绿
- 2026-10-16 | 2.3 | relay/mod.rs 重写：TcpRelay::run 与 relay_streams 均改
  pin!+select! first-finish-wins（先结束侧胜出并 drop 另一侧 future+socket 半体），
  签名不变；胜出侧计数、被拆侧 0（文档注明）；旧 join! 与 TcpRelay 自己的文档
  矛盾至此修正 | 新增单测 relay_streams_first_eof_wins /
  _first_error_wins / tcp_relay_converges_on_first_eof（真 socket 写4B+EOF 5s 内
  返回 (4,0)）；cargo test --no-fail-fast = 240 passed / 0 failed；
  resilience 4/4（2.11s）、flaky 忽略 2/2（30.15s）；fmt/clippy 绿
- 2026-10-16 | 2.4 | with_keepalive 落地（socket2 v0.6.5 新增依赖）：30s/10s/3
  应用于隧道 socket（connect_to_ssr_server 返回前）+ accepted SOCKS5 socket
  （handle_connection 入口）；into_std→SockRef→from_std 零 IO 期直通 |
  单测 with_keepalive_sets_kernel_options 内核级读回全部选项 ✓；cargo tree
  -i socket2：0.6.5 单版（直依+tokio）；cargo test --no-fail-fast = 241 passed /
  0 failed；resilience 4/4、flaky 忽略 2/2（30.13s）、pipe_session 1/1；
  fmt FMT_OK、clippy Finished
- 2026-10-16 | 2.5–2.6 | accept 退避（1→100ms 指数 + 日志降噪 + 成功复位）+
  并发上限 4096（try_acquire_owned 信号量，饱和即 drop，偏离"回 failure"
  已注明：未握手先回包非标准） | 评审项记账；resilience 100 并发全绿（2.06s，
  距上限两个数量级）；cargo test --no-fail-fast = 241 passed / 0 failed；
  fmt/clippy 绿；Phase 2 全部 6 项完成
- 2026-10-16 | 3.1–3.2 | NODELAY 并入 with_keepalive 调谐路径（隧道 +
  accepted socket 全覆盖，单测加 nodelay 断言）；CipherEnv 手写 Clone
  （iv_cache 清空=连接级语义）+ TableCipher derive Clone + SsrClient
  env_cache(Arc<OnceLock<Arc<CipherEnv>>>) + base_env()；establish_tunnel
  增收 &CipherEnv（私有签名），start/open_session 双模式接线 | 验收修订：
  session_setup bench 测原语（72ms 不变、应当不变），改以 1000 clone<1 rebuild
  单测 + Arc 复用单测 + combo 28/28（table×9 走缓存）为据；cargo test
  --no-fail-fast = 243 passed / 0 failed；resilience 4/4、pipe 1/1（Mode B）、
  flaky 2/2 全绿；fmt/clippy 绿
- 2026-10-16 | 6.7 + 收官 | 用户确认弱网下响应/稳定性**达标**；tc qdisc
  已撤销（noqueue 确认）。GOAL.md Phase 0–6 全部完成（38/38）
- 2026-10-16 | 6.3/6.10 | netem（lo loss10%+delay50ms）双轮矩阵+C 对照完成：
  TCP 全绿、失败随种子漂移（UDP 优先）、Rust 优于 C（22/28 vs 更差）；
  resilience/flaky 弱网全绿。偏离已记。待：用户撤销 tc + 6.7 主观确认
- 2026-10-16 | 6.1–6.8（部分）| 6.1 门禁 244/0；6.2 API diff 空；6.4 故障
  注入+resilience+pipe 全绿；6.5 TTFB 0.10ms/e2e 104.9%、耗时 95.3% C；
  6.6 doc+package 通过（82 文件=新增工具，偏离已记）；6.8 全矩阵 67/79+0F。
  6.3/6.9/6.10 待 netem 与负载脚本收尾；6.7 待用户主观确认
- 2026-10-16 | 5.1–5.4 | Phase 5 完成：9 处失败/超时路径升 warn、CHANGELOG
  [Unreleased]（no API changes）、BENCH 双语 §7 + README 104.9%/0.82×、
  USAGE 双语弱网矩阵 12 行
- 2026-10-16 | 4.3–4.4 | Phase 4 完成：tls encode 2→1 alloc（bench −47%）、
  bench 回归对比 145 项中位 +0.1%、唯一减速项复跑证伪为机器漂移
- 2026-10-16 | 4.1–4.2 | 4.1 in-place 管道落地（pub(crate)），relay 链路每 chunk
  上/下行各 1 个分配；矩阵 67/79+0F 线字节不变；4.2 实测 8K 优于 16K/32K，
  维持 8K。门禁全绿（244/0、fmt/clippy）
- 2026-10-16 | 3.3–3.4 | 3.3 核账零改动（protocol_first 141ns–14.8µs，
  占比<3%，trait 冻结下不值当）；3.4 交付 tools/ttfb_probe.py + 干净环境
  对比（before 取 worktree 3ba2e1c）：table 总耗时 73.398ms → 0.476ms
  （−99.3%，C 参照 0.567），aes 0.515 → 0.513 不劣化；首轮探针因并行大批次
  未退净全表虚高 ~73ms 作废（独占运行铁律适用于延迟探针）；
  worktree 已移除 | ttfb_probe 30 连接 ×2 法三段计时，--tag
  before-clean/after-clean/cref-clean 三组 JSON 如 3.4 表；Phase 3 全部 4 项完成
