# SSR-CLIENT-RS 持久目标文档

> 本文档是 agent 的 7x24 持续工作指南。每次会话开始时，agent 应首先读取此文件，确认当前阶段和上次进度，然后从上次中断处继续工作。

---

## 项目概述

用 Rust 从零实现 SSR (ShadowsocksR) 客户端库，目标是完全兼容 ssr-n C 服务端，可作为其他项目（GTK4、Tauri 等）的依赖使用。**当前目标：达到可 push 进主线的发布质量。**

- **仓库**: `/home/liangzhaoyuan12/work/rs/ssr-client-rs`
- **服务端**: `/opt/ssr/ssr-server` (LoongArch64 ELF, 配置在 `/opt/ssr/config.json`)
- **参考实现**: `ssr-n/` 目录（C 源码）
- **迁移文档**: `MIGRATION.md`
- **进度记录**: `PROGRESS.md`

---

## 反幻觉与反重复机制

**这是本文档最重要的部分。AI 模型长时间工作时容易产生幻觉和重复行为，必须严格执行以下规则：**

### 开始工作前（每次会话必须）

1. **读取 PROGRESS.md** — 确认上次完成到哪一步，从那里继续，不重做已完成的工作
2. **读取 GOALS.md 本文件** — 确认当前阶段编号和任务列表
3. **运行 `cargo test`** — 确认当前测试数与通过状态，用数字而非记忆
4. **运行 `git log --oneline -5`** — 确认最近提交，不重复已提交的修复

### 工作中（每完成一个小任务必须）

1. **写 PROGRESS.md** — 每修一个 bug、每完成一个测试，立即更新进度文件，记录：日期时间、做了什么、涉及的文件和行号、测试结果
2. **不重复修复** — 如果 PROGRESS.md 记录某项已修复，不要再修它
3. **不凭记忆修改代码** — 修改任何文件前，必须先 `read_file` 读取当前内容，不凭记忆写代码
4. **不凭记忆声称通过** — 每次声称"测试通过"前，必须实际运行 `cargo test` 并看到输出
5. **不重复 commit** — 修改前先 `git log --oneline -3` 检查是否已提交

### 防止幻觉的硬性约束

- **不要修改已通过的测试** — 除非发现它们本身有 bug
- **不要凭空添加新模块** — 除非在本文档的任务列表中明确列出
- **不要声称"已修复"而没跑测试** — 必须有实际 `cargo test` 输出
- **不要重复同一个修复尝试** — 如果同一个修复尝试 3 次仍失败，在 PROGRESS.md 记录阻塞原因，跳到下一个任务
- **不要在一次会话中做太多事** — 一次会话专注 2-3 个明确任务，做完就更新进度
- **不要改代码不跑门禁** — 每次改动后至少跑 `cargo build 2>&1 | grep -c error`；触及协议层再跑 `cargo test`

---

## 当前状态快照（最终：截至 2026-09-23，M5 验收全绿）

**Phase T/Q/R/P/M 全部完成（12/12 门禁绿）**。基线对照（下表为改进前测量值）:

| 门禁项 | 改进前（2026-09-22 基线） | 最终值（2026-09-23） |
|---|---|---|
| 测试 | 186 / 0 failed | **238 / 0 failed** |
| cargo build warning | 35 | **0** |
| clippy -D warnings | 未建立 | **exit 0** |
| fmt --check | 未执行 | **exit 0** |
| 生产路径 unwrap/expect/panic | 138（raw） | **0**（check_panic_paths.sh，白名单 0） |
| unsafe | 5 | **0** |
| [profile.release] | 未配置 | opt3 + thin LTO + CGU=1 + strip |
| 空闲 RSS / 线程 / fd | 未测量 | **3472KB / 5 / 11**，CPU 0.00% |
| 二进制体积 | 1,819,664B | **1,184,520B（−34.9%，<5MB）** |
| 性能 | 无基准 | criterion 76 项 + **vs C: 103.4% 吞吐 / 0.83× CPU** |
| 并发 | 未测量 | **64 流 146.7 MiB/s = 9.7× 单流（≥8×）**，无锁热点 |
| CI | 无 | .github/workflows/ci.yml 四门禁（+e2e dispatch/self-hosted） |

**基线表（历史记录）**:

### 基线数字（改进前的测量值，作为各 Phase 的对照组）

| 项目 | 当前值 | 目标值 | 所属 Phase |
|------|--------|--------|-----------|
| 测试总数 | 186 passed / 0 failed | 见 T 阶段增量 | T |
| 源码规模 | 9745 行 (src+tests) | — | — |
| `cargo build` warning | **35 个** | **0** | Q1 |
| `cargo clippy` | 未建立基线 | `-D warnings` 全绿 | Q2 |
| `cargo fmt --check` | 未执行 | 全绿 | Q3 |
| unwrap/expect/panic (src, grep) | **138 处**（需分拣生产路径/测试代码） | 生产路径 0，例外须书面豁免 | Q4 |
| `unsafe` | **5 处** | 0 或逐条 SAFETY 论证 | Q5 |
| `[profile.release]` | **未配置** | 配置齐（LTO/strip/opt-level） | Q6 |
| 空闲 RSS / 线程数 / fd 数 | 未测量 | 见 R1 目标 | R |
| 二进制体积 | 未测量 | 见 R5 目标 | R |
| 基准吞吐 | 无 benchmark | criterion 基线 + 对标 C | P |
| e2e 测试资产 | **散落在 /tmp（会被清掉）** | 全部入库 `tests/e2e/` 或 `tools/` | T3 |
| CI | 无 | GitHub Actions 四门禁 | M1 |

### 已实现

- **流加密 (16/28)**: none, table, rc4, rc4-md5-6, rc4-md5, aes-128/192/256-cfb, aes-128/192/256-ctr, bf-cfb, des-cfb, salsa20, chacha20, chacha20-ietf
- **AEAD (5/28)**: aes-128/192/256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305 — 本地 e2e 通过（ssr-server plain+origin）
- **协议 (14/14)**: origin, verify_simple, auth_simple, auth_sha1, auth_sha1_v2, auth_sha1_v4, auth_aes128_md5, auth_aes128_sha1, auth_chain_a~f — 全部 e2e 通过
- **混淆 (5/6)**: plain, http_simple, http_post, http_mix, tls1.2_ticket_auth（tls1.2_ticket_fastauth 枚举有了待验证）
- **UDP relay**: SOCKS5 UDP ASSOCIATE 全链路 e2e 通过（auth_chain_a / auth_aes128_sha1 / AEAD 三组，见 commit e40c827）
- SOCKS5 客户端, TCP 中继, JSON 配置解析, 单元测试 186 个

### 已完成阶段（记录，不再重做）

- Phase 0 修复已知 Bug — 全部完成（commit 4138f7b 起）
- Phase 2 协议矩阵 — protocol 14/14、obfs 5/5、cipher 16/21 已实现项 e2e 通过；**加密方法矩阵的自动化回归脚本仍待 T3 入库**
- Phase 4 AEAD — 本地 e2e 通过
- Phase 5/6/7 的旧版任务 — 被本版 T/Q/R/P/M 五阶段取代

### 未实现（枚举有了但代码空缺）

| 加密方法 | 状态 | 备注 |
|-----------|------|------|
| camellia-128/192/256-cfb | 缺实现 | 服务端支持，值得实现 |
| cast5-cfb / idea-cfb / rc2-cfb / seed-cfb | 缺实现 | 服务端本身不支持（C 客户端同样失败），优先级低 |

---

## 主线准入门槛（Definition of Done）

**以下 12 条全部满足，才允许 push 主线。任何一条不满足，在 PROGRESS.md 记录差距后继续对应 Phase。**

| # | 门禁 | 命令 / 度量 | 目标 |
|---|------|------------|------|
| G1 | 编译零告警 | `cargo build --release 2>&1 \| grep -c '^warning'` | 0 |
| G2 | clippy 零告警 | `cargo clippy --all-targets -- -D warnings` | exit 0 |
| G3 | 格式统一 | `cargo fmt --all -- --check` | exit 0 |
| G4 | 测试全绿 | `cargo test` | 0 failed，总数 ≥ 186 + T 阶段新增 |
| G5 | 生产路径无 panic | 见 Q4 的 grep 脚本 | 生产路径 unwrap/expect/panic = 0 |
| G6 | unsafe 审计 | `grep -rn 'unsafe ' src` | 0，或每处有 `// SAFETY:` 论证 |
| G7 | 公共 API 文档 | `cargo doc --no-deps` + `#![warn(missing_docs)]` | 无 missing_docs 告警 |
| G8 | e2e 矩阵 | `tools/matrix_test.sh` 输出 | 已实现组合全 PASS，结果表入库 |
| G9 | 稳定性 | 10 分钟 soak + 异常注入 | 无内存泄漏、无 fd 泄漏、无 panic |
| G10 | 空闲资源 | R1 脚本测量 | RSS ≤ 20MB、空闲 CPU 0%、fd 稳定 |
| G11 | 性能对标 | criterion + 对标 C 客户端 | 本地回环吞吐 ≥ C 客户端 90% |
| G12 | 发布资产 | README/CHANGELOG/LICENSE/CI/examples | 齐全且 CI 绿 |

---

## 工作阶段

> 阶段顺序即执行顺序：**T（测试）→ Q（代码质量）→ R（运行占用）→ P（性能）→ M（主线合入）**。
> 理由：先有测试网兜底，再动代码质量（会改代码），改完测资源占用，资源干净后做性能，最后打包合入。
> 已完成的 Phase 0-4 见"已完成阶段"，本文件不再重复其任务。

### Phase T: 测试补全与强化

**目标**: 测试资产全部入库、可一键回归、覆盖边界与异常，作为后续改代码的安全网。

**任务**:

- [x] T1 测试资产入库（tests/e2e/ + tools/，2026-09-22）
  - 把 `/tmp/test_udp_e2e.py`、`/tmp/srv_*.json`、`/tmp/cli_*.json`、矩阵测试脚本移入仓库
  - 目录约定: 脚本进 `tools/`，e2e 资产进 `tests/e2e/`（配置模板用占位符，端口/密码由脚本注入）
  - 验证: 清空 /tmp 后 `tools/e2e_udp.sh` 仍能全绿
  - 记录: PROGRESS.md 写明入库文件清单

- [x] T2 边界与负面测试（full_coverage edge_cases mod，2026-09-22）
  - 空输入、1 字节输入、超长输入（>65507 UDP、>65535 段）
  - 截断的地址头 / HMAC 长度不足 / base64 非法字符 / JSON 缺字段、字段类型错误
  - 端口 0 与 65535、domain 名 255 字节上限、FRAG != 0 丢弃、mDNS 5353 丢弃
  - 每类至少 2 个用例；**要求：不 panic，返回错误或按 C 行为丢包**
  - 落点: `tests/full_coverage.rs` 追加 `mod edge_cases`

- [x] T3 属性/随机测试（tests/proptest_roundtrip.rs，2026-09-22）
  - dev-dependency 加 `proptest`（纯 Rust，loong64 可编译）
  - 不变量: 任意字节 `decrypt(encrypt(x)) == x`（28 cipher 全枚举）；任意输入协议层不 panic
  - 落点: `tests/proptest_roundtrip.rs`
  - 若 proptest 在 loong64 编译受阻，降级方案: 自写伪随机循环 1000 轮（固定种子，可复现）

- [x] T4 e2e 矩阵自动化脚本（tools/matrix_test.py，39/51+12SKIP 0 FAIL，2026-09-23）
  - `tools/matrix_test.sh`：生成配置 → 起 ssr-server → 起客户端 → curl 验证 → 清理 → 输出 PASS/FAIL 表
  - 组合策略（全叉 21×14×6 过大，采用三轴各自全覆盖 + 关键交叉）:
    1. cipher 轴: 16 已实现流加密 + 5 AEAD，各配 origin+plain = 21 组
    2. protocol 轴: 14 协议，各配 aes-256-cfb+plain = 14 组
    3. obfs 轴: 6 混淆，各配 aes-256-cfb+auth_aes128_sha1 = 6 组
    4. UDP 轴: 3 组（已有脚本，参数化并入库）
  - 结果表写入 `tests/e2e/RESULTS.md`，含日期与服务端版本
  - 已知服务端不支持的组合（cast5/idea/rc2/seed、auth_chain_f+key_len>16 SIGBUS）标记 SKIP 并注明原因

- [x] T5 异常与恢复测试（tests/resilience.rs 4/4 --ignored 全绿，2026-09-23）
  - 服务端 `kill -9` → 客户端不 panic、连接关闭干净、恢复后可重连
  - 客户端空闲超时（idle_timeout）到期回收
  - 并发: 100 个并发 TCP 连接同时传输，全部成功
  - 半关闭: 客户端侧先 close 写端，服务端侧正常收尾
  - 落点: `tests/resilience.rs`（`#[ignore]` 标注长耗时，CI 用 `-- --ignored` 跑）

- [x] T6 长稳 soak 测试（tools/soak_test.sh 600s SOAK_PASS + tools/resource_probe.sh R1 基线，2026-09-23）
  - 10 分钟持续传输（httpbin bytes 循环 + UDP echo 循环）
  - 每 30 秒采样 RSS / fd / 线程数，断言: RSS 增长 ≤ 10MB（warmup 后）、fd 回到基线、无 panic
  - 落点: `tools/soak_test.sh` + `tools/resource_probe.sh`（R1 复用同一脚本）

- [x] T7 回归确认（cargo test 239+4ignored / e2e_udp ALL_PASS / 矩阵 39/51+12SKIP 0 FAIL，2026-09-23）
  - `cargo test` 全绿；`tools/e2e_*.sh` 全绿
  - PROGRESS.md 记录: 新增测试数（186 → N）、矩阵结果表位置

### Phase Q: 代码质量（push 主线的核心）

**目标**: 编译/clippy/fmt 零告警，生产路径零 panic，unsafe 清零，公共 API 有文档，依赖干净。

**任务**:

- [x] Q1 消除 35 个编译告警（debug+release 均 0，2026-09-23）
  - 11 处 `cipher::Array::from_slice` 弃用 → 按提示改 `TryFrom`（注意失败分支返回错误，不 unwrap）
  - 3 处 `clone_from_slice` 同上
  - 4 处 unnecessary mut、8 处 unused import/variable/function、5 处 never read 字段/静态
  - 每改一类跑 `cargo test`，行为不得变化（字节级一致，可用现有协议测试兜底）
  - 完成标准: `cargo build 2>&1 | grep -c '^warning'` = 0

- [x] Q2 clippy 基线并清零（基线 58 → `--all-targets -- -D warnings` rc=0 + [lints.rust] warnings=deny，2026-09-23）
  - 先跑 `cargo clippy --all-targets 2>&1 | tail -20` 记录基线数量到 PROGRESS.md
  - 逐条修复（优先 correctness → perf → style）；确属误报用 `#[allow]` + 一行注释说明理由
  - 完成标准: `cargo clippy --all-targets -- -D warnings` exit 0
  - 在 Cargo.toml 加 `[lints.rust] warnings = ...`（若 MSRV ≥1.74）固化规则

- [x] Q3 rustfmt 统一（238 处 diff → `cargo fmt --all -- --check` exit 0，38 文件纯格式）
  - `cargo fmt --all`，diff 里只允许纯格式变化
  - 完成标准: `cargo fmt --all -- --check` exit 0；fmt 后立即 `cargo test` 全绿

- [x] Q4 生产路径 panic 清零（基线 39 → `tools/check_panic_paths.sh` rc=0，白名单 0 条，2026-09-23）
  - 写 `tools/check_panic_paths.sh`: grep src 下 `unwrap()/expect()/panic!/unreachable!`，排除 `#[cfg(test)]` 块与 `src/bin/`（bin 允许 fail-fast）
  - 分拣当前 138 处 → 生产路径逐处改造: 网络数据路径返回 `SsrError`；逻辑上不可达的用 `unreachable!` 换成带信息的 `SsrError::Internal` 或 `debug_assert` + 保守分支
  - 例外白名单写进脚本顶部（每条附一行理由），白名单条目数只减不增
  - 完成标准: 脚本 exit 0；`cargo test` 全绿

- [x] Q5 unsafe 审计（5 处 unsafe impl Send 全删，`grep -rn 'unsafe ' src` = 0，2026-09-23）
  - 逐处判断: 能删则删（多半可用 safe 等价改写）；必须保留的，原地写 `// SAFETY:` 段落说明不变量与为何成立
  - 完成标准: `grep -rn 'unsafe ' src` = 0，或条目数 = SAFETY 注释数且经人工复核

- [x] Q6 发布构建配置（profile.release: opt3+thin LTO+CGU1+strip；ssr_client 1819664→1184576 字节，−35%）
  - Cargo.toml 增加（库被下游使用时 profile 仅在顶层生效，属无害最佳实践）:
    ```toml
    [profile.release]
    opt-level = 3
    lto = "thin"
    codegen-units = 1
    strip = "symbols"
    ```
  - 记录前后 `ls -lh target/release/ssr_client` 数值到 PROGRESS.md
  - 注意: `panic = "abort"` 不设（库 crate 交给下游决定）

- [x] Q7 公共 API 文档与示例（239 处 missing_docs 清零，`cargo doc --no-deps` 0 告警，examples/socks5.rs 实测跑通，2026-09-23）
  - `src/lib.rs` 加 `#![warn(missing_docs)]`，补全所有 pub 项的 doc comment
  - 文档注释必须写清: 语义、错误条件、与 C 的对应关系（协议层标注 C 函数名与文件行号）
  - 新增 `examples/socks5.rs`: 20 行内起一个可用的 SOCKS5 代理
  - 完成标准: `cargo doc --no-deps` 零告警；example 可 `cargo run --example socks5` 跑通

- [x] Q8 错误处理审计（静默吞错 0、Timeout 变体接通、死参数清除；无 Box<dyn Error>，io 源链 `#[from]` 完整，2026-09-23）
  - 全库搜索 `let _ =`、`ok()`、`.unwrap_or_default()` 处理网络错误的地方，确认无静默吞错
  - 所有 io::Error 传播带上下文（thiserror source 链完整）
  - 对外 API 不返回裸 `Box<dyn Error>`；确认 `SsrError` 变体覆盖全部路径

- [x] Q9 依赖审计（移除 hkdf/tokio-test/sha2；tokio full→7 features；rust-version=1.82；cargo audit 0 漏洞，2026-09-23）
  - 移除未使用依赖（对照 grep 逐个确认: 检查 `hkdf`、`crc32fast`、`bytes`、`tokio-test` 等是否真被用到）
  - `tokio = "full"` 收窄为实际用的 features（net/rt-multi-thread/macros/io-util/time/sync/signal）
  - 加 `rust-version`（实际测得 MSRV 后填）；`cargo update` 后跑全测
  - 有网时跑 `cargo audit`（走 proxychains4）；结果记录 PROGRESS.md

- [x] Q10 Cargo.toml 发布元数据（description/license=GPL-3.0-or-later/repository/keywords/categories/readme + CHANGELOG.md semver 承诺 + LICENSE，`cargo package` rc=0，2026-09-23）
  - 补 `description` / `license`（与 LICENSE 文件一致）/ `repository` / `keywords` / `categories` / `readme`
  - 版本策略: 主线首发 `0.1.0`，写进 CHANGELOG 的兼容性承诺（semver，0.x 允许 breaking）

### Phase R: 运行占用

**目标**: 空闲与负载下的内存、线程、fd、CPU、体积全部量化达标，无泄漏。

**任务**:

- [x] R1 基线测量脚本（resource_probe.sh --idle 全 PASS，数字进 PROGRESS.md，2026-09-23）
  - `tools/resource_probe.sh`: 启动待测客户端，采样 `/proc/<pid>/{status,fd}` + `ps -o nlwp`
  - 记录: 空闲 RSS、线程数、fd 数、`top -b -n2` 空闲 CPU
  - 目标: **空闲 RSS ≤ 20MB、线程数 ≤ CPU核数+4、空闲 CPU = 0%、fd = 基线（3 TCP/UDP 相关 + stdio）**

- [x] R2 fd 泄漏测试（tools/fd_leak_test.sh：500 TCP 回基线、100 UDP 会话淘汰回基线，三跑全过，2026-09-23）
  - 循环 500 次: 建 TCP 连接经代理传输后关闭；结束后 fd 数回到基线
  - UDP: 建 100 个会话，等 `udp_timeout` 过期后会话表清空、fd 回落（验证 udp_relay 淘汰逻辑）
  - 纳入 T5/T6 断言

- [x] R3 负载内存增长（600s/64KB soak SOAK_PASS×2：增长 592KB、斜率 1.0 KB/min、fd 恒定 11、0 panic，2026-09-23）
  - 10 分钟持续 64KB 分块传输，每 30s 采样 RSS；warmup 后线性增长斜率 ≈ 0（总增长 ≤ 10MB）
  - 若增长: 用 `heaptrack`（若可用）或二分法定位（优先怀疑: 会话表、buffer 累积、日志缓冲）

- [x] R4 热路径分配审计（75 to_vec + 9 clone 分诊完毕；alloc_count.rs 插桩：one-shot 4 / stateful 2 allocs 每 64KB 往返；BytesMut=SsrBuffer 0 引用留 P3，2026-09-23）
  - `grep -rn 'to_vec()\|\.clone()' src/crypto src/relay src/protocol` 逐处判断是否可避免
  - 读写 buffer 复用: 评估 `BytesMut` 预分配（依赖已有 `bytes`）；per-connection buffer 不要每包新建大 Vec
  - 验收: R3 达标 + 分配次数对比数据（如用 criterion 的 `iter_batched` 或计数插桩）

- [x] R5 二进制体积（1819664→1184520 字节 −34.9%（≥30%）且 <5MB；size: text 1095829 / data 29416 / bss 392，2026-09-23）
  - 基线记录 → 应用 Q6 profile（strip/lto）→ 目标: 相对基线缩减 ≥ 30%，绝对值 < 5MB
  - 记录 `size target/release/ssr_client` 的 text/data/bss

- [x] R6 资源回收完整性（SIGINT → exit 0、监听释放、无残留进程；T5/T6 全绿 + R1 达标，2026-09-23）
  - `SsrClient::stop()` 后: 所有任务退出、socket 释放、进程可干净退出（无残留线程）
  - 连接中断/超时路径同样释放（用 T5 用例覆盖）
  - 完成标准: T5/T6 全绿 + R1 目标达成

### Phase P: 性能

**目标**: 建立可复现基准，性能不低于 C 客户端 90%，热路径无明显浪费。

**任务**:

- [x] P1 criterion 基准建立（criterion 0.5.1 loong64 编译运行；3 bench 76 项；BENCH.md 含日期/机器/频率，2026-09-23）
  - dev-dependency 加 `criterion`（loong64 编译验证，受阻则降级为自写计时 bin）
  - `benches/cipher_throughput.rs`: 每种 cipher 的 encrypt/decrypt MB/s（1MB buffer）
  - `benches/protocol_overhead.rs`: 各协议 pre_encrypt/post_decrypt 每包 ns 开销
  - `benches/obfs_overhead.rs`: 各 obfs encode/decode 每包 ns 开销
  - 结果表入库 `BENCH.md`（含日期、机器、频率），作为后续回归对照

- [x] P2 对标 C 客户端（64MiB×3 回环：吞吐 15.1 vs 14.6 MiB/s = 103.4% ≥90%；CPU 79.8% vs 99.9% = 0.80× ≤1.5×；双 PASS，2026-09-23）
  - 同机同配置: 我方客户端 vs `/opt/ssr/ssr-client`，本地 ssr-server 回环传 64MB 文件
  - 度量吞吐 MB/s 与 CPU 占用；目标 **吞吐 ≥ C 的 90%，CPU 不高于 C 的 1.5 倍**
  - 脚本: `tools/bench_vs_c.sh`，结果进 BENCH.md

- [x] P3 热路径优化（协议层每包分配 chain 5→2 / aes128 6→4，bench −4.6~−6.3% ≥5%；cipher/obfs 拷贝经数据判定 <5% 不做；238 测试+matrix 0 FAIL，2026-09-23）（有基线后按数据动手，禁止盲改）
  - 优先级: cipher_env encrypt/decrypt 每包分配 → 协议层 hmac/PRNG 每包分配 → obfs 拼包拷贝
  - 每项优化必须: bench 前后对比 + `cargo test` 全绿，收益 < 5% 的不做
  - 明确**不做**的: SIMD 手写汇编、unsafe 加速（与 Q5 冲突）、改变 wire format 的任何优化

- [x] P4 并发扩展性（1/8/64/100 曲线：64 流 146.7 MiB/s = 9.7× 单流 ≥8×；client CPU 83-85% 恒定、fd 回基线 → 无锁热点不优化，2026-09-23）
  - 1/8/64/100 并发流吞吐曲线；无锁竞争热点（Mutex 争用）才优化
  - 目标: 并发 64 时总吞吐 ≥ 单流的 8 倍（回环、有 12 核的前提）

- [x] P5 发布编译核对（release 复测 P1 76 项入 BENCH.md FINAL 版；debug_assert 已剔除（assert 消息串不在二进制）；target-cpu=native 建议已注明，2026-09-23）
  - `cargo build --release` 后复测 P1；确认 release 无 debug_assert 拖累
  - 文档注明: 下游可用 `RUSTFLAGS="-C target-cpu=native"` 自行榨取，库本身不绑 CPU 特性

### Phase M: 主线合入

**目标**: 门禁 G1-G12 全绿，合入资产齐全。

**任务**:

- [x] M1 CI 工作流（.github/workflows/ci.yml 四门禁 + e2e workflow_dispatch/self-hosted；本地逐条跑同命令全绿、yml 解析过，2026-09-23）
  - `.github/workflows/ci.yml`: fmt check → clippy -D warnings → cargo test → release build →（可选）e2e（需服务端，标记 `workflow_dispatch` 或 self-hosted）
  - 本地先逐条跑同样命令，保证 CI 不会红

- [x] M2 README 更新（快速开始/API 示例（编译验证）/支持矩阵→RESULTS.md/14 字段表/MSRV/徽章×4/License 修正 MIT→GPL-3.0-or-later/链 BENCH+CHANGELOG，2026-09-23）
  - 现状核对: 快速开始、API 示例（指向 examples/）、支持矩阵（cipher/protocol/obfs/UDP）、配置字段说明、MSRV、徽章
  - 已测试组合表链到 `tests/e2e/RESULTS.md`

- [x] M3 CHANGELOG + LICENSE（0.1.0 条目含功能范围+已知限制（补 camellia×3/des 说明、21/28 精确化）；LICENSE=上游 GPLv3 与 license 字段一致，2026-09-23）
  - `CHANGELOG.md`: 0.1.0 首发条目（功能范围、已知限制: cast5/idea/rc2/seed 未实现、AEAD 生产组合待复核）
  - `LICENSE` 文件与 Cargo.toml `license` 字段一致

- [x] M4 API 冻结复核（人工过 pub 清单；private_interfaces 编译器证明 0；删死 API SsrBuffer+utils::buffer+bytes 直接依赖；ObfsRelay/Context/rc4_once 私有确认；2026-09-23）
  - `cargo public-api`（或人工过一遍 `pub` 清单）确认无私有类型泄漏、无无意义 pub
  - 内部类型（relay/obfs 细节）尽量 `pub(crate)`；确认 `Box<dyn Protocol>` 等 trait 边界合理

- [x] M5 最终验收（G1-G12 十二门禁全绿，输出贴 PROGRESS.md；快照已更新；push 待用户指示，2026-09-23）

---

## Phase U: 双模式集成 — 系统端口 / 数据管道（用户需求 2026-09-23）

- [x] U1 `SsrClient::open_session(target) -> SsrSession` 数据管道 API（2026-09-23）
  - 模式 A（绑定系统端口、SOCKS5）保持不变；模式 B 不监听端口，返回 AsyncRead+AsyncWrite 明文流
  - 实现约束：建链逻辑抽取 `establish_tunnel` 与 SOCKS5 路径共享；`ObfsRelay` 本地侧泛型化，`run()` 泵体两种模式共用（wire 字节不变）
  - 收尾语义：Drop=中止泵并关隧道；`finish()`=优雅排干并透出泵错误；泵错误映射到 read EOF/write 错误
- [x] U2 验证与文档（拒绝路径+e2e 双会话 200 OK、matrix 39/51 0 FAIL、UDP PASS、README 双片段编译、门禁全绿，2026-09-23）
  - 默认单测（无服务端的拒绝路径）+ `--ignore` e2e（真实 ssr-server：HTTP 往返、IPv4/Domain 两种目标、双会话复用）
  - mode A 回归：matrix 39/51 0 FAIL + UDP ALL_PASS；全门禁 + README 双模式章节（两个片段都编译）+ CHANGELOG

---

## Phase V: IPv6 支持核查 + stop 竞态修复（2026-09-23）

- [x] V1 IPv6 全景核查与收口
  - 协议层原生支持确认（ATYP 0x04 解析/应答/addr_pkg/UDP 往返均有测试）；rustc 实验证明裸拼与括号形式解析**等价**（原代码 IPv6 字面量本就可用——如实记录，非修 bug）
  - `host_port()` 规范化 6 处地址拼接为 std 括号形式；新增 IPv6 字面量连通、`::` 双栈监听、格式等价共 4 测试；http_simple Host 头保持与 C 裸拼逐字节一致（不动）
- [x] V2 stop() 竞态修复（新测试暴露的真 bug）
  - Notify::notify_waiters 无 permit → 错过注册窗口即永挂（僵尸测试进程持端口为证）；改 watch 值语义，TCP/UDP 双循环顶检查；start/stop 压力 15 连跑全过、0 LISTEN 残留
  - 门禁全绿 + matrix 39/51 0 FAIL + UDP ALL_PASS + 管道 e2e 三路复跑

---

## 测试记录模板

每次测试后在 PROGRESS.md 中记录：

```
### YYYY-MM-DD HH:MM 测试记录

**组合**: METHOD + PROTOCOL + OBS
**服务端配置**: (关键参数)
**客户端配置**: (关键参数)
**结果**: PASS / FAIL
**问题描述**: (如果 FAIL，具体错误信息)
**修复**: (如果 FAIL，做了什么修复)
```

资源/性能类记录追加机器信息与原始数字：

```
**环境**: 3A5000 x12 @ 2.0GHz / Deepin 25 / kernel 6.6.143
**原始数据**: RSS idle=xxMB, threads=N, fd=N, 二进制=xxKB, 吞吐=xx MB/s
**对照**: 改前 xx → 改后 xx (±x%)
```

---

## 参考资源

- C 参考实现: `ssr-n/src/` 目录（协议层注释须标注 C 函数名与行号）
- SSR 协议规范: 各协议的 C 实现是最权威的参考
- ssr-n 配置格式: `/opt/ssr/config.json`（ssr-n JSON）
- 服务端帮助: `/opt/ssr/ssr-server -h`
- 已知 C 服务端 bug: auth_chain_f + key_len>16 启动 SIGBUS（我方取 min(16) 规避）

---

## 停止条件

当"主线准入门槛"12 条全部满足时，本项目对当前目标（push 主线）视为完成：

1. `cargo build --release` 零告警
2. `cargo clippy --all-targets -- -D warnings` 零告警
3. `cargo fmt --all -- --check` 零差异
4. `cargo test` 全绿（0 failed，含 T2/T3 新增用例）
5. 生产路径 unwrap/expect/panic = 0（白名单豁免已书面记录）
6. unsafe = 0 或逐条 SAFETY 论证
7. `cargo doc --no-deps` 零 missing_docs
8. e2e 矩阵脚本全绿且资产入库（不依赖 /tmp）
9. 10 分钟 soak: 无内存/fd 泄漏、无 panic
10. 空闲 RSS ≤ 20MB、空闲 CPU 0%、二进制 < 5MB
11. 回环吞吐 ≥ C 客户端 90%（BENCH.md 有数据）
12. README / CHANGELOG / LICENSE / CI / examples 齐全
