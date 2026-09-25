# GOAL — crates.io 发布内容补齐（性能测试 / 使用文档 / 双语 / examples）

本文件是本次任务的唯一清单：自己确定的交付项、每项的验证命令、进度行。
完成后本文件全部勾选即任务结束。

## 反幻觉规则（适用全程）

1. **先读后写**：改任何文件前必须先 `read_file`，不凭记忆改。
2. **先验后报**：没有真实命令输出（测试数、打包文件数、bench 数字）不得勾选任何一项。
3. **不重复已完成项**：勾掉的项不再重做；改前先看下面的进度行。
4. **每完成一项**：在同一行勾选，并追加一条进度行
   `日期 | 项号 | 改动摘要 | 验证命令真实输出摘要`（带真实数字）。
5. **每批完成后跑门禁**：`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` 全绿才算本批完成。
6. **克制范围**：只做清单上的事，不顺手重构源码；前提不成立的项按进度行规则改写为"核账项"并注明证据。

## 当前状态快照（2026-09-24 实测）

- `cargo package --list --allow-dirty`：**4179 个文件** —— 把 68M 的 `ssr-n/`
  参考 C 源码和 5 个转储 JSON（auth_output / ssr_n_file_contents /
  ssr_n_source_files / ssr-obfs-complete / ssr_obfs_source，共 ~650K）全打进去了，
  crates.io 直接发不了（上限 10MB）。
- Cargo.toml 元数据：缺 `homepage`、`documentation`；description/keywords/categories/
  license/readme/rust-version 齐全，keywords 恰好 5 个（crates.io 上限）。
- 文档：README.md / BENCH.md / CHANGELOG.md / MIGRATION.md 全英文，
  **零中文文档**；`docs/` 目录不存在。
- examples：只有 `examples/socks5.rs` 1 个。
- benches：3 个 criterion 目标（cipher_throughput / protocol_overhead /
  obfs_overhead）+ BENCH.md 已有 e2e 对比与并发曲线；
  **缺"建连开销"维度**（新连接的 cipher 上下文创建 + 协议首包 + obfs 握手编码）。
- 测试基线：见进度区首条（后台 `cargo test` 实测求和）。

## 交付清单

### Phase 1 — crates.io 元数据与打包瘦身

- [x] 1.1 Cargo.toml 补齐发布元数据：`homepage`、`documentation = "https://docs.rs/ssr-client-rs"`；
      `exclude` 掉 `ssr-n/`、5 个转储 `*.json`、内部文档 `GOALS.md`、`PROGRESS.md`。
      验证：`grep -E 'homepage|documentation|exclude' Cargo.toml`
- [x] 1.2 打包瘦身生效。验证：`cargo package --list --allow-dirty | wc -l`
      且 `cargo package --list --allow-dirty | grep -cE 'ssr-n/|auth_output|GOALS|PROGRESS'` 为 0
- [x] 1.3 打包可构建。验证：`cargo package --allow-dirty` 成功（Packaged + verified）

### Phase 2 — 性能测试补齐

- [x] 2.1 三个现有 bench 全部跑通，记录中位数。验证：`cargo bench -- --noplot`（独占机器，无并行构建）
- [x] 2.2 新增 `benches/session_setup.rs`（建连开销：CipherEnv 上下文创建、协议
      首包 pre_encrypt（含认证头）、obfs 握手 encode/decode），Cargo.toml 注册 `[[bench]]`。
      验证：`cargo bench --bench session_setup -- --noplot` 出数
- [x] 2.5 核账项（执行中发现）：BENCH.md 尾部有 3 份重复的 "## 4. P2 end-to-end"
      块（历次验收追加未替换，git log -p 证实分别来自 ac986f5 / 864cc1c /
      1ff3c43）——去重，仅保最新一轮（1ff3c43：102.7% / 0.76×，即 6ed29f
      二进制），并挪回 §5 之前恢复 1→5 编号顺序；README 两语言的引用数字
      同步为 102.7% / 0.76×。验证：`grep -c '^## 4\.' BENCH.md` = 1
- [x] 2.3 BENCH.md 增补 session_setup 章节 + 复核运行元数据仍然准确。
      验证：`grep -c 'session_setup' BENCH.md` ≥ 1
- [x] 2.4 新增 `BENCH.zh-CN.md`：BENCH.md 全量中文版（同样的表格与数字，不改数）。
      验证：`test -f BENCH.zh-CN.md`，且各表格行数与 BENCH.md 一致

### Phase 3 — 使用文档（docs/，中英两份）

- [x] 3.1 新增 `docs/USAGE.md`（英文全量）：安装（crates.io）、快速开始、两种集成模式、
      配置字段全表、支持矩阵（cipher/protocol/obfs/UDP）、错误处理与超时语义、
      性能调优（target-cpu=native、bench 指引）、example 索引与运行命令、FAQ。
      验证：`test -f docs/USAGE.md` + 其中所有相对链接文件存在（脚本核对）
- [x] 3.2 新增 `docs/USAGE.zh-CN.md`：与 3.1 结构逐节对应的完整中文版。
      验证：`test -f docs/USAGE.zh-CN.md` + 两文件小节标题数量一致（脚本核对）

### Phase 4 — 使用说明（README，中英两份）

- [x] 4.1 更新 `README.md`：crates.io 安装方式（`cargo add ssr-client-rs`）、
      crates.io + docs.rs 徽章、指向 `docs/USAGE.md`、顶部语言切换链接、
      examples 索引。验证：`grep -c 'docs.rs\|crates.io\|README.zh-CN' README.md` ≥ 3
- [x] 4.2 新增 `README.zh-CN.md`：与英文版逐节对应的完整中文版。
      验证：`test -f README.zh-CN.md`，小节数与 README.md 一致

### Phase 5 — examples

- [x] 5.1 `examples/socks5.rs`（已有）：补中英双语头注释与用法行。验证：编译过
- [x] 5.2 新增 `examples/open_session.rs`：Mode B 数据管道（`open_session` → HTTP GET → `finish`）
- [x] 5.3 新增 `examples/config_builder.rs`：结构体字面量构建配置 + JSON 解析 +
      错误展示（`SsrError` 的 Display），打印最终生效配置
- [x] 5.4 全部 example 可编译。验证：`cargo build --examples` 成功
- [x] 5.5 README（双语）与 docs/USAGE（双语）里给出每个 example 的运行命令。
      验证：4 个文件中 `cargo run --example` 各 ≥ 3 处

### Phase 6 — 总验证（全绿才算完成）

- [x] 6.1 门禁：`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
      全绿，测试总数 ≥ 基线（见进度区）
- [x] 6.2 `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` 成功（docs.rs 可构建）
- [x] 6.3 `cargo package --allow-dirty` 成功，包文件数复核与 1.2 一致
- [x] 6.4 双语完整性核对：下列 6 个文件两两英中对应齐全
      （README↔README.zh-CN、docs/USAGE↔docs/USAGE.zh-CN、BENCH↔BENCH.zh-CN），
      且所有相对链接指向的文件存在

## 范围外（明确不做）

- 不改任何生产源码逻辑（`src/` 只读，除非 example/bench 编译需要且不进发布包的行为变化）。
- CHANGELOG.md / MIGRATION.md 保持英文（行业惯例，Keep a Changelog），不另出中文版。
- 不执行 `cargo publish`（发布动作由用户自己做）。
- 不 push、不打 tag（按用户 git 工作流）。

## 进度行

（每完成一项在此追加：`日期 | 项号 | 摘要 | 真实输出`）

- 2026-09-24 | 2.x（前置修复） | 发现 BENCH.md 的复现命令 `cargo bench -- --noplot` 实际跑不通：libtest 拒收 --noplot（rc=101 "Unrecognized option"）；加 `[lib] bench = false` 修根因，四 criterion 目标不受影响 | 修复后后台全量 `cargo bench -- --noplot` 启动（proc_bc3b0d710d4b）
- 2026-09-24 | 3.1–3.2 | 新增 docs/USAGE.md（16.4K，13 个 `##` 节）与 docs/USAGE.zh-CN.md（16.2K，13 个 `##` 节）；相对链接核对仅 BENCH.zh-CN.md 未建（Phase 2 交付） | `grep -c '^## '` = 13/13；链接脚本：broken 仅 ../BENCH.zh-CN.md
- 2026-09-24 | 4.1–4.2 | README.md 补 crates.io/docs.rs 徽章、语言切换、`cargo add`/版本号安装、example 表、USAGE 链接；新增 README.zh-CN.md 全量中文版 | H2 数 9=9；README.md 标记（docs.rs|crates.io|README.zh-CN）=3；链接脚本 broken 仅 BENCH.zh-CN.md
- 2026-09-24 | 5.1–5.3 | socks5.rs 补双语头注释；新增 examples/open_session.rs（Mode B）、examples/config_builder.rs（离线配置构建+错误展示）；修 config_builder JSON 键笔误 ob_param→obfs_param | `cargo check --bench session_setup`、`cargo check --examples` 均 Finished 0 error
- 2026-09-24 | 2.1 | 三个旧 bench 全跑通并逐项对比基线 | 76 个中位数解析（cipher 42 + protocol 22 + obfs 12），对 BENCH.md 偏差 −7.4%…+2.4%，全在 ±10% 噪声带（相关路径零改动 → 环境波动）；rc 前三 target 0
- 2026-09-24 | 2.2 | 新增 benches/session_setup.rs 并注册；途中修自身 bug（encrypt_ctx 对 camellia 等 new 成功但 ctx 失败，unwrap 炸 → 先探测再计时）| `cargo bench --bench session_setup -- --noplot` rc=0，69/69 项出数（env 28 + encrypt_ctx 21 + protocol_first 14 + obfs_first 6）；发现 table 每连接建表 72.06 ms、bf-cfb encrypt_ctx 49.1 µs
- 2026-09-24 | 2.3 | BENCH.md 加复跑核账说明与复现命令修正（three→four + bench=false 说明），追加 §6 session-setup 章节 | `grep -n '^## '` = Run metadata+§1..§6 顺序正确，227 行
- 2026-09-24 | 2.4 | 新增 BENCH.zh-CN.md 全量中文版 | `grep -c '^## '` 中英各 = 7；§6 三表行数 28/14/6 与英文版一致
- 2026-09-24 | 2.5 | BENCH.md 三份重复 §4 去重保最新（6ed29f/102.7%/0.76x），挪回 §5 前；README×2 引用数字同步 | `grep -c '^## 4\.' BENCH.md` = 1；丢弃旧块 ecd9b44095fa、76e84c39821f
- 2026-09-24 | 5.4 | | （验证并入 6.1 门禁：clippy --all-targets + cargo build --examples）
- 2026-09-24 | 5.5 | 四份文档（README×2、USAGE×2）各自 `cargo run --example` 命令数 | 每份 = 3（要求 ≥3）

- 2026-09-24 | 6.1–6.4 | 总门禁与终验 | fmt --check = FMT_OK；clippy --all-targets -D warnings rc=0；cargo test 229 passed/0 failed（=基线 229）；cargo build --examples OK；RUSTDOCFLAGS=-D-warnings cargo doc --no-deps OK；cargo package = Packaged 75 files (171.4KiB compressed)，list=75；6 份双语文件互链 0 broken、H2 数 9/9、13/13、7/7；`-c/--config` 参数与 src/bin/ssr_client.rs:10 实证一致；./target/debug/config_builder 实跑输出生效配置
- 2026-09-24 | 1.1–1.3 | Cargo.toml 补 homepage/documentation + exclude（ssr-n/、*.json、GOALS/GOAL/PROGRESS） | `cargo package --list` 4179→68 文件；`cargo package` = Packaged 68 files, 618.3KiB (150.4KiB compressed), Verified, Finished in 30.27s；禁运文件 grep 计数 0
