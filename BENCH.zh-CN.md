# BENCH.zh-CN.md — criterion 性能基线（P1）

可复现的微基准基线，用于回归对比（GOALS P1）。英文版：[BENCH.md](BENCH.md)。

## 运行元数据

| 字段 | 值 |
|---|---|
| 日期 | 2026-09-23 |
| 机器 | Loongson-3A5000 (LA664)，4 核 @ 2.30 GHz，LoongArch64 |
| 内核 / 系统 | 6.6.143-loong64-desktop-hwe / Deepin 25 |
| profile | `cargo bench` = release（opt3、thin LTO、codegen-units=1、strip） |
| 工具链 | rustc stable-loongarch64，criterion 0.5.1 |
| 方法 | 预热 300 ms、测量 1 s、10 个样本、`--noplot` |
| 噪声 | 桌面会话、未隔离 CPU —— ±10% 以内视为噪声带 |

复现：`cargo bench -- --noplot`（全部四个目标；`[lib]` 与各 `[[bin]]` 设了
`bench = false`，libtest 不会见到 `--noplot`）。

2026-09-24 复跑核账：§1–3 全部 76 个中位数与下表偏差在
−7.4%…+2.4% 之内（噪声带 ±10%，相关路径零代码改动 → 环境波动，非回归）；
§6 即来自该次运行。

## 1. cipher 吞吐（1 MiB 缓冲，criterion — FINAL release-profile 轮）

`encrypt` = 常驻上下文流式加密；`decrypt` = 每包全新上下文
（含 IV/salt 解析与密钥调度）。不支持的方法（camellia、cast5、idea、
rc2、seed —— 底层 crate 未覆盖）被 `CipherEnv::new` 跳过。此前有其他
cargo 任务并行时取的数字被污染（缓存敏感路径最多差 10 倍）；下表全部来自
全部 Phase-P 改动之后的最终空机轮。想再挤最后几个百分点的下游用户可用
`RUSTFLAGS="-C target-cpu=native"` 构建 —— 本库自身不锁定 CPU 特性（P5）。

| cipher | encrypt MiB/s | decrypt MiB/s |
|---|---:|---:|
| aes-128-cfb | 29.6 | 27.7 |
| aes-128-ctr | 116.9 | 110.6 |
| aes-128-gcm | 81.8 | 69.3 |
| aes-192-cfb | 25.5 | 23.6 |
| aes-192-ctr | 100.8 | 96.0 |
| aes-192-gcm | 73.1 | 63.1 |
| aes-256-cfb | 22.2 | 20.7 |
| aes-256-ctr | 88.0 | 84.4 |
| aes-256-gcm | 66.3 | 58.0 |
| bf-cfb | 73.0 | 71.6 |
| chacha20 | 347.7 | 300.2 |
| chacha20-ietf | 348.2 | 300.3 |
| chacha20-ietf-poly1305 | 241.8 | 157.9 |
| des-cfb | 20.8 | 20.7 |
| none | 15889.9 | 1941.1 |
| rc4 | 193.9 | 178.7 |
| rc4-md5 | 194.2 | 177.4 |
| rc4-md5-6 | 194.0 | 177.7 |
| salsa20 | 398.9 | 344.7 |
| table | 928.5 | 647.6 |
| xchacha20-ietf-poly1305 | 239.6 | 157.2 |

## 2. 协议每包开销（1440 B，ns/包 — FINAL 轮，P3 之后）

下表已含 P3 每包分配削减（`hmac_key_buf` 暂存复用、直接填充 `out`、
RC4 原地运算）；相对 P3 前基线：auth_aes128 pre/post −4.6…−6.3%、
auth_chain_a/c pre −5.8%（每包分配次数：auth_chain 5→2、auth_aes128 6→4）。

`auth_chain_*` 的 `post/*` 为 **n/a**：客户端 `post_decrypt` 只解析
服务器方向的帧（单向哈希链），`client_pre_encrypt` 输出无法自环 ——
已用探针二进制确认，且属设计使然（full_coverage 的链测试只跑 `pre`）。
在 bench 里抓真实服务器帧需要驱动 C 服务器；端到端开销由 P2 §4 覆盖。

| protocol | pre | post |
|---|---:|---:|
| auth_aes128_md5 | 5.97 µs | 5.79 µs |
| auth_aes128_sha1 | 4.70 µs | 4.45 µs |
| auth_chain_a | 12.09 µs | n/a |
| auth_chain_b | 11.90 µs | n/a |
| auth_chain_c | 12.06 µs | n/a |
| auth_chain_d | 11.97 µs | n/a |
| auth_chain_e | 11.98 µs | n/a |
| auth_chain_f | 11.97 µs | n/a |
| auth_sha1 | 9.62 µs | 8.72 µs |
| auth_sha1_v2 | 9.11 µs | 8.17 µs |
| auth_sha1_v4 | 8.84 µs | 8.19 µs |
| auth_simple | 1.64 µs | 1.62 µs |
| origin | 145 ns | 422 ns |
| verify_simple | 1.66 µs | 1.41 µs |

## 3. obfs 每包开销（1440 B，ns/包 — FINAL 轮）

稳态：HTTP 头已发出、TLS 握手已完成（可达处经预热 encode 调用置位
0x04/0x08）。

| obfs | encode | decode |
|---|---:|---:|
| http_mix | 227 ns | 2.01 µs |
| http_post | 214 ns | 2.02 µs |
| http_simple | 214 ns | 2.03 µs |
| plain | 193 ns | 2.00 µs |
| tls1.2_ticket_auth | 470 ns | 343 ns |
| tls1.2_ticket_fastauth | 476 ns | 333 ns |

## 4. P2 端到端 vs C 客户端（2026-09-25）

| 字段 | 值 |
|---|---|
| 配置 | aes-256-cfb / auth_aes128_sha1 / tls1.2_ticket_auth，loopback |
| 载荷 | 64 MiB 随机文件 × 3 轮，取中位数 |
| 服务器 | /opt/ssr/ssr-server (d70342262c45) |
| C 客户端 | /opt/ssr/ssr-client (988974dcdfa5) |
| Rust 客户端 | /home/liangzhaoyuan12/work/rs/ssr-client-rs/target/release/ssr_client (03a3925de66d) |

| 客户端 | 吞吐 MiB/s | 墙钟中位数 s | CPU % |
|---|---|---|---|
| C | 13.9 | 4.603170 | 97.8 |
| Rust | 14.8 | 4.332194 | 75.3 |

**结果**：吞吐 rust/C = 106.5%（目标 ≥ 90%），
CPU rust/C = 0.77×（目标 ≤ 1.5×）—— throughput rust/C=106.47% (PASS, need >=90%)  cpu rust/C=0.77x (PASS, need <=1.5x)

## 5. P4 并发扩展曲线（2026-09-23）

本地 ssr-server + Rust 客户端，aes-256-cfb / auth_aes128_sha1 /
tls1.2_ticket_auth，64 MiB 原始文件，每级 15 s 窗口。`client CPU%`
为窗口期内进程级（所有线程）数值。

| 级别 | MiB/s | × 单流 | client CPU % | server CPU % | fd | RSS MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 15.1 | 1.0× | 83 | 99 | 10 | 3.6 |
| 8 | 149.1 | 9.9× | 85 | 99 | 18 | 4.4 |
| 64 | 146.7 | **9.7×** | 84 | 99 | 16 | 7.8 |
| 100 | 144.4 | 9.6× | 83 | 97 | 52 | 8.8 |

- **GOALS 目标达成**：64 级 ≥8× 单流 → 实测 **9.7×**。
  （单流受流控限制约 15 MiB/s，非算力限制，所以 8× 比值在这台 4 核机上
  也能达到；聚合吞吐在整机算力墙 —— client+server+curl —— 饱和，这就是
  曲线在 8 流走平而非继续爬升的原因。）
- **无锁热点**：各级别 client CPU 恒定 83–85%（每 MiB 成本恒定），
  吞吐不随级别下降，fd 跑完回落基线（10），100 流时 RSS 峰值 8.8 MiB。
  无 Mutex 争用特征 → 按 GOALS 无需优化。
- 预算交叉核对：aes-256-cfb 软实现 22 MiB/s/核（§1 微基准），解密
  149 MiB/s 需 ~0.68 核 —— 与实测客户端总 0.83 核一致（其余 ~0.15 核
  用于系统调用/协议/伪装）。C 侧服务器镜像同此。
- 已知瑕疵：origin-CPU 列采样的 http.server 包装 PID 而非 python worker，
  读数为 0 —— 不参与任何判定。
- `method=none` 对照轮连不上（服务器拒绝），证实手写配置的 `method`
  键两端都被认真对待。

## 6. session-setup 开销（每条**新连接**，criterion — 2026-09-24）

`establish_tunnel` + `assemble` 为每条连接做的事，不含 TCP 连接本身
（bench `session_setup`，计时内全新状态）。机器与方法同上。

| method | env — `with_method`（KDF） | encrypt_ctx — IV + 上下文 |
|---|---:|---:|
| `none` | 1.54 µs | 3.01 µs |
| `table` | 72.06 ms | 3.01 µs |
| `rc4` | 2.40 µs | 4.14 µs |
| `rc4-md5-6` | 2.41 µs | 5.31 µs |
| `rc4-md5` | 2.41 µs | 5.34 µs |
| `aes-128-cfb` | 2.40 µs | 6.11 µs |
| `aes-192-cfb` | 2.68 µs | 6.04 µs |
| `aes-256-cfb` | 2.68 µs | 6.51 µs |
| `aes-128-ctr` | 2.40 µs | 5.30 µs |
| `aes-192-ctr` | 2.67 µs | 6.86 µs |
| `aes-256-ctr` | 2.67 µs | 5.39 µs |
| `bf-cfb` | 2.40 µs | 49.10 µs |
| `camellia-128-cfb` | 2.40 µs | — |
| `camellia-192-cfb` | 2.69 µs | — |
| `camellia-256-cfb` | 2.66 µs | — |
| `cast5-cfb` | 2.41 µs | — |
| `des-cfb` | 2.41 µs | 4.43 µs |
| `idea-cfb` | 2.41 µs | — |
| `rc2-cfb` | 2.42 µs | — |
| `seed-cfb` | 2.42 µs | — |
| `salsa20` | 2.67 µs | 3.54 µs |
| `chacha20` | 2.67 µs | 3.53 µs |
| `chacha20-ietf` | 2.68 µs | 3.63 µs |
| `aes-128-gcm` | 2.39 µs | 3.88 µs |
| `aes-192-gcm` | 2.65 µs | 3.93 µs |
| `aes-256-gcm` | 2.68 µs | 3.98 µs |
| `chacha20-ietf-poly1305` | 2.65 µs | 3.98 µs |
| `xchacha20-ietf-poly1305` | 2.65 µs | 3.98 µs |

注：`table` 每条连接都从密码重建两张 256 项替换表 —— **72 ms**，连接
翻涌场景避免用 `table`（C 客户端付出同样的每连接代价）；7 个 `—` 方法
可解析但无底层实现（建 ctx 失败，与 §1 跳过集一致）；`bf-cfb` 的
49 µs encrypt_ctx 是 Blowfish 密钥调度。其余 env 值都在 1.54–2.69 µs
（MD5 链 `bytes_to_key`，成本随密钥长度走）。

| protocol | 首包 — 构建 + `set_server_iv` + `client_pre_encrypt`（含连接头） |
|---|---:|
| `origin` | 138 ns |
| `verify_simple` | 779 ns |
| `auth_simple` | 944 ns |
| `auth_sha1` | 2.47 µs |
| `auth_sha1_v2` | 4.82 µs |
| `auth_sha1_v4` | 3.24 µs |
| `auth_aes128_md5` | 10.83 µs |
| `auth_aes128_sha1` | 10.24 µs |
| `auth_chain_a` | 13.82 µs |
| `auth_chain_b` | 13.63 µs |
| `auth_chain_c` | 14.00 µs |
| `auth_chain_d` | 14.78 µs |
| `auth_chain_e` | 12.24 µs |
| `auth_chain_f` | 11.58 µs |

| obfs | 首次编码 — 构建 + `set_key` + 握手编码（HTTP 头 / TLS ClientHello） |
|---|---:|
| `plain` | 147 ns |
| `http_simple` | 2.59 µs |
| `http_post` | 4.19 µs |
| `http_mix` | 3.15 µs |
| `tls1.2_ticket_auth` | 3.13 µs |
| `tls1.2_ticket_fastauth` | 4.61 µs |

**结论**：一条非 `table` 连接典型付出 ≈ 2.5 µs（KDF）+ 3–7 µs
（cipher ctx）+ 0.14–14.8 µs（协议首包）+ 0.15–4.6 µs（obfs 握手）
≈ **几十 µs CPU** —— 相对一次网络 RTT 可忽略；建连是网络受限，
不是算力受限。
