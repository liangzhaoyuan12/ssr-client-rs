# 使用指南 — ssr-client-rs

本库的完整使用文档。快速上手见 [README.zh-CN.md](../README.zh-CN.md)，
本页深入全部细节。英文版本：[USAGE.md](USAGE.md)。

- [1. 概览](#1-概览)
- [2. 安装](#2-安装)
- [3. 快速开始](#3-快速开始)
- [4. 集成模式](#4-集成模式)
- [5. 配置参考](#5-配置参考)
- [6. 支持的算法](#6-支持的算法)
- [7. 错误处理与超时](#7-错误处理与超时)
- [8. UDP 中继](#8-udp-中继)
- [9. 示例](#9-示例)
- [10. 性能](#10-性能)
- [11. 测试](#11-测试)
- [12. 常见问题](#12-常见问题)

## 1. 概览

`ssr-client-rs` 是 `ssr-n` C 语言 ShadowsocksR 客户端库的字节级兼容
Rust 移植。每个包都经过这条流水线：

```
用户数据 → SOCKS5 → 协议 (pre_encrypt) → 加密 (encrypt) → 伪装 (encode) → 服务器
服务器   → 伪装 (decode) → 解密 (decrypt) → 协议 (post_decrypt) → 用户
```

设计保证：

- 全库 **零 `unsafe`**。
- **生产路径零 panic** —— 所有可能失败的操作都返回 `SsrResult<T>`
  （CI 由 `tools/check_panic_paths.sh` 强制检查）。
- **基于 Tokio 的异步 I/O**，future 全程 `Send`，可安全用于
  `rt-multi-thread`。
- **兼容 ssr-n JSON 配置** —— C 客户端读什么键，这里就读什么键。

## 2. 安装

从 crates.io 安装（MSRV **1.82**）：

```toml
[dependencies]
ssr-client-rs = "0.1"
tokio = { version = "1", features = ["net", "rt-multi-thread", "macros", "io-util", "time", "sync", "signal"] }
```

或用 `cargo add`：

```bash
cargo add ssr-client-rs
```

跟踪最新（git）：

```toml
[dependencies]
ssr-client-rs = { git = "https://cnb.cool/liangzhaoyuan12/ssr-client-rs" }
```

本库没有需要配置的 default feature。平台支持：linux x86_64（CI）与
linux loongarch64。理论上凡能编译 Rust + tokio 的平台都可构建，但只在
这两个平台上实测过。

## 3. 快速开始

```rust,no_run
use ssr_client_rs::config_json::config_from_json;
use ssr_client_rs::{CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig};

#[tokio::main]
async fn main() {
    // 方式一：ssr-n 风格 JSON 配置（键名即结构体字段，全表见 §5）。
    let json = r#"{
        "server": "example.com", "server_port": 8388,
        "listen_address": "127.0.0.1", "listen_port": 1080,
        "password": "secret", "method": "aes-256-cfb",
        "protocol": "auth_aes128_sha1", "protocol_param": "",
        "obfs": "tls1.2_ticket_auth", "obfs_param": "",
        "udp": true, "idle_timeout": 300,
        "connect_timeout": 6, "udp_timeout": 6
    }"#;
    let config = config_from_json(json).expect("valid config");

    // 方式二：结构体字面量 —— 字段全公开，其余走 `Default`。
    let _config2 = SsrClientConfig {
        server: "example.com".into(),
        server_port: 8388,
        password: "secret".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::AuthAES128SHA1,
        obfs: ObfsType::TLS12TicketAuth,
        ..Default::default()
    };

    let client = SsrClient::new(config);
    client.start().await.expect("SOCKS5 listener + relay");
}
```

`SsrClient::new` 只保存配置：在调用 `start()`（模式 A）或
`open_session()`（模式 B）之前，不绑端口也不连服务器。

## 4. 集成模式

| | 模式 A —— 系统端口（默认） | 模式 B —— 数据管道 |
|---|---|---|
| API | `client.start()` | `client.open_session(target)` |
| 前端 | 绑定 `listen_address:listen_port`，处理 SOCKS5 + UDP ASSOCIATE | 无 —— 由你自己的前端协议接管 |
| 后端 | 内部处理 | 面向 `target` 的 `AsyncRead + AsyncWrite` 明文流 |
| 适用 | 给应用即插即用的本地代理 | 自定义 DNS、路由规则、直连/代理选择、传输中的字节中间件 |

两种模式共用同一个隧道构建器，线上字节完全一致。

### 模式 A —— SOCKS5 本地代理

`start()` 绑定本地端口，提供 SOCKS5 `CONNECT`，并在 `udp: true` 时
提供 `UDP ASSOCIATE`，直到调用 `stop()` 或进程退出。把任何支持 SOCKS5
的应用指向 `127.0.0.1:1080` 即可。

```rust,no_run
# use ssr_client_rs::{SsrClient, SsrClientConfig};
# async fn demo(client: SsrClient) -> ssr_client_rs::SsrResult<()> {
client.start().await?; // 绑定并服务，直到 stop()
// client.stop();      // 在另一个任务/句柄里调用
# Ok(())
# }
```

辅助访问器：`client.is_running()` 与 `client.config()`。

### 模式 B —— 数据管道

`open_session` 把一条经隧道的 TCP 连接作为纯明文流返回 —— 不绑任何
本地端口：

```rust,no_run
use ssr_client_rs::{CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let client = SsrClient::new(SsrClientConfig {
        server: "example.com".into(),
        server_port: 8388,
        password: "secret".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::AuthAES128SHA1,
        obfs: ObfsType::TLS12TicketAuth,
        ..Default::default()
    });

    // `Domain` 目标由 SSR 服务器代为解析（远程 DNS）；
    // `IPv4`/`IPv6` 目标可以是本地解析器的结果。
    let target = TargetAddr::Domain("example.com".into(), 443);
    let mut session = client.open_session(target).await.map_err(std::io::Error::other)?;

    // 明文字节 —— 可套任意 AsyncRead/AsyncWrite 中间件。
    session.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
    let mut reply = Vec::new();
    session.read_to_end(&mut reply).await?;
    session.finish().await.map_err(std::io::Error::other)?;
    Ok(())
}
```

会话生命周期：

- 读写携带的是目标连接的**明文**；封帧、加密、伪装在后台泵任务里进行。
- 可用 `tokio::io::split` 拆分，或套任意 `AsyncRead + AsyncWrite`
  中间件（日志、计量、TLS …）。
- `finish()` 优雅关闭（排空服务器侧并返回中途继传错误）；直接 drop
  则是中止式关闭。
- `open_session` 失败场景：服务器不可达 / 握手超时（`connect_timeout`）、
  cipher/protocol/obfs 构建失败 —— 全部以 `SsrError` 返回。

模式 A 的 SOCKS5 解析与 UDP ASSOCIATE 与模式 B 完全不重叠。

## 5. 配置参考

JSON 键名与 `SsrClientConfig` 字段一一对应（`config_from_json`，
参见 `ssr-n/src/config_json.c`）；可选的 `client_settings` 对象可以
覆盖 `server*` / `listen*` 条目。

| 字段 / JSON 键 | 类型 | 默认值（`new`） | 含义 |
|---|---|---|---|
| `server` | string | — | 远程 SSR 服务器主机/IP |
| `server_port` | u16 | — | 远程 SSR 服务器端口 |
| `listen_address` | string | `127.0.0.1` | 本地 SOCKS5 绑定地址（`::` = IPv6 双栈） |
| `listen_port` | u16 | `1080` | 本地 SOCKS5 绑定端口 |
| `password` | string | — | 加密密码 |
| `method` | `CipherType` | — | 加密方式名，如 `aes-256-cfb`（JSON 存名字，经 `from_name` 解析） |
| `protocol` | `ProtocolType` | — | 协议名，如 `auth_aes128_sha1`（缺省 → `Origin`） |
| `protocol_param` | string | `""` | 协议参数（`uid:key…`） |
| `obfs` | `ObfsType` | `Plain` | 伪装名，如 `tls1.2_ticket_auth`（JSON 存名字） |
| `obfs_param` | string | `""` | 伪装参数（host…）；留空 = 自动 |
| `udp` | bool | `false` | 启用 UDP ASSOCIATE 中继 |
| `idle_timeout` | u32 | `300` | 空闲 TCP 隧道回收秒数（`0` = 不回收） |
| `connect_timeout` | u32 | `6` | 连接 SSR 服务器超时（秒） |
| `udp_timeout` | u32 | `6` | UDP 会话空闲超时（秒） |

补充说明：

- `config_from_json` 返回 `Result<SsrClientConfig, String>`（JSON 解析/
  键错误是普通字符串）；其余入口一律返回 `SsrResult<T>`。
- 枚举字段接受 ssr-n 线上名字 —— 用代码构建配置时，自行用
  `CipherType::from_name` / `ProtocolType::from_name` /
  `ObfsType::from_name` 解析（见
  [examples/config_builder.rs](../examples/config_builder.rs)）。
- `SsrClientConfig` 实现 `Debug + Clone`，可用 `{:?}` 打印生效配置。

## 6. 支持的算法

最新完整 e2e 矩阵：[`tests/e2e/RESULTS.md`](../tests/e2e/RESULTS.md)
—— 对照参考 `ssr-n` 服务器 **39/51 PASS + 12 SKIP，0 FAIL**。

### 加密方式（28 个名字可解析，21 个已实现）

| 分组 | 方法 |
|---|---|
| AES 流加密 | `aes-128-cfb`、`aes-192-cfb`、`aes-256-cfb`、`aes-128-ctr`、`aes-192-ctr`、`aes-256-ctr` |
| AES AEAD | `aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm` |
| ChaCha/Salsa | `chacha20`、`chacha20-ietf`、`salsa20` |
| ChaCha AEAD | `chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305` |
| 经典 | `rc4`、`rc4-md5`、`rc4-md5-6`、`bf-cfb`、`des-cfb` |
| 其他 | `table`、`none` |
| 可解析、未实现 | `camellia-128/192/256-cfb`、`cast5-cfb`、`idea-cfb`、`rc2-cfb`、`seed-cfb` |

未实现的名字在环境构建时立即返回 `SsrError::InvalidCipherMethod`
—— 绝不静默降级。其中若干（`cast5`、`idea`、`rc2`、`seed`、
`des-cfb`）参考服务器本身也拒绝（C 客户端同样失败）。

### 协议（14 个）

`origin`、`verify_simple`、`auth_simple`、`auth_sha1`、`auth_sha1_v2`、
`auth_sha1_v4`、`auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a`、
`auth_chain_b`、`auth_chain_c`、`auth_chain_d`、`auth_chain_e`、
`auth_chain_f`。

`verify_simple`/`auth_simple`/`auth_sha1`/`auth_sha1_v2` 四个在 e2e 里
SKIP，只因参考服务器没有为它们注册 `server_post_decrypt`（C 客户端同样
失败）；客户端侧实现是齐全的。

### 伪装（6 个，全部 e2e 验证）

`plain`、`http_simple`、`http_post`、`http_mix`、`tls1.2_ticket_auth`、
`tls1.2_ticket_fastauth`。

### AEAD 降级规则

当 `method` 为 AEAD 加密时，线上隧道强制使用 `plain` 伪装 + `origin`
协议（与 `ssr_executive.c:175-179` 一致）；该连接上你设置的
`protocol`/`obfs` 不生效。这是设计行为，不是 bug。

## 7. 错误处理与超时

所有可能失败的入口统一返回 `SsrError`（`SsrResult<T> = Result<T,
SsrError>`），其实现了 `Display` + `std::error::Error`（经 `thiserror`）：

| 变体 | 触发场景 |
|---|---|
| `Io` | 底层 socket/文件 IO 失败（包装 `std::io::Error`，`#[from]`） |
| `InvalidCipherMethod` / `InvalidProtocol` / `InvalidObfs` | 未知或未实现的算法名 |
| `Crypto` | 加密/解密/密钥派生失败 |
| `Protocol` | SSR 协议握手或帧编解码失败 |
| `Obfs` | 伪装编解码或握手失败 |
| `Connection` | 监听/连接/收发/继传泵失败 |
| `Socks5` | 非法 SOCKS5 输入或不支持的命令/地址类型 |
| `Timeout` | 超过 `connect_timeout` / `idle_timeout` / 握手期限 |
| `InvalidArgument` | 调用方传值越界或未知 |
| `Other` | 其余一切 |

超时语义：

- `connect_timeout`（默认 6 秒）：拨号 SSR 服务器与 obfs 握手的期限。
- `idle_timeout`（默认 300 秒）：空闲 TCP 隧道在此秒数后回收；`0` 关闭回收。
- `udp_timeout`（默认 6 秒）：每 UDP 会话状态的过期时间。

需要区别处理时按变体 match（如 `Timeout`/`Connection` 重试、
`InvalidCipherMethod` 视为配置错误）：

```rust,no_run
use ssr_client_rs::{CipherType, SsrError};

match CipherType::from_name("nope") {
    Ok(_) => unreachable!(),
    Err(e @ SsrError::InvalidCipherMethod(_)) => eprintln!("配置错误: {e}"),
    Err(e) => eprintln!("其他: {e}"),
}
```

## 8. UDP 中继

SOCKS5 `UDP ASSOCIATE` 仅限**模式 A**，且需 `"udp": true`：

1. 配置里打开它（`udp: true`，默认 6 秒不合适就调 `udp_timeout`）。
2. 启动代理（`client.start()`）。
3. 应用的 SOCKS5 代理开启 UDP 支持；数据报经 SSR 服务器封装，按会话
   解复用，空闲状态在 `udp_timeout` 后清除。

UDP e2e 覆盖：`bash tools/e2e_udp.sh --all`（3/3 组合 PASS）。

## 9. 示例

| 示例 | 演示内容 | 运行 |
|---|---|---|
| [examples/socks5.rs](../examples/socks5.rs) | 模式 A：从 JSON 配置启动完整 SOCKS5 本地代理，Ctrl-C 优雅 `stop()` | `cargo run --release --example socks5 -- config.json` |
| [examples/open_session.rs](../examples/open_session.rs) | 模式 B：一条隧道连接当明文流用 —— 经隧道发 HTTP GET，优雅 `finish()` | `cargo run --release --example open_session -- config.json example.com 80` |
| [examples/config_builder.rs](../examples/config_builder.rs) | 两种方式构建配置、名字↔枚举解析、`SsrError` 展示 —— 离线可跑，无需服务器 | `cargo run --example config_builder` |

与 `socks5.rs` 相同入口也打包成二进制：

```bash
cargo run --release --bin ssr_client -- -c config.json
```

## 10. 性能

- 想再挤出最后几个百分点的加密吞吐，下游二进制可用
  `RUSTFLAGS="-C target-cpu=native"` 构建 —— 本库自身不锁定 CPU 特性。
- 微基准（4 个 criterion 目标）：

```bash
cargo bench -- --noplot
# 单独跑某个：
cargo bench --bench cipher_throughput -- --noplot
cargo bench --bench protocol_overhead -- --noplot
cargo bench --bench obfs_overhead -- --noplot
cargo bench --bench session_setup -- --noplot   # 每连接建立开销
```

- 实测数字 —— 加密吞吐、协议/伪装每包开销、建连开销、与 C 客户端
  正面对比、并发曲线 —— 全部在 [`BENCH.zh-CN.md`](../BENCH.zh-CN.md)
  （[English](../BENCH.md)），每张表都记录了日期、机器、主频与方法。

bench 使用的 release profile：`opt-level = 3`、`lto = "thin"`、
`codegen-units = 1`。

## 11. 测试

```bash
cargo test                                            # 单元 + 集成
python3 tools/matrix_test.py                          # e2e 矩阵（需要本地 ssr-server）
bash tools/e2e_udp.sh --all                           # UDP e2e
cargo test --test resilience -- --ignored             # 中断/超时/半关闭套件
bash tools/soak_test.sh                               # 10 分钟稳定性浸泡
bash tools/fd_leak_test.sh                            # fd 泄漏探针
cargo doc --no-deps                                   # 本地 API 文档（与 docs.rs 兼容）
```

CI（`.github/workflows/ci.yml`）跑四道门：fmt / clippy / test / release
构建，且 `[lints.rust] warnings = "deny"` —— 任何警告都算失败。

## 12. 常见问题

**Q: 怎么填连接参数？** 和 C 客户端一样三项：`method`、`protocol`
（+ `protocol_param`）、`obfs`（+ `obfs_param`）必须与服务器一致。
直接从服务器配置里抄。

**Q: AEAD 加密（`aes-256-gcm` …）好像忽略了我设的 protocol/obfs？**
不是 bug —— 见 [§6 AEAD 降级规则](#aead-降级规则)。

**Q: 可以不起本地 SOCKS5 端口吗？** 可以 —— 模式 B，
`open_session()`（§4）。

**Q: 主机名谁来解析？** `TargetAddr::Domain` → SSR 服务器解析
（远程 DNS，本地网络看不到 DNS 查询）；`TargetAddr::IPv4/IPv6` →
你的解析器已经算好的结果。

**Q: 会 panic 吗？** 生产路径不会；所有失败都是 `SsrError`。
`unwrap`/`panic!` 只出现在测试、bench 和示例里。

**Q: `start()` 报 "Address already in use"？** 别的进程占着
`listen_address:listen_port`。换 `listen_port` 或停掉旧代理。

**Q: 本地连上了但服务器踢掉连接？** 密码 / method / protocol / obfs
与服务器不一致，或服务器拒绝该加密方式（有些名字服务器端也拒 —— 见 §6）。

**Q: 许可证哪来的？** GPL-3.0-or-later：本库移植自 `ssr-n` C 客户端
（GPLv3+），上游许可证继续适用。

## 参见

- [README.zh-CN.md](../README.zh-CN.md) —— 快速上手 / [English](../README.md)
- [BENCH.zh-CN.md](../BENCH.zh-CN.md) —— 性能报告 / [English](../BENCH.md)
- [CHANGELOG.md](../CHANGELOG.md) —— 发布说明、兼容性承诺
- [tests/e2e/RESULTS.md](../tests/e2e/RESULTS.md) —— 完整 e2e 矩阵结果
- docs.rs 上的 API 文档（发布后可用）
