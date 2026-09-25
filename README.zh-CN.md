# ssr-client-rs

[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-blue.svg)](https://blog.rust-lang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86__64%20%7C%20loongarch64-lightgrey.svg)](#构建)
[![Crates.io](https://img.shields.io/crates/v/ssr-client-rs.svg)](https://crates.io/crates/ssr-client-rs)
[![docs.rs](https://docs.rs/crates/ssr-client-rs/badge.svg)](https://docs.rs/ssr-client-rs)

[English](README.md) | **简体中文**

ShadowsocksR（SSR-N）协议的字节级兼容 Rust 客户端库，提供加密、协议、
伪装与传输层，以及 SOCKS5 本地代理。对照参考实现 `ssr-n` C 服务器完成
验证。

完整使用文档：[`docs/USAGE.zh-CN.md`](docs/USAGE.zh-CN.md)
（[English](docs/USAGE.md)）

## 特性

- **28 个加密方式名，已实现 21 个**（见[支持矩阵](#支持矩阵)）
- **14 种协议** —— origin、verify_simple、auth_simple、auth_sha1/v2/v4、
  auth_aes128_md5/sha1、auth_chain_a–f
- **6 种伪装** —— plain、http_simple/post/mix、
  tls1.2_ticket_auth/fastauth（六种全部 e2e 验证）
- **TCP + UDP 中继**（SOCKS5 CONNECT 与 UDP ASSOCIATE）
- **基于 Tokio 的异步 I/O**，零 `unsafe`，生产路径零 panic
- **兼容 ssr-n JSON 配置**（`server`、`listen_port` … 键名，见
  [配置](#配置)）

```
用户数据 → SOCKS5 → 协议 (pre_encrypt) → 加密 (encrypt) → 伪装 (encode) → 服务器
服务器   → 伪装 (decode) → 解密 (decrypt) → 协议 (post_decrypt) → 用户
```

## 支持矩阵

最新完整矩阵见 [`tests/e2e/RESULTS.md`](tests/e2e/RESULTS.md)
（对照 `/opt/ssr/ssr-server`：**39/51 PASS + 12 SKIP，0 FAIL**）：

| 维度 | 结果 | SKIP 原因 |
|---|---|---|
| cipher（28） | **20 PASS** | camellia×3：客户端未实现；cast5/idea/rc2/seed/des-cfb：服务器本身拒绝（C 客户端同样失败） |
| protocol（14） | **10 PASS** | verify_simple/auth_simple/auth_sha1/v2 —— 服务器未注册 `server_post_decrypt`（C 客户端同样失败） |
| obfs（6） | **6 PASS** | —— |
| UDP（3 组合） | **3 PASS** | —— |

实测吞吐与每包开销见 [`BENCH.zh-CN.md`](BENCH.zh-CN.md)
（[English](BENCH.md)）：与 C 客户端正面对比 **吞吐 106.5%、CPU 0.77×**，
附并发曲线与 cipher/protocol/obfs/建连开销各表。

## 快速开始

### 作为库使用

```toml
[dependencies]
ssr-client-rs = "0.1"
tokio = { version = "1", features = ["full"] }
```

如需跟踪 git 版本：`ssr-client-rs = { git = "https://cnb.cool/liangzhaoyuan12/ssr-client-rs" }`。
详见 [`docs/USAGE.zh-CN.md`](docs/USAGE.zh-CN.md) §2。

```rust,no_run
use ssr_client_rs::config_json::config_from_json;
use ssr_client_rs::{CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig};

#[tokio::main]
async fn main() {
    // 方式 A：加载 ssr-n 风格 JSON 配置（键名即结构体字段）。
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

    // 方式 B：直接写结构体字面量（字段全公开，只填关心的，
    // 其余走 Default）。
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

### 两种集成模式

| | 模式 A —— 系统端口（默认） | 模式 B —— 数据管道 |
|---|---|---|
| API | `client.start()` | `client.open_session(target)` |
| 前端 | 绑定 `listen_address:listen_port`，处理 SOCKS5 + UDP ASSOCIATE | 无 —— 由你自己的前端协议接管 |
| 后端 | 内部处理 | 面向 `target` 的 `AsyncRead + AsyncWrite` 明文流 |
| 适用 | 给应用即插即用的本地代理 | 自定义 DNS、路由规则、直连/代理选择、传输中的字节中间件 |

两种模式共用同一个隧道构建器，线上字节完全一致。模式 B 示例：

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

    // 前端逐连接决定路由：`Domain` 目标由 SSR 服务器解析（远程 DNS）；
    // `IPv4`/`IPv6` 目标可以是本地解析器的结果。直连（不走代理）时
    // 完全跳过 `open_session` 即可。
    let target = TargetAddr::Domain("example.com".into(), 443);
    let mut session = client.open_session(target).await.map_err(std::io::Error::other)?;

    // 这里读写的是目标连接的明文 —— 可套任意 AsyncRead/AsyncWrite
    // 中间件来检查或修改它们。
    session.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
    let mut reply = Vec::new();
    session.read_to_end(&mut reply).await?;
    session.finish().await.map_err(std::io::Error::other)?;
    Ok(())
}
```

模式 A（`start()`）会绑定端口，因此与 `open_session` 的失败场景、
SOCKS5 路径互不重叠；UDP ASSOCIATE 仅限模式 A。

### 可运行示例

| 示例 | 演示内容 | 运行 |
|---|---|---|
| [`examples/socks5.rs`](examples/socks5.rs) | 模式 A：从 JSON 配置启动 SOCKS5 代理 | `cargo run --release --example socks5 -- config.json` |
| [`examples/open_session.rs`](examples/open_session.rs) | 模式 B：隧道连接当明文流用 | `cargo run --release --example open_session -- config.json example.com 80` |
| [`examples/config_builder.rs`](examples/config_builder.rs) | 两种方式构建配置、名字解析、错误展示（离线可跑） | `cargo run --example config_builder` |

`socks5` 同一入口也打包成二进制：`ssr-client -c <config.json>`
（`src/bin/ssr_client.rs`）。

## 配置

逐字段完整参考（含 FAQ 与错误处理）：
[`docs/USAGE.zh-CN.md`](docs/USAGE.zh-CN.md) §5 —— 英文版
[`docs/USAGE.md`](docs/USAGE.md) §5。

JSON 键名与 `SsrClientConfig` 字段一一对应（`config_from_json`，参见
上游 `ssr-n` 的 `src/config_json.c`）；可选的 `client_settings` 对象可以覆盖
`server*` / `listen*` 条目。

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

所有可能失败的入口统一返回 `SsrError` 类型（`SsrResult<T>`）；
库在生产路径上绝不 panic（由 `tools/check_panic_paths.sh` 强制检查）。

## 构建

```bash
cargo build --release     # [lints.rust] warnings = "deny"：任何警告都导致构建失败
```

- **MSRV：1.82**（`Cargo.toml` 的 `rust-version`）
- 已在 **linux x86_64**（CI）与 **linux loongarch64**（Loongson 3A5000）实测
- CI 跑四道门 —— fmt / clippy / test / release ——
  见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

想再挤出最后几个百分点的加密吞吐，下游二进制可用
`RUSTFLAGS="-C target-cpu=native"` 构建 —— 本库自身不锁定 CPU 特性。

## 测试

```bash
cargo test                                            # 单元 + 集成
python3 tools/matrix_test.py                          # e2e 矩阵（需要本地 ssr-server）
bash tools/e2e_udp.sh --all                           # UDP e2e
cargo test --test resilience -- --ignored             # 中断/超时/半关闭套件
bash tools/soak_test.sh                               # 10 分钟稳定性浸泡
cargo bench                                           # criterion 基线（见 BENCH.zh-CN.md）
```

## 项目结构

```
src/
├── lib.rs              # 公共 API 入口（模块图、再导出）
├── config.rs           # SsrClientConfig
├── config_json.rs      # ssr-n JSON 配置解析
├── error.rs            # SsrError 统一错误类型
├── crypto/             # 加密（cipher_env、stream、aead、table、bytes_to_key）
├── protocol/           # 协议（origin … auth_chain_a~f）
├── obfs/               # 伪装（plain、http_simple、tls_ticket）
├── socks5/             # SOCKS5 协议解析
├── relay/              # TCP 中继
├── local/              # 本地代理服务 + UDP 中继
└── utils/              # hash、base64、crc32、adler32、sockaddr
benches/                # criterion：加密吞吐、协议/伪装开销、建连开销
examples/               # socks5 / open_session / config_builder
tools/                  # e2e 矩阵、浸泡、fd 探针、与 C 客户端对比的基准
tests/                  # 全覆盖、proptest、resilience、e2e 资产
```

## 性能

见 [`BENCH.zh-CN.md`](BENCH.zh-CN.md)（[English](BENCH.md)）：加密吞吐、
协议/伪装每包开销、建连开销、与 C 客户端正面对比、并发曲线
（1/8/64/100 流）—— 每张表都记录日期、机器、主频与方法。

## 许可证

[GPL-3.0-or-later](LICENSE) —— 本库移植自 `ssr-n` C 客户端
（GPLv3，“version 3 or any later version”）；上游许可证继续适用。
发布说明与已知限制见 [CHANGELOG.md](CHANGELOG.md)，
完整使用指南见 [docs/USAGE.zh-CN.md](docs/USAGE.zh-CN.md)
（[English](docs/USAGE.md)）。
