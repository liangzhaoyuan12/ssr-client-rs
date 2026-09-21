# SSR-CLIENT-RS 持久目标文档

> 本文档是 agent 的 7x24 持续工作指南。每次会话开始时，agent 应首先读取此文件，确认当前阶段和上次进度，然后从上次中断处继续工作。

---

## 项目概述

用 Rust 从零实现 SSR (ShadowsocksR) 客户端库，目标是完全兼容 ssr-n C 服务端，可作为其他项目（GTK4、Tauri 等）的依赖使用。

- **仓库**: `/home/liangzhaoyuan12/work/rs/ssr-client-rs`
- **服务端**: `/opt/ssr/ssr-server` (LoongArch64 ELF, 配置在 `/opt/ssr/config.json`)
- **参考实现**: `ssr-n/` 目录（C 源码）
- **迁移文档**: `MIGRATION.md`

---

## 反幻觉与反重复机制

**这是本文档最重要的部分。AI 模型长时间工作时容易产生幻觉和重复行为，必须严格执行以下规则：**

### 开始工作前（每次会话必须）

1. **读取 PROGRESS.md** — 确认上次完成到哪一步，从那里继续，不重做已完成的工作
2. **读取 GOALS.md 本文件** — 确认当前阶段编号和任务列表
3. **运行 `cargo test --list`** — 确认当前有多少测试，用数字而非记忆
4. **运行 `git log --oneline -5`** — 确认最近提交，不重复已提交的修复

### 工作中（每完成一个小任务必须）

1. **写 PROGRESS.md** — 每修一个 bug、每完成一个测试，立即更新进度文件，记录：日期时间、做了什么、涉及的文件和行号、测试结果
2. **不重复修复** — 如果 PROGRESS.md 记录了 "auth_sha1_v4 roundtrip 已修复"，不要再修它
3. **不凭记忆修改代码** — 修改任何文件前，必须先 `read_file` 读取当前内容，不凭记忆写代码
4. **不凭记忆声称通过** — 每次声称 "测试通过" 前，必须实际运行 `cargo test` 并看到输出
5. **不重复 commit** — 修改前先 `git log --oneline -3` 检查是否已提交

### 防止幻觉的硬性约束

- **不要修改已通过的测试** — 除非发现它们本身有 bug
- **不要凭空添加新模块** — 除非在本文档的任务列表中明确列出
- **不要声称 "已修复" 而没跑测试** — 必须有实际 `cargo test` 输出
- **不要重复同一个修复尝试** — 如果同一个修复尝试 3 次仍失败，在 PROGRESS.md 记录阻塞原因，跳到下一个任务
- **不要在一次会话中做太多事** — 一次会话专注 2-3 个明确任务，做完就更新进度

---

## 当前状态快照（截至 2026-09-21）

### 测试情况

- 单元测试: 122 passed, 0 failed
- hk_integration: 15 passed, 0 failed
- full_coverage: 41 passed, 5 failed (auth_sha1_v4 相关)
- **总计: 178 passed, 5 failed**
- 失败的 5 个测试全部是 auth_sha1_v4 的 roundtrip/pipeline 问题

### 已实现（可工作的，经真实服务器验证）

- **生产配置**: aes-256-cfb + auth_aes128_sha1 + tls1.2_ticket_auth — 真实服务器 192.0.2.1:2800 已验证通过（httpbin 200, github 200, google 204, 5MB 下载 4.52 MB/s）
- **流加密 (16/28)**: none, table, rc4, rc4-md5-6, rc4-md5, aes-128/192/256-cfb, aes-128/192/256-ctr, bf-cfb, des-cfb, salsa20, chacha20, chacha20-ietf
- **AEAD (5/28)**: aes-128/192/256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305 — 模块完成，端到端未互通（服务端二进制与源码 obfs 实现不一致）
- **协议 (12/14)**: origin, verify_simple, auth_simple, auth_sha1, auth_sha1_v2, auth_aes128_md5, auth_aes128_sha1, auth_chain_a~f
- **混淆 (5/6)**: plain, http_simple, http_post, http_mix, tls1.2_ticket_auth, tls1.2_ticket_fastauth
- SOCKS5 客户端, TCP 中继, JSON 配置解析

### 端到端测试矩阵（实测 16/37 通过，C 客户端 32/37）

- obfs: 5/5 通过 (plain, http_simple, http_post, http_mix, tls1.2_ticket_auth)
- protocol: 2/4 通过 (auth_aes128_sha1, auth_aes128_md5); auth_sha1_v4 和 auth_chain_a 未通
- cipher: 9/28 通过 (aes-128/192/256-cfb, aes-128/192/256-ctr, bf-cfb, salsa20, chacha20-ietf)

### 未实现（枚举有了但代码空缺）

| 加密方法 | 状态 | 备注 |
|-----------|------|------|
| camellia-128-cfb | 缺实现 | 需要 camellia crate 或手动实现 |
| camellia-192-cfb | 缺实现 | 同上 |
| camellia-256-cfb | 缺实现 | 同上 |
| cast5-cfb | 缺实现 | 服务端本身也不支持（C 客户端同样失败） |
| idea-cfb | 缺实现 | 同上 |
| rc2-cfb | 缺实现 | 同上 |
| seed-cfb | 缺实现 | 同上 |

### 已知 Bug

1. **auth_sha1_v4 roundtrip 失败** — `client_post_decrypt` 产出截断数据，5 个测试失败
2. **AEAD 端到端不通** — 模块测试通过，但服务端二进制的 obfs 实现与源码不一致，握手阶段断开
3. **auth_chain_a 端到端不通** — 协议级 roundtrip 通过但端到端连接失败

### 阻塞项

AEAD 端到端：服务端二进制 `/opt/ssr/ssr-server` 的 obfs 实现与源码 `ssr-n/src/` 不一致。
源码中 tls12_ticket_auth 生成标准 TLS ClientHello（0x16 03 01），但实际二进制在 AEAD 下产生非 TLS 格式数据（首字节 0x50）。
**需要获取服务端对应的源码版本或反编译 obfs 部分才能继续。**

---

## 工作阶段

### Phase 0: 修复已知 Bug（最高优先级）

**目标**: 让现有测试全部通过

**任务**:

- [ ] 0.1 修复 auth_sha1_v4 roundtrip bug
  - 文件: `src/protocol/auth_sha1_v4.rs`
  - 现象: `client_post_decrypt` 产出截断数据
  - 参考: `src/protocol/auth_sha1.rs` 和 `src/protocol/auth_sha1_v2.rs`（同族协议，roundtrip 通过）
  - 对比 C 源码 `ssr-n/src/auth_aes128.c` 和 `ssr-n/src/auth_sha1_v4.c`
  - 验证: `cargo test test_proto_auth_sha1_v4` 通过

- [ ] 0.2 运行完整测试套件确认无回归
  - `cargo test` — 全部 0 failures
  - `cargo test --test full_coverage` — 全部通过
  - `cargo test --test hk_integration` — 全部通过

### Phase 1: 本地服务端集成测试（hk.json）

**目标**: 用 `/opt/ssr/ssr-server` + `/opt/ssr/config.json` 验证客户端能连通

**任务**:

- [ ] 1.1 确认服务端可用性
  ```
  file /opt/ssr/ssr-server
  ss -tlnp | grep 2800
  cat /opt/ssr/config.json
  ```
  - 如果 2800 端口已被占用，可能是之前的测试实例，先 kill
  - 如果服务端配置的协议不是当前要测的，需要生成新配置

- [ ] 1.2 启动本地 SSR 服务端（用 hk.json 的配置）
  ```bash
  # 先杀掉可能残留的旧进程
  pkill -f "ssr-server" 2>/dev/null; sleep 0.5
  /opt/ssr/ssr-server -c /opt/ssr/config.json &
  ss -tlnp | grep 2800
  ```

- [ ] 1.3 用 hk.json 配置启动客户端
  ```bash
  cargo run --release --bin ssr_client -- -c hk.json &
  ss -tlnp | grep 1080
  ```

- [ ] 1.4 通过 SOCKS5 代理访问外部
  ```bash
  curl -x socks5://127.0.0.1:1080 http://httpbin.org/ip
  ```
  - 验证: 返回 JSON（公网 IP）

- [ ] 1.5 记录结果到 PROGRESS.md

### Phase 2: 全协议矩阵端到端测试

**目标**: 本机服务端 + 客户端，逐一测试所有加密方法、协议、混淆的组合

**测试矩阵**:

#### 2.1 加密方法矩阵

为每个加密方法生成一份配置文件，启动服务端，然后用客户端连接测试。

| 加密方法 | 需要服务端配置 | 测试方法 |
|-----------|---------------|----------|
| none | method: "none" | 客户端连通+数据传输 |
| table | method: "table" | 同上 |
| rc4 | method: "rc4" | 同上 |
| rc4-md5-6 | method: "rc4-md5-6" | 同上 |
| rc4-md5 | method: "rc4-md5" | 同上 |
| aes-128-cfb | method: "aes-128-cfb" | 同上 |
| aes-192-cfb | method: "aes-192-cfb" | 同上 |
| aes-256-cfb | method: "aes-256-cfb" | 同上 |
| aes-128-ctr | method: "aes-128-ctr" | 同上 |
| aes-192-ctr | method: "aes-192-ctr" | 同上 |
| aes-256-ctr | method: "aes-256-ctr" | 同上 |
| bf-cfb | method: "bf-cfb" | 同上 |
| des-cfb | method: "des-cfb" | 同上 |
| salsa20 | method: "salsa20" | 同上 |
| chacha20 | method: "chacha20" | 同上 |
| chacha20-ietf | method: "chacha20-ietf" | 同上 |
| aes-128-gcm | method: "aes-128-gcm" | 同上 (AEAD) |
| aes-192-gcm | method: "aes-192-gcm" | 同上 (AEAD) |
| aes-256-gcm | method: "aes-256-gcm" | 同上 (AEAD) |
| chacha20-ietf-poly1305 | method: "chacha20-ietf-poly1305" | 同上 (AEAD) |
| xchacha20-ietf-poly1305 | method: "xchacha20-ietf-poly1305" | 同上 (AEAD) |
| camellia-128-cfb | 需先实现 | 先实现再测试 |
| camellia-192-cfb | 需先实现 | 先实现再测试 |
| camellia-256-cfb | 需先实现 | 先实现再测试 |
| cast5-cfb | 需先实现 | 先实现再测试 |
| idea-cfb | 需先实现 | 先实现再测试 |
| rc2-cfb | 需先实现 | 先实现再测试 |
| seed-cfb | 需先实现 | 先实现再测试 |

#### 2.2 协议矩阵

在每个加密方法下测试协议（使用已实现的加密方法）：

| 协议 | 测试要点 |
|------|---------|
| origin | 纯加密，无协议帧 |
| verify_simple | HMAC 验证帧 |
| auth_simple | 简单认证帧 |
| auth_sha1 | SHA1 HMAC 认证 |
| auth_sha1_v2 | SHA1 HMAC v2 |
| auth_sha1_v4 | SHA1 HMAC v4 |
| auth_aes128_md5 | AES128 + MD5 认证 |
| auth_aes128_sha1 | AES128 + SHA1 认证 |
| auth_chain_a | 链式协议 a |
| auth_chain_b | 链式协议 b |
| auth_chain_c | 链式协议 c |
| auth_chain_d | 链式协议 d |
| auth_chain_e | 链式协议 e |
| auth_chain_f | 链式协议 f |

**测试方法**: 生成配置文件 → 启动服务端 → 客户端连接 → curl 通过代理 → 记录结果

#### 2.3 混淆矩阵

在每个协议+加密组合下测试混淆：

| 混淆 | 测试要点 |
|------|---------|
| plain | 无混淆 |
| http_simple | HTTP GET 伪装 |
| http_post | HTTP POST 伪装 |
| http_mix | 随机 GET/POST |
| tls1.2_ticket_auth | TLS ticket 认证（需握手） |
| tls1.2_ticket_fastauth | TLS ticket 快速认证 |

#### 2.4 实际执行方式

每个测试组合的执行流程：

```bash
# 1. 生成服务端配置
cat > /tmp/ssr_test_server.json << EOF
{
    "password": "test_password",
    "method": "<METHOD>",
    "protocol": "<PROTOCOL>",
    "protocol_param": "<PROTO_PARAM>",
    "obfs": "<OBS>",
    "obfs_param": "<OBFS_PARAM>",
    "udp": false,
    "idle_timeout": 30,
    "connect_timeout": 6,
    "udp_timeout": 6,
    "server_settings": {
        "listen_address": "127.0.0.1",
        "listen_port": 18388
    }
}
EOF

# 2. 生成客户端配置
cat > /tmp/ssr_test_client.json << EOF
{
    "password": "test_password",
    "method": "<METHOD>",
    "protocol": "<PROTOCOL>",
    "protocol_param": "<PROTO_PARAM>",
    "obfs": "<OBS>",
    "obfs_param": "<OBFS_PARAM>",
    "udp": false,
    "client_settings": {
        "server": "127.0.0.1",
        "server_port": 18388,
        "listen_address": "127.0.0.1",
        "listen_port": 18180
    }
}
EOF

# 3. 启动服务端
/opt/ssr/ssr-server -c /tmp/ssr_test_server.json &
SERVER_PID=$!
sleep 1

# 4. 启动客户端
cargo run --bin ssr_client -- -c /tmp/ssr_test_client.json &
CLIENT_PID=$!
sleep 1

# 5. 测试连通
RESULT=$(curl -x socks5://127.0.0.1:18180 --connect-timeout 5 http://httpbin.org/ip 2>/dev/null)
if echo "$RESULT" | grep -q "origin"; then
    echo "PASS: <METHOD>+<PROTOCOL>+<OBS>"
else
    echo "FAIL: <METHOD>+<PROTOCOL>+<OBS>"
fi

# 6. 清理
kill $CLIENT_PID $SERVER_PID 2>/dev/null
wait $CLIENT_PID $SERVER_PID 2>/dev/null
```

**注意**: 可能有些加密方法 ssr-n 服务端不支持（比如 camellia 如果服务端没编译进去）。对服务端不支持的方法，标记为 "服务端不支持，跳过"。

### Phase 3: 补全缺失的加密方法

> **优先级说明**: 7 个缺失加密方法中，camellia-128/192/256-cfb 值得实现（服务端支持），
> 而 cast5-cfb, idea-cfb, rc2-cfb, seed-cfb **服务端本身不支持**（C 客户端也失败），
> 实现这些的优先级低。优先做 camellia。

**目标**: 实现缺失的流加密方法，优先 camellia

**任务**:

- [ ] 3.1 实现 Camellia-CFB (128/192/256)
  - 查找 Rust camellia crate: `cargo search camellia`
  - 如果没有合适 crate，手动实现 Camellia 块密码 + cfb-mode
  - 修改文件: `src/crypto/stream.rs`, `src/crypto/cipher_env.rs`
  - 添加到 `stream_encrypt` / `stream_decrypt` / `make_encrypt_ctx` / `make_decrypt_ctx`

- [ ] 3.2 实现 CAST5-CFB
  - 查找 Rust cast5 crate
  - 同上模式

- [ ] 3.3 实现 IDEA-CFB
  - 需要手动实现 IDEA 块密码
  - 或找到 `idea` crate

- [ ] 3.4 实现 RC2-CFB
  - 需要手动实现 RC2 块密码

- [ ] 3.5 实现 Seed-CFB
  - 需要手动实现 SEED 块密码
  - 或找到 `seed` crate

- [ ] 3.6 每个实现完成后写单元测试
  - Roundtrip 测试: encrypt → decrypt = identity
  - 大数据测试: 16KB 数据 roundtrip
  - 添加到 `tests/full_coverage.rs`

- [ ] 3.7 运行 Phase 2 的矩阵测试验证

### Phase 4: AEAD 端到端互通

> **阻塞警告**: 当前被阻塞 — 服务端二进制的 obfs 实现与源码不一致。
> 此阶段在获取正确源码版本或反编译 obfs 部分之前无法推进。
> 如果此阻塞无法解除，此阶段可跳过，将 AEAD 标记为"模块完成但端到端未验证"。

**目标**: AEAD 加密模式（aes-128-gcm, aes-256-gcm 等）能真正连通服务端

**任务**:

- [ ] 4.1 对比客户端 AEAD 实现与 C 服务端的 wire format
  - 关键差异点: salt 传输、nonce 递增、chunk 分割
  - 参考: `ssr-n/src/aead.c`

- [ ] 4.2 检查 AEAD downgrade 逻辑
  - `local/mod.rs` 中 AEAD 模式强制使用 plain obfs + origin protocol
  - 确认服务端是否也这样处理

- [ ] 4.3 修复 AEAD 连通性
  - 逐字节对比客户端和服务端的加密输出
  - 用 `SSR_DEBUG=1` 抓 handshake 数据

- [ ] 4.4 AEAD 矩阵测试
  - aes-128-gcm + origin + plain
  - aes-256-gcm + origin + plain
  - chacha20-ietf-poly1305 + origin + plain
  - xchacha20-ietf-poly1305 + origin + plain

### Phase 5: 性能优化

**目标**: 达到可发布的性能水平

**任务**:

- [ ] 5.1 基准测试
  - 用 `criterion` crate 写 benchmark
  - 测试每种加密方法的 throughput (MB/s)
  - 测试协议层 pre_encrypt/post_decrypt 的 overhead
  - 测试 obfs encode/decode 的 overhead

- [ ] 5.2 热路径优化
  - `cipher_env.rs` 中的 encrypt/decrypt 是热路径
  - 检查是否有不必要的内存分配 (clone, to_vec)
  - 考虑使用 `bytes::BytesMut` 避免拷贝
  - 检查 `Vec<u8>` 分配是否可以用预分配或 buffer pool

- [ ] 5.3 连接池与复用
  - 评估是否需要连接复用
  - 如果需要，设计连接池

- [ ] 5.4 编译优化
  - 确认 release profile 配置合理
  - LTO, opt-level=3, codegen-units=1 等

### Phase 6: 遗漏检查与代码质量

**目标**: 代码达到可发布的质量水平

**任务**:

- [ ] 6.1 审查所有 error handling
  - 检查所有 `unwrap()` 和 `expect()` 是否合理
  - 确保错误传播链完整，不留 panic

- [ ] 6.2 审查边界条件
  - 空数据处理
  - 超大数据处理
  - 网络断开/超时处理
  - 端口范围 (0-65535)

- [ ] 6.3 审查协议层逻辑
  - 对比每个协议的 `client_pre_encrypt` / `client_post_decrypt` 与 C 源码
  - 特别关注 auth_chain_a~f 的差异
  - 检查 HMAC key 构建是否正确

- [ ] 6.4 审查混淆层逻辑
  - 对比每个 obfs 的 encode/decode 与 C 源码
  - 特别关注 tls1.2_ticket_auth 的 ClientHello 构建

- [ ] 6.5 添加文档注释
  - 所有 pub 函数/类型需要 doc comment
  - 复杂逻辑需要内联注释说明算法

- [ ] 6.6 检查 Cargo.toml
  - 移除未使用的依赖
  - 确认版本号合理
  - 添加 description, license, repository 等 metadata

### Phase 7: 最终验证

**目标**: 确认所有功能正确，性能达标，可发布

**任务**:

- [ ] 7.1 完整测试矩阵通过
  - 所有加密方法 × 所有协议 × 所有混淆的组合
  - 记录每个组合的通过/失败状态

- [ ] 7.2 长时间运行测试
  - 客户端连接后持续传输 10 分钟
  - 检查内存泄漏 (RSS 持续增长?)
  - 检查连接稳定性

- [ ] 7.3 异常场景测试
  - 服务端 kill -9 后客户端的行为
  - 客户端 kill -9 后服务端的行为
  - 网络中断后的重连
  - 并发连接测试

- [ ] 7.4 README 编写
  - 项目简介
  - 快速开始
  - API 文档
  - 配置说明
  - 已测试的组合列表

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

---

## 参考资源

- C 参考实现: `ssr-n/src/` 目录
- SSR 协议规范: 各协议的 C 实现是最权威的参考
- ssr-n 配置格式: `hk.json` 和 `/opt/ssr/config.json`
- 服务端帮助: `/opt/ssr/ssr-server -h`

---

## 停止条件

当以下所有条件满足时，项目可视为完成：

1. `cargo test` 全部通过（0 failures）
2. 所有 28 种加密方法的 roundtrip 测试通过
3. 所有 14 种协议的 roundtrip 测试通过
4. 所有 6 种混淆的 roundtrip 测试通过
5. 至少 hk.json 配置的端到端测试通过
6. AEAD 端到端测试通过
7. `cargo clippy` 无 warning
8. README 完成
9. benchmark 基准已建立
