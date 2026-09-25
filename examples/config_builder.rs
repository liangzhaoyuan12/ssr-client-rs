//! Build the configuration two ways and inspect what the client will use —
//! no network, safe to run anywhere.
//! 两种方式构建配置并查看客户端实际生效值 —— 不碰网络，任何机器都能跑。
//!
//! Run: `cargo run --example config_builder`
//! 运行：`cargo run --example config_builder`

use ssr_client_rs::{
    config_json::config_from_json, CipherType, ObfsType, ProtocolType, SsrClient, SsrClientConfig,
};

fn main() {
    // Way 1: an ssr-n style JSON config (keys match the struct fields;
    // see docs/USAGE.md for the full table).
    // 方式一：ssr-n 风格 JSON 配置（键名即结构体字段，全表见 docs/USAGE.md）。
    let json = r#"{
        "server": "example.com", "server_port": 8388,
        "listen_address": "127.0.0.1", "listen_port": 1080,
        "password": "secret", "method": "aes-256-gcm",
        "protocol": "auth_aes128_sha1", "protocol_param": "",
        "obfs": "tls1.2_ticket_auth", "obfs_param": "",
        "udp": true, "idle_timeout": 300,
        "connect_timeout": 6, "udp_timeout": 6
    }"#;
    let from_json = match config_from_json(json) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("bad config: {e}");
            std::process::exit(1);
        }
    };
    println!("[json ] {from_json:?}\n");

    // Way 2: a struct literal — every field is public, fill in what you
    // care about, the rest comes from `Default`.
    // 方式二：结构体字面量 —— 字段全公开，只填关心的，其余走 `Default`。
    let built = SsrClientConfig {
        server: "example.com".into(),
        server_port: 8388,
        password: "secret".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::AuthAES128SHA1,
        obfs: ObfsType::TLS12TicketAuth,
        ..Default::default()
    };
    println!("[built] {built:?}\n");

    // What JSON parsing does internally: names <-> enum variants.
    // JSON 解析内部做的就是名字 <-> 枚举变体的转换。
    println!(
        "aes-256-gcm   -> {:?}",
        CipherType::from_name("aes-256-gcm")
    );
    println!(
        "auth_chain_a  -> {:?}",
        ProtocolType::from_name("auth_chain_a")
    );
    println!("http_simple   -> {:?}", ObfsType::from_name("http_simple"));

    // Every fallible entry point returns the single `SsrError` type,
    // which implements `Display` — here: an unknown cipher name.
    // 所有可能失败的入口统一返回实现了 `Display` 的 `SsrError`：
    if let Err(e) = CipherType::from_name("no-such-cipher") {
        println!("bad cipher    -> {e}");
    }

    // `SsrClient::new` only stores the config — nothing is bound or
    // connected until `start()` (Mode A) or `open_session()` (Mode B).
    // `SsrClient::new` 只保存配置 —— `start()`（模式 A）/
    // `open_session()`（模式 B）之前不绑端口也不连服务器。
    let client = SsrClient::new(from_json);
    println!("\neffective config: {:?}", client.config());
}
