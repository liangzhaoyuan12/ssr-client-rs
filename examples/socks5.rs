//! A minimal SOCKS5 proxy built on this library (integration Mode A).
//! 基于本库的最小 SOCKS5 代理（集成模式 A）。
//!
//! Run with a config: `cargo run --release --example socks5 -- config.json`
//! 带配置运行：`cargo run --release --example socks5 -- config.json`

use ssr_client_rs::{config_json::config_from_json, SsrClient};

#[tokio::main]
async fn main() {
    // Load an ssr-n style JSON config; a path is required.
    let path = match std::env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("Usage: cargo run --example socks5 -- <config.json>");
            std::process::exit(1);
        }
    };
    let text = std::fs::read_to_string(&path).expect("read config");
    let config = config_from_json(&text).expect("parse config");

    let listen = format!("{}:{}", config.listen_address, config.listen_port);
    let server = format!("{}:{}", config.server, config.server_port);
    let client = SsrClient::new(config);
    let handle = client.clone();

    tokio::spawn(async move {
        if let Err(e) = handle.start().await {
            eprintln!("proxy error: {e}");
        }
    });

    eprintln!("SOCKS5 listening on {listen} -> SSR {server}");
    tokio::signal::ctrl_c().await.expect("wait for ctrl-c");
    client.stop();
}
