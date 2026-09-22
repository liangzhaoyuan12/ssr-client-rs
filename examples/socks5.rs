//! A minimal SOCKS5 proxy built on this library.
//!
//! Run with a config:    `cargo run --example socks5 -- hk.json`
//! Or use built-in test defaults (hk.json values): `cargo run --example socks5`

use ssr_client_rs::{config_json::config_from_json, SsrClient, SsrClientConfig};

#[tokio::main]
async fn main() {
    // Load ssr-n style JSON if given, otherwise fall back to built-in test values.
    let config = match std::env::args().nth(1) {
        Some(path) => {
            let text = std::fs::read_to_string(&path).expect("read config");
            config_from_json(&text).expect("parse config")
        }
        None => SsrClientConfig::default_test(),
    };

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
