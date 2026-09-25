//! Integration Mode B — the data pipe: one tunneled TCP connection exposed
//! as a plain `AsyncRead + AsyncWrite` plaintext stream.
//! 集成模式 B —— 数据管道：把一条经 SSR 隧道的 TCP 连接当作普通明文流来读写。
//!
//! Needs an SSR server reachable from the config.
//! 需要配置里的 SSR 服务器可达。
//!
//! Run: `cargo run --release --example open_session -- config.json example.com 80`
//! 运行：`cargo run --release --example open_session -- config.json example.com 80`

use ssr_client_rs::{config_json::config_from_json, SsrClient, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // <config.json> <host> [port] — defaults to plain HTTP port 80.
    // <配置文件> <主机> [端口] —— 默认明文 HTTP 80 端口。
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(host)) = (args.next(), args.next()) else {
        eprintln!("Usage: cargo run --example open_session -- <config.json> <host> [port]");
        std::process::exit(1);
    };
    let port: u16 = match args.next() {
        Some(p) => p.parse().expect("port must be a number"),
        None => 80,
    };

    let text = std::fs::read_to_string(&path).expect("read config");
    let config = config_from_json(&text).expect("parse config");
    let client = SsrClient::new(config);

    // A `Domain` target is resolved by the SSR server (remote DNS); pass an
    // `IPv4`/`IPv6` target instead when your own resolver already decided.
    // `Domain` 目标由 SSR 服务器代为解析（远程 DNS）；
    // 若本地已解析好，可改传 `IPv4`/`IPv6` 目标。
    let target = TargetAddr::Domain(host.clone(), port);
    let mut session = client
        .open_session(target)
        .await
        .map_err(std::io::Error::other)?;

    // Bytes read/written here are the target connection's plaintext —
    // wrap the session in any AsyncRead/AsyncWrite middleware as needed.
    // 这里读写的都是目标连接的明文，可按需套任意 AsyncRead/AsyncWrite 中间件。
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    session.write_all(request.as_bytes()).await?;

    let mut reply = Vec::new();
    session.read_to_end(&mut reply).await?;
    print!("{}", String::from_utf8_lossy(&reply));

    // Graceful close: drains the server side and surfaces any mid-stream
    // relay error (dropping the session would abort instead).
    // 优雅关闭：排空服务器侧并抛出中途继传出错（直接 drop 会是中止式关闭）。
    session.finish().await.map_err(std::io::Error::other)?;
    Ok(())
}
