use ssr_client_rs::config::SsrClientConfig;
use ssr_client_rs::local::SsrClient;
use tokio::signal;

#[tokio::main]
async fn main() {
    let config = SsrClientConfig {
        server: "127.0.0.1".to_string(),
        server_port: 18388,
        listen_address: "127.0.0.1".to_string(),
        listen_port: 18900,
        password: "test-password".to_string(),
        method: "aes-256-cfb".to_string(),
        protocol: "auth_aes128_sha1".to_string(),
        protocol_param: String::new(),
        obfs: "tls1.2_ticket_auth".to_string(),
        obfs_param: String::new(),
        udp: false,
        idle_timeout: 300,
        connect_timeout: 6,
        udp_timeout: 6,
    };

    let client = SsrClient::new(config);
    let client_ref = client.clone();

    tokio::spawn(async move {
        if let Err(e) = client.start().await {
            eprintln!("Error: {e}");
        }
    });

    eprintln!("SSR client listening on 127.0.0.1:18900");
    signal::ctrl_c().await.ok();
    client_ref.stop();
}
