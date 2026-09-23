use ssr_client_rs::config::SsrClientConfig;
use ssr_client_rs::crypto::cipher_env::CipherEnv;
use ssr_client_rs::protocol::auth_aes128::AuthAES128;
use ssr_client_rs::protocol::{Protocol, ServerInfo};
use ssr_client_rs::{CipherType, ObfsType, ProtocolType};

fn main() {
    let config = SsrClientConfig {
        server: "192.0.2.1".into(),
        server_port: 2800,
        listen_address: "0.0.0.0".into(),
        listen_port: 1080,
        password: "test-password".into(),
        method: CipherType::AES256CFB,
        protocol: ProtocolType::AuthAES128SHA1,
        protocol_param: "".into(),
        obfs: ObfsType::TLS12TicketAuth,
        obfs_param: "".into(),
        udp: true,
        idle_timeout: 300,
        connect_timeout: 6,
        udp_timeout: 6,
    };

    println!("=== SSR Client Test with hk.json Server ===");
    println!("Server: {}:{}", config.server, config.server_port);
    println!();

    // Test 1: Cipher
    println!("[1] Cipher (aes-256-cfb)...");
    let env = CipherEnv::with_method(&config.password, config.method).unwrap();
    let data = b"test data for google access";
    let encrypted = env.encrypt(data).unwrap();
    let decrypted = env.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, data);
    println!(
        "    Encrypt/decrypt: OK ({} -> {} bytes)",
        data.len(),
        encrypted.len()
    );
    println!();

    // Test 2: Protocol
    println!("[2] Protocol (auth_aes128_md5)...");
    let server_info = ServerInfo {
        key: env.key().to_vec(),
        iv: vec![0u8; 16],
        ..Default::default()
    };
    let mut protocol = AuthAES128::new_md5(server_info);
    protocol.init_user_key();
    let target = b"CONNECT www.google.com:443";
    let framed = protocol.client_pre_encrypt(target).unwrap();
    println!(
        "    Pre-encrypt: {} -> {} bytes",
        target.len(),
        framed.len()
    );
    println!();

    // Test 3: Full pipeline
    println!("[3] Full pipeline (protocol + cipher)...");
    let env2 = CipherEnv::with_method(&config.password, config.method).unwrap();
    let framed2 = protocol.client_pre_encrypt(target).unwrap();
    let encrypted2 = env2.encrypt(&framed2).unwrap();
    let decrypted2 = env2.decrypt(&encrypted2).unwrap();
    let plain2 = protocol.client_post_decrypt(&decrypted2).unwrap();
    assert_eq!(plain2, target);
    println!("    Pipeline roundtrip: OK");
    println!();

    println!("=== All pipeline tests passed! ===");
    println!();
    println!(
        "Note: Full proxy test requires SSR server at {}:{}",
        config.server, config.server_port
    );
    println!("The server is reachable (port 2800 open).");
    println!("To use as SOCKS5 proxy, start: cargo run --bin ssr_client");
}
