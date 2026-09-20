/// Integration tests using hk.json server parameters.

use ssr_client_rs::config::SsrClientConfig;
use ssr_client_rs::crypto::cipher_env::CipherEnv;
use ssr_client_rs::protocol::auth_aes128::AuthAES128;
use ssr_client_rs::protocol::auth_sha1::AuthSHA1;
use ssr_client_rs::protocol::auth_sha1_v2::AuthSHA1V2;
use ssr_client_rs::protocol::auth_sha1_v4::AuthSHA1V4;
use ssr_client_rs::protocol::auth_simple::AuthSimple;
use ssr_client_rs::protocol::origin::Origin;
use ssr_client_rs::protocol::verify_simple::VerifySimple;
use ssr_client_rs::protocol::{Protocol, ServerInfo};
use ssr_client_rs::obfs::tls_ticket::Tls12TicketAuthObfs;
use ssr_client_rs::obfs::Obfs;

fn hk_config() -> SsrClientConfig {
    SsrClientConfig {
        server: "192.0.2.1".into(),
        server_port: 2800,
        listen_address: "0.0.0.0".into(),
        listen_port: 1080,
        password: "test-password".into(),
        method: "aes-256-cfb".into(),
        protocol: "auth_aes128_sha1".into(),
        protocol_param: "".into(),
        obfs: "tls1.2_ticket_auth".into(),
        obfs_param: "".into(),
        udp: true,
        idle_timeout: 300,
        connect_timeout: 6,
        udp_timeout: 6,
    }

}

fn server_info() -> ServerInfo {
    ServerInfo {
        key: vec![0x42u8; 16],
        iv: vec![0x24u8; 16],
        ..Default::default()
    }

}

#[test]
fn test_hk_config_parse() {
    let config = hk_config();
    assert_eq!(config.server, "192.0.2.1");
    assert_eq!(config.server_port, 2800);
    assert_eq!(config.password, "test-password");
    assert_eq!(config.method, "aes-256-cfb");
    assert_eq!(config.protocol, "auth_aes128_sha1");
    assert_eq!(config.obfs, "tls1.2_ticket_auth");

}

#[test]
fn test_hk_cipher_aes256_cfb() {
    let env = CipherEnv::new("test-password", "aes-256-cfb").unwrap();
    assert_eq!(env.key().len(), 32);
    assert_eq!(env.iv_len(), 16);
    let data = b"integration test data for hk server";
    let encrypted = env.encrypt(data).unwrap();
    assert_ne!(encrypted, data);
    let decrypted = env.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, data);

}

#[test]
fn test_hk_cipher_roundtrip_large() {
    let env = CipherEnv::new("test-password", "aes-256-cfb").unwrap();
    let data = vec![0xABu8; 8192];
    let encrypted = env.encrypt(&data).unwrap();
    let decrypted = env.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, data);

}

#[test]
fn test_hk_origin_pipeline() {
    let mut proto = Origin;
    let data = b"hello from hk client";
    let framed = proto.client_pre_encrypt(data).unwrap();
    assert_eq!(framed, data);
    let plain = proto.client_post_decrypt(&framed).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_verify_simple_pipeline() {
    let mut proto = VerifySimple::new();
    let data = b"verify simple test for hk";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let plain = proto.client_post_decrypt(&framed).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_auth_simple_pipeline() {
    let mut proto = AuthSimple::new();
    let data = b"auth simple test for hk server";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let plain = proto.client_post_decrypt(&framed).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_auth_sha1_pipeline() {
    let si = server_info();
    let mut proto = AuthSHA1::new(si);
    let data = b"auth sha1 test for hk server";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let plain = proto.client_post_decrypt(&framed).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_auth_sha1_v2_pipeline() {
    let si = server_info();
    let mut proto = AuthSHA1V2::new(si);
    let data = b"auth sha1 v2 test for hk";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let plain = proto.client_post_decrypt(&framed).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_auth_sha1_v4_pipeline() {
    let si = server_info();
    let mut proto = AuthSHA1V4::new(si);
    let data = b"auth sha1 v4 test for hk";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let plain = proto.client_post_decrypt(&framed).unwrap();
    assert_eq!(plain, data);

}

#[test]

#[test]
fn test_hk_tls_ticket_obfs() {
    let mut obfs = Tls12TicketAuthObfs::new("192.0.2.1".into(), 2800, "".into(), false);
    obfs.set_key(vec![0x42u8; 16]);
    let data = b"tls ticket auth test for hk";
    let encoded = obfs.client_encode(data).unwrap();
    let _decoded = obfs.client_decode(&encoded).unwrap();

}

#[test]
fn test_hk_full_encrypt_protocol_pipeline() {
    let mut proto = VerifySimple::new();
    let env = CipherEnv::new("test-password", "aes-256-cfb").unwrap();
    let data = b"full pipeline test for hk server";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let encrypted = env.encrypt(&framed).unwrap();
    assert_ne!(encrypted, data);
    let decrypted = env.decrypt(&encrypted).unwrap();
    let plain = proto.client_post_decrypt(&decrypted).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_auth_sha1_full_pipeline() {
    let si = server_info();
    let mut proto = AuthSHA1::new(si);
    let env = CipherEnv::new("test-password", "aes-256-cfb").unwrap();
    let data = b"auth sha1 full pipeline for hk";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let encrypted = env.encrypt(&framed).unwrap();
    let decrypted = env.decrypt(&encrypted).unwrap();
    let plain = proto.client_post_decrypt(&decrypted).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_auth_sha1_v4_full_pipeline() {
    let si = server_info();
    let mut proto = AuthSHA1V4::new(si);
    let env = CipherEnv::new("test-password", "aes-256-cfb").unwrap();
    let data = b"auth sha1 v4 full pipeline for hk";
    let framed = proto.client_pre_encrypt(data).unwrap();
    let encrypted = env.encrypt(&framed).unwrap();
    let decrypted = env.decrypt(&encrypted).unwrap();
    let plain = proto.client_post_decrypt(&decrypted).unwrap();
    assert_eq!(plain, data);

}

#[test]
fn test_hk_large_data_pipeline() {
    let si = server_info();
    let mut proto = AuthSHA1V4::new(si);
    let env = CipherEnv::new("test-password", "aes-256-cfb").unwrap();
    let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let framed = proto.client_pre_encrypt(&data).unwrap();
    let encrypted = env.encrypt(&framed).unwrap();
    let decrypted = env.decrypt(&encrypted).unwrap();
    let plain = proto.client_post_decrypt(&decrypted).unwrap();
    assert_eq!(plain, data);

}
