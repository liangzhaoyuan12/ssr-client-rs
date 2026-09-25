//! Session-setup cost: everything `establish_tunnel` + `assemble` do for
//! every NEW connection, minus the TCP connect itself (µs/connection).
//! 建连开销：`establish_tunnel` + `assemble` 为每条**新连接**做的事，
//! 不含 TCP 连接本身（微秒/连接）。
//!
//! * `env/{method}` — `CipherEnv::with_method` (bytes_to_key KDF, per
//!   connection: src/local/mod.rs:609)
//! * `encrypt_ctx/{method}` — `create_encrypt_ctx` (random IV + context,
//!   src/local/mod.rs:214)
//! * `protocol_first/{name}` — fresh protocol + `set_server_iv` + first
//!   `client_pre_encrypt` (connection header emitted inside the timed
//!   routine)
//! * `obfs_first/{name}` — fresh obfs + `set_key` + first
//!   `client_encode` (HTTP header / TLS ClientHello emitted)
//!
//! Results land in BENCH.md (GOAL Phase 2).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssr_client_rs::crypto::cipher_env::CipherEnv;
use ssr_client_rs::crypto::ObfsType;
use ssr_client_rs::obfs::{create_obfs, Obfs};
use ssr_client_rs::protocol::auth_aes128::AuthAES128;
use ssr_client_rs::protocol::auth_chain::{
    AuthChainA, AuthChainB, AuthChainC, AuthChainD, AuthChainE, AuthChainF,
};
use ssr_client_rs::protocol::auth_sha1::AuthSHA1;
use ssr_client_rs::protocol::auth_sha1_v2::AuthSHA1V2;
use ssr_client_rs::protocol::auth_sha1_v4::AuthSHA1V4;
use ssr_client_rs::protocol::auth_simple::AuthSimple;
use ssr_client_rs::protocol::origin::Origin;
use ssr_client_rs::protocol::verify_simple::VerifySimple;
use ssr_client_rs::protocol::{Protocol, ServerInfo};
use std::time::Duration;

const PASSWORD: &str = "bench-password";
const HOST: &str = "bench.example.com";

/// First-packet payload: the SSR address package (ATYP + domain + port).
const FIRST_PAYLOAD: usize = 1 + 17 + 2;

/// Every method name accepted by `CipherEnv::new` (ssr_cipher_names.h).
const METHODS: &[&str] = &[
    "none",
    "table",
    "rc4",
    "rc4-md5-6",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
];

/// Protocol names accepted by `create_protocol` (src/local/mod.rs).
const PROTOCOLS: &[&str] = &[
    "origin",
    "verify_simple",
    "auth_simple",
    "auth_sha1",
    "auth_sha1_v2",
    "auth_sha1_v4",
    "auth_aes128_md5",
    "auth_aes128_sha1",
    "auth_chain_a",
    "auth_chain_b",
    "auth_chain_c",
    "auth_chain_d",
    "auth_chain_e",
    "auth_chain_f",
];

/// Obfs names accepted by `create_obfs`.
const OBFS: &[&str] = &[
    "plain",
    "http_simple",
    "http_post",
    "http_mix",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];

/// Mirror of the `ServerInfo` setup in `create_protocol`.
fn si(name: &str) -> ServerInfo {
    let mut srv = ServerInfo {
        key: vec![0x42u8; 16],
        iv: vec![0x24u8; 16],
        ..Default::default()
    };
    if name.starts_with("auth_chain_") {
        srv.overhead = 4;
    }
    srv
}

/// Fresh protocol instance exactly as `create_protocol` builds one.
fn make(name: &str) -> Box<dyn Protocol> {
    let mut p: Box<dyn Protocol> = match name {
        "origin" | "" => Box::new(Origin),
        "verify_simple" => Box::new(VerifySimple::new()),
        "auth_simple" => Box::new(AuthSimple::new()),
        "auth_sha1" => Box::new(AuthSHA1::new(si(name))),
        "auth_sha1_v2" => Box::new(AuthSHA1V2::new(si(name))),
        "auth_sha1_v4" => Box::new(AuthSHA1V4::new(si(name))),
        // AuthAES128 does not override the trait's default no-op
        // `init_user_key`; call the inherent method before boxing (the
        // pack path in production does the same).
        "auth_aes128_md5" => {
            let mut a = AuthAES128::new_md5(si(name));
            a.init_user_key();
            Box::new(a)
        }
        "auth_aes128_sha1" => {
            let mut a = AuthAES128::new_sha1(si(name));
            a.init_user_key();
            Box::new(a)
        }
        "auth_chain_a" => Box::new(AuthChainA::new(si(name), "auth_chain_a")),
        "auth_chain_b" => Box::new(AuthChainB::new(si(name))),
        "auth_chain_c" => Box::new(AuthChainC::new(si(name))),
        "auth_chain_d" => Box::new(AuthChainD::new(si(name))),
        "auth_chain_e" => Box::new(AuthChainE::new(si(name))),
        "auth_chain_f" => Box::new(AuthChainF::new(si(name), "")),
        other => panic!("unknown protocol {other}"),
    };
    p.init_user_key();
    p
}

fn bench_session_setup(c: &mut Criterion) {
    let payload = vec![0xABu8; FIRST_PAYLOAD];
    let mut group = c.benchmark_group("session_setup");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));
    group.warm_up_time(Duration::from_millis(300));

    // 1. Per-connection cipher environment: KDF runs on every connection.
    //    Unsupported methods (camellia, cast5, idea, rc2, seed) are skipped
    //    by `CipherEnv::new`, as in cipher_throughput.
    //    每连接重建 cipher 环境：KDF 每连接都跑；不支持的方法直接跳过。
    for &method in METHODS {
        if CipherEnv::new(PASSWORD, method).is_err() {
            continue;
        }
        group.bench_function(format!("env/{method}"), |b| {
            b.iter(|| black_box(CipherEnv::new(PASSWORD, method).unwrap()))
        });
    }

    // 2. Per-connection encrypt context: random IV/salt + context build.
    //    每连接的加密上下文：随机 IV/salt + 上下文构建。
    for &method in METHODS {
        let Ok(env) = CipherEnv::new(PASSWORD, method) else {
            continue;
        };
        // Unsupported underlying ciphers (camellia, cast5, idea, rc2, seed)
        // parse fine but fail at context creation — skip like cipher_throughput.
        if env.create_encrypt_ctx().is_err() {
            continue;
        }
        group.bench_function(format!("encrypt_ctx/{method}"), |b| {
            b.iter(|| black_box(env.create_encrypt_ctx().unwrap()))
        });
    }

    // 3. Fresh protocol + first pre_encrypt (connection header included),
    //    with the per-connection set_server_iv assemble() performs.
    //    全新协议实例 + 首包 pre_encrypt（含连接头），含 assemble 的 set_server_iv。
    let iv = CipherEnv::new(PASSWORD, "aes-256-cfb")
        .unwrap()
        .create_encrypt_ctx()
        .unwrap()
        .1;
    for &name in PROTOCOLS {
        group.bench_function(format!("protocol_first/{name}"), |b| {
            b.iter(|| {
                let mut proto = make(name);
                proto.set_server_iv(black_box(iv.clone()));
                black_box(proto.client_pre_encrypt(black_box(&payload)).unwrap())
            })
        });
    }

    // 4. Fresh obfs + first encode: HTTP header / TLS ClientHello emitted
    //    inside the timed routine; `plain` is stateless.
    //    全新 obfs + 首次编码：HTTP 头 / TLS ClientHello 在计时内发出；plain 无状态。
    let obfs_key = CipherEnv::new(PASSWORD, "aes-256-cfb")
        .unwrap()
        .key()
        .to_vec();
    for &name in OBFS {
        group.bench_function(format!("obfs_first/{name}"), |b| {
            b.iter(|| {
                let mut obfs: Box<dyn Obfs> =
                    create_obfs(ObfsType::from_name(name).unwrap(), HOST, 443, "");
                obfs.set_key(black_box(obfs_key.clone()));
                black_box(obfs.client_encode(black_box(&payload[..8])).unwrap())
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_session_setup);
criterion_main!(benches);
