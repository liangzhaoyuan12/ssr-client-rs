//! P1: per-packet protocol overhead (ns/packet, 1440 B payload).
//!
//! * `pre/<name>`  — steady-state `client_pre_encrypt` (connection header
//!   already emitted by one warm-up call).
//! * `post/<name>` — steady-state `client_post_decrypt`; a producer instance
//!   frames packets inside the untimed `iter_batched` setup, the consumer
//!   (warmed by one header frame) strips them inside the timed routine.
//!
//! Results land in BENCH.md (GOALS P1).

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
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

const PAYLOAD: usize = 1440;

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

fn make(name: &str) -> Box<dyn Protocol> {
    let mut p: Box<dyn Protocol> = match name {
        "origin" | "" => Box::new(Origin),
        "verify_simple" => Box::new(VerifySimple::new()),
        "auth_simple" => Box::new(AuthSimple::new()),
        "auth_sha1" => Box::new(AuthSHA1::new(si(name))),
        "auth_sha1_v2" => Box::new(AuthSHA1V2::new(si(name))),
        "auth_sha1_v4" => Box::new(AuthSHA1V4::new(si(name))),
        // AuthAES128 does not override the trait's default no-op
        // `init_user_key`, so calling it through `Box<dyn Protocol>` (as
        // `make()` did below) does nothing; a receive-only instance would
        // keep an empty user_key and every frame HMAC would mismatch.
        // Call the inherent method on the concrete type before boxing —
        // in production the pack path triggers the same inherent call.
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

fn bench_protocol_overhead(c: &mut Criterion) {
    let data = vec![0xABu8; PAYLOAD];
    let mut group = c.benchmark_group("protocol_overhead");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));
    group.warm_up_time(Duration::from_millis(300));

    for &name in PROTOCOLS {
        // Steady-state pre_encrypt: emit the connection header once.
        let mut proto = make(name);
        let _warm = proto.client_pre_encrypt(&data).unwrap();
        group.bench_function(format!("pre/{name}"), |b| {
            b.iter(|| black_box(proto.client_pre_encrypt(black_box(&data)).unwrap()))
        });

        // auth_chain_* has NO client-side self-loop: pre walks the client
        // hash chain, post walks the server hash chain, and only a real
        // server (ssr-n server_pre_encrypt) can produce frames post accepts —
        // probe-verified: even same-instance pre->post fails from frame 1.
        // The C client faces the same limitation (e2e covers the real
        // direction instead), so post is measured pre-only for chains.
        if name.starts_with("auth_chain_") {
            continue;
        }

        // Steady-state post_decrypt on ONE instance (frame generation kept
        // out of the timed routine by iter_batched).  Same-instance feeding
        // mirrors `full_coverage::test_protocol_roundtrip`: pack_auth_data
        // writes BOTH chain hashes, so client pre -> post stays in lockstep.
        // Cross-instance feeding cannot work — the receive side derives its
        // XOR/HMAC/RC4 state from hashes only the sender ever computed.
        // Warm with frames <= 1200 B: the first frame is header-only (an
        // auth_aes128/chain client post of its own auth header is not the
        // server's direction — it errors by design and clears the buffer),
        // the second is the first data frame with matching pack/recv ids.
        let warm = vec![0xABu8; 100];
        let mut proto = make(name);
        let _hdr = proto.client_pre_encrypt(&warm).unwrap();
        let _ = proto.client_post_decrypt(&_hdr);
        let _d1 = proto.client_pre_encrypt(&warm).unwrap();
        proto.client_post_decrypt(&_d1).unwrap();
        let cell = std::cell::RefCell::new(proto);
        group.bench_function(format!("post/{name}"), |b| {
            b.iter_batched(
                || cell.borrow_mut().client_pre_encrypt(&data).unwrap(),
                |framed| {
                    black_box(
                        cell.borrow_mut()
                            .client_post_decrypt(black_box(&framed))
                            .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, bench_protocol_overhead);
criterion_main!(benches);
