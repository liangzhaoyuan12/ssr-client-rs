//! P1: per-cipher encrypt/decrypt throughput (1 MiB buffer), MB/s.
//!
//! * encrypt — steady-state streaming with a persistent context (TCP
//!   reality: IV/salt negotiated once, keystream advances across calls).
//! * decrypt — one fresh context per iteration built from the wire bytes
//!   (per-packet reality: IV/salt split + context setup included).
//!
//! Results land in BENCH.md (GOALS P1).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ssr_client_rs::crypto::cipher_env::CipherEnv;
use std::time::Duration;

const PAYLOAD: usize = 1 << 20; // 1 MiB
const PASSWORD: &str = "bench-password";

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

fn bench_cipher_throughput(c: &mut Criterion) {
    let plaintext = vec![0xA5u8; PAYLOAD];
    let mut group = c.benchmark_group("cipher_throughput");
    group.throughput(Throughput::Bytes(PAYLOAD as u64));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));
    group.warm_up_time(Duration::from_millis(300));

    for method in METHODS {
        let env = match CipherEnv::new(PASSWORD, method) {
            Ok(env) => env,
            Err(e) => {
                eprintln!("bench skip {method}: {e}");
                continue;
            }
        };

        // --- encrypt: persistent context, sequential 1 MiB blocks ---
        let (mut ectx, iv) = match env.create_encrypt_ctx() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("bench skip {method} (encrypt ctx): {e}");
                continue;
            }
        };
        // Wire image of one full block: IV prefix (empty for AEAD/zero-IV
        // methods) + ciphertext — the decrypt side consumes exactly this.
        let body = env.encrypt_ctx(&mut ectx, &plaintext, false).unwrap();
        let full_ct: Vec<u8> = [iv.as_slice(), body.as_slice()].concat();

        group.bench_function(format!("encrypt/{method}"), |b| {
            b.iter(|| {
                black_box(
                    env.encrypt_ctx(&mut ectx, black_box(&plaintext), false)
                        .unwrap(),
                )
            })
        });

        // --- decrypt: fresh context per wire block (IV/salt split) ---
        group.bench_function(format!("decrypt/{method}"), |b| {
            b.iter(|| {
                let (mut dctx, body) = env
                    .create_decrypt_ctx_from_ciphertext(black_box(&full_ct))
                    .unwrap();
                black_box(env.decrypt_ctx(&mut dctx, &body).unwrap())
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cipher_throughput);
criterion_main!(benches);
