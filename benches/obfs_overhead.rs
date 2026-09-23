//! P1: per-packet obfs overhead (ns/packet, 1440 B payload).
//!
//! Each obfs instance is driven to its steady state before timing:
//! * encode — HTTP header emitted / TLS handshake completed (0x04);
//! * decode — HTTP response header stripped / TLS server response validated
//!   (0x08, synthesised from the public HMAC recipe: key + client_id).
//!
//! Results land in BENCH.md (GOALS P1).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssr_client_rs::obfs::{create_obfs, Obfs};
use ssr_client_rs::utils::hash::hmac_sha1;
use std::time::Duration;

const PAYLOAD: usize = 1440;

/// Obfs names accepted by `create_obfs`.
const OBFS: &[&str] = &[
    "plain",
    "http_simple",
    "http_post",
    "http_mix",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];

fn make(name: &str) -> Box<dyn Obfs> {
    create_obfs(name, "bench.example.com", 443, "").expect("known obfs name")
}

/// Synthesise a server handshake response that passes the TLS obfs
/// validation (mirrors `tls12_ticket_auth_client_decode` HMAC checks).
fn synth_server_response(key: &[u8], client_id: &[u8; 32]) -> Vec<u8> {
    let mut hmac_key = Vec::with_capacity(key.len() + client_id.len());
    hmac_key.extend_from_slice(key);
    hmac_key.extend_from_slice(client_id);

    // Layout: [0..11] hdr, [11..33] data, [33..43] hmac1,
    //          [43..len-10] filler, [len-10..len] hmac2.  Total >= 76.
    let len = 76usize;
    let mut buf = vec![0u8; len];
    buf[11..33].copy_from_slice(&[0x5Au8; 22]);
    let h1 = hmac_sha1(&hmac_key, &buf[11..33]);
    buf[33..43].copy_from_slice(&h1[..10]);
    let h2 = hmac_sha1(&hmac_key, &buf[..len - 10]);
    buf[len - 10..].copy_from_slice(&h2[..10]);
    buf
}

/// Drive a non-TLS instance to steady state (HTTP header emitted + response
/// header stripped); `plain` is stateless.
fn steady(name: &str) -> Box<dyn Obfs> {
    let mut obfs = make(name);
    obfs.set_key(vec![0x42u8; 16]);
    if name.starts_with("http") {
        let _ = obfs.client_encode(&[0u8; 8]).unwrap();
        let _ = obfs
            .client_decode(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    }
    obfs
}

fn bench_obfs_overhead(c: &mut Criterion) {
    let data = vec![0xCDu8; PAYLOAD];
    let mut group = c.benchmark_group("obfs_overhead");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));
    group.warm_up_time(Duration::from_millis(300));

    for &name in OBFS {
        if name.starts_with("tls") {
            // Concrete path so we can read `client_id` for the synthesised
            // server response (trait objects have no downcast).
            let mut obfs = ssr_client_rs::obfs::tls_ticket::Tls12TicketAuthObfs::new(
                "bench.example.com".to_string(),
                443,
                String::new(),
                name.ends_with("fastauth"),
            );
            obfs.set_key(vec![0x42u8; 16]);
            let _ = obfs.client_encode(b"").unwrap();
            let _ = obfs.client_encode(b"").unwrap();
            let cid = *obfs.get_client_id();
            let resp = synth_server_response(&[0x42u8; 16], &cid);
            let (_o, fb) = obfs.client_decode(&resp).unwrap();
            debug_assert!(fb, "server handshake response must validate");

            group.bench_function(format!("encode/{name}"), |b| {
                b.iter(|| black_box(obfs.client_encode(black_box(&data)).unwrap()))
            });
            // Steady-state decode: application-data records (0x17 + len + body).
            let mut record = vec![0x17, 0x03, 0x03];
            record.extend_from_slice(&(data.len() as u16).to_be_bytes());
            record.extend_from_slice(&data);
            group.bench_function(format!("decode/{name}"), |b| {
                b.iter(|| black_box(obfs.client_decode(black_box(&record)).unwrap()))
            });
            continue;
        }

        let mut obfs = steady(name);
        group.bench_function(format!("encode/{name}"), |b| {
            b.iter(|| black_box(obfs.client_encode(black_box(&data)).unwrap()))
        });

        // Decode steady-state: HTTP header already consumed, so both
        // families take the passthrough path over the raw payload.
        group.bench_function(format!("decode/{name}"), |b| {
            b.iter(|| black_box(obfs.client_decode(black_box(&data)).unwrap()))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_obfs_overhead);
criterion_main!(benches);
