//! R4 allocation-count instrumentation for the per-packet crypto hot path
//! (GOALS Phase R: "分配次数对比数据（计数插桩）").
//!
//! Wraps the system allocator with a counting `#[global_allocator]` and
//! measures heap allocation events per 64KB encrypt/decrypt round-trip.
//! This is the P3 baseline: hot-path optimizations must lower these numbers
//! without changing wire bytes (e2e matrix stays green).
//!
//! Everything runs in ONE `#[test]` fn so the shared counters cannot be
//! contaminated by parallel tests inside this binary.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

struct CountingAlloc;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

use ssr_client_rs::crypto::cipher_env::CipherEnv;

const PACKET: usize = 65536; // 64KB — the soak/GOALS transfer chunk
const ITERS: usize = 200;

#[test]
fn allocs_per_64k_packet_roundtrip() {
    let env = CipherEnv::new("alloc_probe_pw", "aes-256-cfb").unwrap();
    let data = vec![0xABu8; PACKET];

    // ---- warmup: one-time costs (rng seeding, table init, capacity growth)
    for _ in 0..20 {
        let ct = env.encrypt(&data).unwrap();
        let pt = env.decrypt(&ct).unwrap();
        assert_eq!(pt.len(), data.len());
    }

    // ---- one-shot path (C: ss_encrypt_all / ss_decrypt_all) --------------
    let a0 = ALLOCS.load(Relaxed);
    let b0 = ALLOC_BYTES.load(Relaxed);
    for _ in 0..ITERS {
        let ct = env.encrypt(&data).unwrap();
        let pt = env.decrypt(&ct).unwrap();
        std::hint::black_box(&pt);
    }
    let oneshot_allocs = ALLOCS.load(Relaxed) - a0;
    let oneshot_bytes = ALLOC_BYTES.load(Relaxed) - b0;
    let oneshot_per = oneshot_allocs / ITERS as u64;

    // ---- stateful TCP path (C: ss_encrypt/ss_decrypt with enc_ctx) --------
    let (mut ectx, iv) = env.create_encrypt_ctx().unwrap();
    let mut framed = iv.clone();
    framed.extend_from_slice(&env.encrypt_ctx(&mut ectx, &data, true).unwrap());
    let (mut dctx, first) = env.create_decrypt_ctx_from_ciphertext(&framed).unwrap();
    let _ = env.decrypt_ctx(&mut dctx, &first).unwrap();

    let a1 = ALLOCS.load(Relaxed);
    for _ in 0..ITERS {
        let ct = env.encrypt_ctx(&mut ectx, &data, false).unwrap();
        let pt = env.decrypt_ctx(&mut dctx, &ct).unwrap();
        std::hint::black_box(&pt);
    }
    let stateful_allocs = ALLOCS.load(Relaxed) - a1;
    let stateful_per = stateful_allocs / ITERS as u64;

    eprintln!(
        "R4 alloc baseline (64KB, aes-256-cfb, {ITERS} iters):\n  \
         one-shot encrypt+decrypt: {oneshot_per} allocs/roundtrip \
         ({} B avg),\n  \
         stateful encrypt+decrypt: {stateful_per} allocs/roundtrip",
        oneshot_bytes / ITERS as u64
    );

    // Regression guards (loose): each round-trip is input-copy + output +
    // IV/overhead vectors; C's ss_decrypt_all also calloc()s a plain buffer
    // per packet, so a small constant is expected — not zero.
    assert!(
        oneshot_per <= 16,
        "one-shot roundtrip allocs regressed: {oneshot_per} > 16 per 64KB packet"
    );
    assert!(
        stateful_per <= 16,
        "stateful roundtrip allocs regressed: {stateful_per} > 16 per 64KB packet"
    );
}
