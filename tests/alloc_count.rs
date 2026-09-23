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
use std::hint::black_box;

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

    // ---- P3 extension: per-packet allocs + ns/op for protocol & obfs -----
    // 1440 B packets, steady state (header emitted / handshake completed),
    // ITERS small enough to keep the whole test fast but >> 1 for averaging.
    p3_protocol_obfs(ITERS_P3);
}

const ITERS_P3: usize = 2000;
const PKT: usize = 1440;

fn per_op<F: FnMut()>(iters: usize, mut f: F) -> (u64, f64) {
    // warmup outside the measurement
    for _ in 0..64 {
        f();
    }
    let a = ALLOCS.load(Relaxed);
    let t0 = std::time::Instant::now();
    for _ in 0..iters {
        f();
    }
    let dt = t0.elapsed().as_secs_f64();
    let allocs = ALLOCS.load(Relaxed) - a;
    (allocs / iters as u64, dt * 1e9 / iters as f64)
}

fn p3_protocol_obfs(iters: usize) {
    use ssr_client_rs::obfs::create_obfs;
    use ssr_client_rs::protocol::auth_aes128::AuthAES128;
    use ssr_client_rs::protocol::auth_chain::AuthChainA;
    use ssr_client_rs::protocol::origin::Origin;
    use ssr_client_rs::protocol::{Protocol, ServerInfo};

    let pkt = vec![0xCDu8; PKT];
    let mut report = String::from("P3 alloc/time probe (1440B, steady):\n");

    let si = || ServerInfo {
        key: vec![0x42u8; 16],
        iv: vec![0x24u8; 16],
        ..Default::default()
    };
    macro_rules! proto_probe {
        ($label:literal, $ctor:expr) => {{
            let mut p: Box<dyn Protocol> = $ctor;
            p.init_user_key();
            let warm = vec![0xABu8; 100];
            let _ = p.client_pre_encrypt(&warm).unwrap();
            let (a, ns) = per_op(iters, || {
                black_box(p.client_pre_encrypt(black_box(&pkt)).unwrap());
            });
            report.push_str(&format!("  {} pre:  {a} allocs, {ns:.0} ns\n", $label));
        }};
    }
    proto_probe!("origin", Box::new(Origin));
    proto_probe!("auth_chain_a", {
        let mut p = AuthChainA::new(si(), "auth_chain_a");
        p.init_user_key();
        Box::new(p)
    });
    proto_probe!("auth_aes128_md5", {
        let mut p = AuthAES128::new_md5(si());
        p.init_user_key(); // inherent — see P1 finding (dyn call is a no-op)
        Box::new(p)
    });

    // protocol post: same-instance lockstep (mirrors the P1 bench warmup).
    {
        let mut p: Box<dyn Protocol> = Box::new(Origin);
        let _ = p.client_pre_encrypt(&pkt).unwrap();
        let (a, ns) = per_op(iters, || {
            black_box(p.client_post_decrypt(black_box(&pkt)).unwrap());
        });
        report.push_str(&format!("  origin post: {a} allocs, {ns:.0} ns\n"));
    }

    // obfs encode/decode: plain (stateless) + http_simple (steady) + tls.
    for name in ["plain", "http_simple", "tls1.2_ticket_fastauth"] {
        let mut o = create_obfs(name, "bench.example.com", 443, "").unwrap();
        o.set_key(vec![0x42u8; 16]);
        // drive to steady state
        let _ = o.client_encode(&[0u8; 8]).unwrap();
        let _ = o.client_encode(&[0u8; 8]).unwrap();
        if name.starts_with("http") {
            let _ = o
                .client_decode(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        }
        let (ae, nse) = per_op(iters, || {
            black_box(o.client_encode(black_box(&pkt)).unwrap());
        });
        report.push_str(&format!("  {name} encode: {ae} allocs, {nse:.0} ns\n"));
        let (ad, nsd) = per_op(iters, || {
            black_box(o.client_decode(black_box(&pkt)).unwrap());
        });
        report.push_str(&format!("  {name} decode: {ad} allocs, {nsd:.0} ns\n"));
    }
    eprint!("{report}");
}
