# BENCH.md — criterion baseline (P1)

Reproducible micro-benchmark baseline for regression comparison (GOALS P1).

## Run metadata

| field | value |
|---|---|
| date | 2026-09-23 |
| machine | Loongson-3A5000 (LA664), 4 cores @ 2.30 GHz, LoongArch64 |
| kernel / OS | 6.6.143-loong64-desktop-hwe / Deepin 25 |
| profile | `cargo bench` = release (opt3, thin LTO, codegen-units=1, strip) |
| toolchain | rustc stable-loongarch64, criterion 0.5.1 |
| method | warm-up 300 ms, measure 1 s, 10 samples, `--noplot` |
| noise | desktop session, no CPU isolation — treat ±10% as noise band |

Reproduce: `cargo bench -- --noplot` (all three targets).

## 1. cipher throughput (1 MiB buffer, criterion — FINAL release-profile run)

`encrypt` = persistent-context streaming; `decrypt` = fresh ctx per packet
(IV/salt parse + key schedule included). Unsupported methods (camellia,
cast5, idea, rc2, seed — underlying crate coverage) are skipped by
`CipherEnv::new`. Earlier numbers taken while other cargo jobs ran in
parallel were contaminated (up to 10x on cache-sensitive paths); everything
below is from the final idle-machine run after all Phase-P changes.
Downstream users wanting the last few percent can build with
`RUSTFLAGS="-C target-cpu=native"` — the library itself does not pin CPU
features (P5).

| cipher | encrypt MiB/s | decrypt MiB/s |
|---|---:|---:|
| aes-128-cfb | 29.6 | 27.7 |
| aes-128-ctr | 116.9 | 110.6 |
| aes-128-gcm | 81.8 | 69.3 |
| aes-192-cfb | 25.5 | 23.6 |
| aes-192-ctr | 100.8 | 96.0 |
| aes-192-gcm | 73.1 | 63.1 |
| aes-256-cfb | 22.2 | 20.7 |
| aes-256-ctr | 88.0 | 84.4 |
| aes-256-gcm | 66.3 | 58.0 |
| bf-cfb | 73.0 | 71.6 |
| chacha20 | 347.7 | 300.2 |
| chacha20-ietf | 348.2 | 300.3 |
| chacha20-ietf-poly1305 | 241.8 | 157.9 |
| des-cfb | 20.8 | 20.7 |
| none | 15889.9 | 1941.1 |
| rc4 | 193.9 | 178.7 |
| rc4-md5 | 194.2 | 177.4 |
| rc4-md5-6 | 194.0 | 177.7 |
| salsa20 | 398.9 | 344.7 |
| table | 928.5 | 647.6 |
| xchacha20-ietf-poly1305 | 239.6 | 157.2 |

## 2. protocol per-packet overhead (1440 B, ns/packet — FINAL run, post-P3)

Numbers below already include the P3 per-packet allocation cuts
(`hmac_key_buf` scratch reuse, direct-fill `out`, in-place RC4);
vs the pre-P3 baseline: auth_aes128 pre/post −4.6…−6.3%, auth_chain_a/c
pre −5.8% (allocs per packet: auth_chain 5→2, auth_aes128 6→4).

`post/*` for `auth_chain_*` is **n/a**: the client `post_decrypt` only parses
server-direction frames (single-direction hash chains); `client_pre_encrypt`
output cannot self-roundtrip — confirmed with a probe binary and by design
(full_coverage's chain tests exercise `pre` only). Capturing real server
frames would require driving the C server inside the bench; end-to-end cost
is covered by P2 §4 instead.

| protocol | pre | post |
|---|---:|---:|
| auth_aes128_md5 | 5.97 µs | 5.79 µs |
| auth_aes128_sha1 | 4.70 µs | 4.45 µs |
| auth_chain_a | 12.09 µs | n/a |
| auth_chain_b | 11.90 µs | n/a |
| auth_chain_c | 12.06 µs | n/a |
| auth_chain_d | 11.97 µs | n/a |
| auth_chain_e | 11.98 µs | n/a |
| auth_chain_f | 11.97 µs | n/a |
| auth_sha1 | 9.62 µs | 8.72 µs |
| auth_sha1_v2 | 9.11 µs | 8.17 µs |
| auth_sha1_v4 | 8.84 µs | 8.19 µs |
| auth_simple | 1.64 µs | 1.62 µs |
| origin | 145 ns | 422 ns |
| verify_simple | 1.66 µs | 1.41 µs |

## 3. obfs per-packet overhead (1440 B, ns/packet — FINAL run)

Steady state: HTTP header emitted, TLS handshake completed (0x04/0x08 set
via warm-up encode calls where reachable through the public API).

| obfs | encode | decode |
|---|---:|---:|
| http_mix | 227 ns | 2.01 µs |
| http_post | 214 ns | 2.02 µs |
| http_simple | 214 ns | 2.03 µs |
| plain | 193 ns | 2.00 µs |
| tls1.2_ticket_auth | 470 ns | 343 ns |
| tls1.2_ticket_fastauth | 476 ns | 333 ns |

## 4. P2 end-to-end vs C client (2026-09-23)

| field | value |
|---|---|
| config | aes-256-cfb / auth_aes128_sha1 / tls1.2_ticket_auth, loopback |
| payload | 64 MiB random file x 3 runs, median |
| server | /opt/ssr/ssr-server (d70342262c45) |
| C client | /opt/ssr/ssr-client (988974dcdfa5) |
| Rust client | /home/liangzhaoyuan12/work/rs/ssr-client-rs/target/release/ssr_client (ecd9b44095fa) |

| client | throughput MiB/s | median wall s | CPU % |
|---|---|---|---|
| C | 14.6 | 4.385326 | 99.9 |
| Rust | 15.1 | 4.248949 | 79.8 |

**Result**: throughput rust/C = 103.4% (target >= 90%),
CPU rust/C = 0.80x (target <= 1.5x) — throughput rust/C=103.42% (PASS, need >=90%)  cpu rust/C=0.80x (PASS, need <=1.5x)

## 5. P4 concurrency scaling curve (2026-09-23)

Local ssr-server + Rust client, aes-256-cfb / auth_aes128_sha1 /
tls1.2_ticket_auth, 64 MiB origin, 15 s window per level. `client CPU%`
is process-wide (all threads) over the window.

| level | MiB/s | × single | client CPU % | server CPU % | fd | RSS MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 15.1 | 1.0× | 83 | 99 | 10 | 3.6 |
| 8 | 149.1 | 9.9× | 85 | 99 | 18 | 4.4 |
| 64 | 146.7 | **9.7×** | 84 | 99 | 16 | 7.8 |
| 100 | 144.4 | 9.6× | 83 | 97 | 52 | 8.8 |

- **GOALS target met**: ≥8× single-stream at level 64 → measured **9.7×**.
  (Single stream is flow-control-bound at ~15 MiB/s, not compute-bound, so
  the 8× ratio is reachable even on this 4-core box; aggregate saturates at
  the whole-machine compute wall — client+server+curl — which is why the
  curve plateaus at 8 streams instead of climbing further.)
- **No lock hotspot**: client CPU stays 83–85% across all levels (constant
  per-MiB cost), throughput never *drops* as level grows, fd returns to
  baseline (10) after the run, RSS peaks at 8.8 MiB at 100 streams. No
  Mutex-contention signature → per GOALS, nothing to optimize.
- Budget cross-check: aes-256-cfb soft implementation costs 22 MiB/s/core
  (§1 micro), so decrypting 149 MiB/s needs ~0.68 core on the client —
  consistent with the measured 0.83 core total (remaining ~0.15 core for
  syscalls/protocol/obfs). server mirrors this on the C side.
- Known flaw: the origin-CPU column samples the http.server wrapper PID
  instead of the python worker, so it reads 0 — not used for any verdict.
- A `method=none` control run fails to connect (server rejects it), which
  confirms the `method` key is honored by both ends of the hand-written
  configs.

## 4. P2 end-to-end vs C client (2026-09-23)

| field | value |
|---|---|
| config | aes-256-cfb / auth_aes128_sha1 / tls1.2_ticket_auth, loopback |
| payload | 64 MiB random file x 3 runs, median |
| server | /opt/ssr/ssr-server (d70342262c45) |
| C client | /opt/ssr/ssr-client (988974dcdfa5) |
| Rust client | /home/liangzhaoyuan12/work/rs/ssr-client-rs/target/release/ssr_client (76e84c39821f) |

| client | throughput MiB/s | median wall s | CPU % |
|---|---|---|---|
| C | 14.6 | 4.379351 | 99.8 |
| Rust | 15.1 | 4.226786 | 83.0 |

**Result**: throughput rust/C = 103.4% (target >= 90%),
CPU rust/C = 0.83x (target <= 1.5x) — throughput rust/C=103.42% (PASS, need >=90%)  cpu rust/C=0.83x (PASS, need <=1.5x)
