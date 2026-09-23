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

## 1. cipher_throughput — 1 MiB buffer per iteration

encrypt = persistent context streaming (TCP reality); decrypt = fresh
context per wire block incl. IV/salt split (per-packet reality).
MiB/s derived as 1 MiB / time (criterion thrpt agrees).

| cipher | encrypt time | enc MiB/s | decrypt time | dec MiB/s |
|---|---|---|---|---|
| aes-128-cfb | 33.808 ms | 30 | 36.118 ms | 28 |
| aes-128-ctr | 8.574 ms | 117 | 9.035 ms | 111 |
| aes-128-gcm | 12.185 ms | 82 | 14.404 ms | 69 |
| aes-192-cfb | 39.239 ms | 25 | 42.425 ms | 24 |
| aes-192-ctr | 9.9584 ms | 100 | 10.404 ms | 96 |
| aes-192-gcm | 13.679 ms | 73 | 15.856 ms | 63 |
| aes-256-cfb | 44.994 ms | 22 | 48.34 ms | 21 |
| aes-256-ctr | 11.364 ms | 88 | 11.848 ms | 84 |
| aes-256-gcm | 15.099 ms | 66 | 17.497 ms | 57 |
| bf-cfb | 13.724 ms | 73 | 13.931 ms | 72 |
| chacha20 | 2.8729 ms | 348 | 3.3306 ms | 300 |
| chacha20-ietf | 2.8716 ms | 348 | 3.3306 ms | 300 |
| chacha20-ietf-poly1305 | 4.1925 ms | 239 | 6.3603 ms | 157 |
| des-cfb | 48.145 ms | 21 | 48.312 ms | 21 |
| none | 63.061 µs | 15858 | 514.57 µs | 1943 |
| rc4 | 5.1909 ms | 193 | 5.6365 ms | 177 |
| rc4-md5 | 5.1723 ms | 193 | 5.6304 ms | 178 |
| rc4-md5-6 | 5.1507 ms | 194 | 5.6305 ms | 178 |
| salsa20 | 2.5085 ms | 399 | 2.8984 ms | 345 |
| table | 1.0704 ms | 934 | 1.5462 ms | 647 |
| xchacha20-ietf-poly1305 | 4.2344 ms | 236 | 6.3886 ms | 157 |

Skipped by `CipherEnv::new` (not implemented, same 8 as matrix CIPHER_SKIP):
camellia-128/192/256-cfb, cast5-cfb, idea-cfb, rc2-cfb, seed-cfb.

## 2. protocol_overhead — 1440 B payload, ns/packet

| protocol | pre_encrypt | post_decrypt |
|---|---|---|
| auth_aes128_md5 | 6.3273 µs | 6.0859 µs |
| auth_aes128_sha1 | 4.9755 µs | 4.744 µs |
| auth_chain_a | 12.768 µs | n/a* |
| auth_chain_b | 12.535 µs | n/a* |
| auth_chain_c | 12.785 µs | n/a* |
| auth_chain_d | 12.353 µs | n/a* |
| auth_chain_e | 12.37 µs | n/a* |
| auth_chain_f | 12.377 µs | n/a* |
| auth_sha1 | 9.5458 µs | 8.7397 µs |
| auth_sha1_v2 | 9.0669 µs | 8.1569 µs |
| auth_sha1_v4 | 8.8337 µs | 8.222 µs |
| auth_simple | 1.5857 µs | 1.5907 µs |
| origin | 148.19 ns | 414.89 ns |
| verify_simple | 1.6779 µs | 1.407 µs |

\* auth_chain_a..f post: no client-side self-loop exists — pre walks the
client hash chain, post walks the server hash chain, and only a real
ssr-n server (`server_pre_encrypt`) can produce frames `post_decrypt`
accepts (probe-verified: same-instance pre→post fails from frame 1; the
C client faces the same limitation). Covered by the real-direction e2e
matrix instead (39/51, all auth_chain variants PASS).

## 3. obfs_overhead — 1440 B payload, ns/packet (steady state)

| obfs | encode | decode |
|---|---|---|
| http_mix | 232.34 ns | 2.0664 µs |
| http_post | 223.29 ns | 267.06 ns |
| http_simple | 252.77 ns | 238.86 ns |
| plain | 193.49 ns | 2.0563 µs |
| tls1.2_ticket_auth | 480.81 ns | 2.1126 µs |
| tls1.2_ticket_fastauth | 466.63 ns | 2.0905 µs |

Steady state reached before timing: HTTP header emitted + response
header stripped; TLS handshake driven to 0x04/0x08 via the public API
(fastauth encode + synthesised server-HMAC response for decode).

## Reading guide

* P3 optimizations must move these numbers — before/after tables go in
  PROGRESS.md, gain < 5% = not worth taking (GOALS P3).
* P5 re-runs this baseline for confirmation; numbers above are already
  release-grade: opt3 + thin LTO + codegen-units=1, no debug_assert cost.
* P2 appends the end-to-end vs C table (tools/bench_vs_c.sh).


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
