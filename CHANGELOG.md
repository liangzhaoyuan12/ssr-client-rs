# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Compatibility promise

- **0.x (current)**: the public API (`SsrClient`, `SsrClientConfig`, `SsrError`,
  `SsrResult`, the re-exports in `lib.rs`, and everything documented on
  `docs.rs`) may change in any release, including breaking changes. Every
  breaking change is listed here.
- **1.0 and later**: semantic versioning strictly. Breaking changes only in
  major releases; security/bug fixes in patch releases.
- Byte-level protocol compatibility with ssr-n is a **feature**, not part of
  the semver contract: wire-format fixes that make the client match ssr-n
  behaviour are shipped as patch releases even when they change bytes on the
  wire.

## [Unreleased]

### Performance

- **Per-connection cipher environment cache**: the substitution table / key
  derivation is computed once per client instead of once per connection.
  `table` method TTFB drops **72.9 ms → 0.1 ms (−99.3 %)**, now on par with
  the C client. `none` derives the 16-byte EVP key exactly like ssr-n
  (`enc_table_init` else-branch), which also fixes obfs/protocol HMAC
  interop with `method = none`.
- **Relay data path**: one fewer allocation per 8 KB chunk in both
  directions (in-place encrypt/decrypt plumbing; AEAD keeps its framing
  path). Steady state is 2 allocations per chunk per direction.
- **`tls1.2_ticket_auth` / `fastauth` encode**: record fragments are packed
  straight into the output buffer — 2 → 1 allocations per packet, obfs
  encode ~47 % faster (`obfs_overhead` bench −47.8 % / −45.6 %).

### Fixed (stability / weak networks)

- SOCKS5 greeting and CONNECT replies are read frame-by-frame; split
  packets no longer fail the handshake.
- A stream-cipher IV split across TCP reads is reassembled instead of
  erroring with "Ciphertext too short for IV".
- Obfs handshake responses are loop-read until validated (10 s budget)
  instead of a single read.
- Every relay write is bounded by the idle timeout (300 s floor), and the
  post-EOF drain loop is bounded too — a stalled peer can no longer pin a
  task forever.
- TCP keepalive (30 s idle / 10 s interval / 3 probes) and TCP_NODELAY on
  both the SSR tunnel socket and the accepted SOCKS5 socket.
- Accept-error backoff (1 ms → 100 ms, log-throttled) and a 4096
  concurrent-connection ceiling (saturated accepts are dropped).

### Notes

- **No public API changes**: the exported surface is identical to 0.1.0
  (verified by an API snapshot diff; all additions are `pub(crate)` /
  private).

## [0.1.0] — unreleased

First release: a byte-compatible Rust port of the ssr-n client.

### Added

- **28 cipher method names parsed; 21 implemented**: AES-128/192/256 CFB &
  CTR, ChaCha20 (IETF + legacy), Salsa20, Blowfish-CFB, DES-CFB,
  RC4-MD5 / RC4-MD5-6, Table, and the AEAD suite (aes-128/192/256-gcm,
  chacha20-ietf-poly1305 …). The 20 combinations the reference server also
  accepts are verified byte-identical against it (e2e matrix).
- **14 protocols**: origin, verify_simple, auth_simple, auth_sha1/v2/v4,
  auth_aes128_md5/sha1, auth_chain_a…f.
- **6 obfs**: plain, http_simple/post/mix, tls1.2_ticket_auth/fastauth.
- Async (tokio) TCP relay with per-connection `idle_timeout` reclamation and
  UDP relay (SOCKS5 UDP ASSOCIATE), incl. protocol UDP hooks and AEAD/RC4
  per-packet UDP crypto.
- Local SOCKS5 server (`SsrClient`) plus `examples/socks5.rs`.
- **Dual integration modes**: Mode A binds a system port and serves SOCKS5
  (`SsrClient::start`); Mode B binds nothing and hands back a data pipe —
  `SsrClient::open_session(target) -> SsrSession`, an
  `AsyncRead + AsyncWrite` plaintext stream to the target for callers that
  do their own front-end (custom DNS, routing rules, direct-vs-proxy
  decisions, in-flight byte middleware). Both modes share one tunnel
  builder, so their wire bytes are identical; TCP only (UDP ASSOCIATE
  stays in Mode A).
- **IPv6 end to end**: SOCKS5 `ATYP 0x04` targets (CONNECT parse, success
  reply, SSR address package, UDP datagram round-trip), IPv6-literal
  `server` / `listen_address` configuration, and dual-stack `::` listeners —
  all covered by dedicated tests (`host_port()` formats addresses in the
  bracketed form std documents; bare and bracketed forms resolve
  identically). The outbound UDP socket already picked its family
  (`0.0.0.0:0` vs `[::]:0`).
- ssr-n JSON config loader (`config_from_json`).
- Strongly typed config: `SsrClientConfig::method/protocol/obfs` are the
  `CipherType`/`ProtocolType`/`ObfsType` enums (struct-literal friendly with
  `..Default::default()`); JSON name strings are parsed once at the config
  boundary via `from_name`, so an unknown name fails at load instead of at
  connect time. Build configs as struct literals — `SsrClientConfig::new()`
  with positional arguments was removed.

### Changed

- The repository no longer vendors the upstream `ssr-n` C sources: the
  `ssr-n/` directory (68 MB, reference only) was removed on 2026-09-25.
  Nothing in the build, tests or tooling read it, and it was already
  excluded from `cargo package`; source comments still cite upstream
  `ssr-n` file names for provenance.

### Fixed

- `SsrClient::stop()` no longer races `start()`: the shutdown signal is a
  `watch` channel (value semantics) instead of `Notify::notify_waiters`,
  which stored no permit — a `stop()` landing before the accept loops
  registered their waiter hung `start()` forever (observed as a test
  process holding its listen port). Both the TCP accept loop and the UDP
  relay now check the flag at the top of every turn; `stop()`/`start()`
  keep their signatures, and a stop-then-restart cycle works.

### Known limitations

- `cast5`, `idea`, `rc2`, `seed` and the three `camellia-*-cfb` cipher
  methods are not implemented (7 of the 28 parsed names; camellia and the
  others are accepted by the reference server, hence the dedicated SKIP rows
  in the matrix).
- `des-cfb` **is** implemented, but the reference server's mbedTLS backend
  rejects it, so that matrix row is a server-side SKIP (the C client fails
  the same way).
- The AEAD "hk" (half-waterfall) combination still needs a review pass
  against ssr-n.
- Protocols `verify_simple`/`auth_simple`/`auth_sha1`/`auth_sha1_v2` cannot
  complete against the stock ssr-n **server** (it never registers
  `server_post_decrypt` for them; the C client fails identically) — recorded
  as SKIP in the e2e matrix, not a client bug.

### Quality gates

- `cargo test` 237 tests, e2e matrix 39/51 PASS + 12 SKIP, 0 FAIL
  (remaining cases are server-side limitations, see above).
- Zero compiler warnings, zero clippy warnings (`-D warnings`),
  zero production-path panics, zero `unsafe`.
- `cargo audit`: 0 vulnerabilities; MSRV 1.82.
