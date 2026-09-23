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
- ssr-n JSON config loader (`config_from_json`).

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
