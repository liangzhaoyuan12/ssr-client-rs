# e2e matrix results

- date: 2026-10-16 01:05:34
- client: RUST (target/release/ssr_client)
- server: /opt/ssr/ssr-server sha256[:12]=d70342262c45
- result: **10/14 passed**, 4 skipped (not run)

| axis | method | protocol | obfs | result | note |
|------|--------|----------|------|--------|------|
| protocol | aes-256-cfb | origin | plain | PASS |  |
| protocol | aes-256-cfb | verify_simple | plain | SKIP | SKIP: server has no server_post_decrypt (C client fails too) |
| protocol | aes-256-cfb | auth_simple | plain | SKIP | SKIP: server has no server_post_decrypt (C client fails too) |
| protocol | aes-256-cfb | auth_sha1 | plain | SKIP | SKIP: server has no server_post_decrypt (C client fails too) |
| protocol | aes-256-cfb | auth_sha1_v2 | plain | SKIP | SKIP: server has no server_post_decrypt (C client fails too) |
| protocol | aes-256-cfb | auth_sha1_v4 | plain | PASS |  |
| protocol | aes-256-cfb | auth_aes128_md5 | plain | PASS |  |
| protocol | aes-256-cfb | auth_aes128_sha1 | plain | PASS |  |
| protocol | aes-256-cfb | auth_chain_a | plain | PASS |  |
| protocol | aes-256-cfb | auth_chain_b | plain | PASS |  |
| protocol | aes-256-cfb | auth_chain_c | plain | PASS |  |
| protocol | aes-256-cfb | auth_chain_d | plain | PASS |  |
| protocol | aes-256-cfb | auth_chain_e | plain | PASS |  |
| protocol | aes-128-cfb | auth_chain_f | plain | PASS |  |
