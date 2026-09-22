# e2e matrix results

- date: 2026-09-23 06:02:44
- client: RUST (target/release/ssr_client)
- server: /opt/ssr/ssr-server sha256[:12]=d70342262c45
- result: **39/51 passed**, 12 skipped (not run)

| axis | method | protocol | obfs | result | note |
|------|--------|----------|------|--------|------|
| cipher | none | origin | plain | PASS |  |
| cipher | table | origin | plain | PASS |  |
| cipher | rc4 | origin | plain | PASS |  |
| cipher | rc4-md5 | origin | plain | PASS |  |
| cipher | rc4-md5-6 | origin | plain | PASS |  |
| cipher | aes-128-cfb | origin | plain | PASS |  |
| cipher | aes-192-cfb | origin | plain | PASS |  |
| cipher | aes-256-cfb | origin | plain | PASS |  |
| cipher | aes-128-ctr | origin | plain | PASS |  |
| cipher | aes-192-ctr | origin | plain | PASS |  |
| cipher | aes-256-ctr | origin | plain | PASS |  |
| cipher | bf-cfb | origin | plain | PASS |  |
| cipher | salsa20 | origin | plain | PASS |  |
| cipher | chacha20 | origin | plain | PASS |  |
| cipher | chacha20-ietf | origin | plain | PASS |  |
| cipher | aes-128-gcm | origin | plain | PASS |  |
| cipher | aes-192-gcm | origin | plain | PASS |  |
| cipher | aes-256-gcm | origin | plain | PASS |  |
| cipher | chacha20-ietf-poly1305 | origin | plain | PASS |  |
| cipher | xchacha20-ietf-poly1305 | origin | plain | PASS |  |
| cipher | camellia-128-cfb | origin | plain | SKIP | SKIP: client not implemented (server supports) |
| cipher | camellia-192-cfb | origin | plain | SKIP | SKIP: client not implemented (server supports) |
| cipher | camellia-256-cfb | origin | plain | SKIP | SKIP: client not implemented (server supports) |
| cipher | cast5-cfb | origin | plain | SKIP | SKIP: server itself does not support (C client fails too) |
| cipher | idea-cfb | origin | plain | SKIP | SKIP: server itself does not support (C client fails too) |
| cipher | rc2-cfb | origin | plain | SKIP | SKIP: server itself does not support (C client fails too) |
| cipher | seed-cfb | origin | plain | SKIP | SKIP: server itself does not support (C client fails too) |
| cipher | des-cfb | origin | plain | SKIP | SKIP: server mbedTLS does not support des-cfb |
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
| obfs | aes-256-cfb | auth_aes128_sha1 | plain | PASS |  |
| obfs | aes-256-cfb | auth_aes128_sha1 | http_simple | PASS |  |
| obfs | aes-256-cfb | auth_aes128_sha1 | http_post | PASS |  |
| obfs | aes-256-cfb | auth_aes128_sha1 | http_mix | PASS |  |
| obfs | aes-256-cfb | auth_aes128_sha1 | tls1.2_ticket_auth | PASS |  |
| obfs | aes-256-cfb | auth_aes128_sha1 | tls1.2_ticket_fastauth | PASS |  |
| udp | aes-256-cfb+auth_chain_a |  |  | PASS |  |
| udp | aes-256-cfb+auth_aes128_sha1 |  |  | PASS |  |
| udp | aes-128-gcm+origin (AEAD) |  |  | PASS |  |
