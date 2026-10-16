# e2e matrix results

- date: 2026-10-16 11:08:57
- client: C-REF (/opt/ssr/ssr-client)
- server: /opt/ssr/ssr-server sha256[:12]=d70342262c45
- result: **0/3 passed**

| axis | method | protocol | obfs | result | note |
|------|--------|----------|------|--------|------|
| udp | aes-256-cfb+auth_chain_a |  |  | FAIL(ERR) |  |
| udp | aes-256-cfb+auth_aes128_sha1 |  |  | FAIL(ERR) |  |
| udp | aes-128-gcm+origin (AEAD) |  |  | FAIL(ERR) |  |
