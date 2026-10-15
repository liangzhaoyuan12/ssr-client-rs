# e2e matrix results

- date: 2026-10-16 00:20:48
- client: C-REF (/opt/ssr/ssr-client)
- server: /opt/ssr/ssr-server sha256[:12]=d70342262c45
- result: **26/28 passed**

| axis | method | protocol | obfs | result | note |
|------|--------|----------|------|--------|------|
| combo | none | origin | plain | PASS |  |
| combo | none | origin | http_simple | PASS |  |
| combo | none | origin | tls1.2_ticket_auth | PASS |  |
| combo | none | auth_aes128_sha1 | plain | FAIL(ERR) |  |
| combo | none | auth_aes128_sha1 | http_simple | PASS |  |
| combo | none | auth_aes128_sha1 | tls1.2_ticket_auth | PASS |  |
| combo | none | auth_chain_a | plain | PASS |  |
| combo | none | auth_chain_a | http_simple | PASS |  |
| combo | none | auth_chain_a | tls1.2_ticket_auth | PASS |  |
| combo | table | origin | plain | PASS |  |
| combo | table | origin | http_simple | PASS |  |
| combo | table | origin | tls1.2_ticket_auth | PASS |  |
| combo | table | auth_aes128_sha1 | plain | FAIL(ERR) |  |
| combo | table | auth_aes128_sha1 | http_simple | PASS |  |
| combo | table | auth_aes128_sha1 | tls1.2_ticket_auth | PASS |  |
| combo | table | auth_chain_a | plain | PASS |  |
| combo | table | auth_chain_a | http_simple | PASS |  |
| combo | table | auth_chain_a | tls1.2_ticket_auth | PASS |  |
| combo | aes-256-cfb | origin | plain | PASS |  |
| combo | aes-256-cfb | origin | http_simple | PASS |  |
| combo | aes-256-cfb | origin | tls1.2_ticket_auth | PASS |  |
| combo | aes-256-cfb | auth_aes128_sha1 | plain | PASS |  |
| combo | aes-256-cfb | auth_aes128_sha1 | http_simple | PASS |  |
| combo | aes-256-cfb | auth_aes128_sha1 | tls1.2_ticket_auth | PASS |  |
| combo | aes-256-cfb | auth_chain_a | plain | PASS |  |
| combo | aes-256-cfb | auth_chain_a | http_simple | PASS |  |
| combo | aes-256-cfb | auth_chain_a | tls1.2_ticket_auth | PASS |  |
| combo | aes-256-gcm | origin | plain | PASS |  |
