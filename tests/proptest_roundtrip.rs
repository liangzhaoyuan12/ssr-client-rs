//! Phase T3: property-based tests (GOALS T3).
//!
//! Invariants, over arbitrary generated input:
//! 1. `decrypt(encrypt(x)) == x` for every stream cipher roundtrip.
//! 2. Protocol layers never panic on arbitrary bytes (they must return
//!    Ok/Err instead), matching the C reference's drop-or-emit contract.
//!
//! Deterministic: proptest fixes the RNG seed per run unless PROPTEST_RNG
//! is set, so failures are reproducible from the printed minimal case.

use proptest::prelude::*;
use ssr_client_rs::crypto::cipher_env::CipherEnv;
use ssr_client_rs::protocol::auth_aes128::AuthAES128;
use ssr_client_rs::protocol::auth_chain::AuthChainA;
use ssr_client_rs::protocol::auth_sha1_v4::AuthSHA1V4;
use ssr_client_rs::protocol::{Protocol, ServerInfo};
use ssr_client_rs::socks5::{build_udp_datagram, parse_udp_datagram, TargetAddress};

fn si() -> ServerInfo {
    ServerInfo {
        key: vec![0x42u8; 16],
        iv: vec![0x24u8; 16],
        ..Default::default()
    }
}

/// All stream ciphers we implement (GOALS phase list: 16 implemented + none/table).
/// AEAD methods are excluded: they use context APIs, not encrypt()/decrypt().
const STREAM_CIPHERS: &[&str] = &[
    "none",
    "rc4",
    "rc4-md5-6",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "des-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
];

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    // 0..=2048 bytes: covers empty, tiny, and multi-block sizes.
    proptest::collection::vec(any::<u8>(), 0..=2048)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Invariant 1: roundtrip identity for every implemented stream cipher.
    #[test]
    fn prop_cipher_roundtrip(data in arb_bytes(), idx in 0usize..STREAM_CIPHERS.len()) {
        let method = STREAM_CIPHERS[idx];
        let env = CipherEnv::new("prop_test_password", method)
            .unwrap_or_else(|e| panic!("{method}: CipherEnv::new failed: {e}"));
        let enc = env.encrypt(&data).unwrap_or_else(|e| panic!("{method}: encrypt failed: {e}"));
        let dec = env.decrypt(&enc).unwrap_or_else(|e| panic!("{method}: decrypt failed: {e}"));
        prop_assert_eq!(dec, data);
    }

    /// Invariant 2a: AuthChainA pre_encrypt accepts any input without panic,
    /// and the framing always grows (auth header + payload) for non-empty data.
    #[test]
    fn prop_chain_a_pre_no_panic(data in arb_bytes()) {
        let mut p = AuthChainA::new(si(), "auth_chain_a");
        let out = p.client_pre_encrypt(&data); // must not panic
        if let Ok(framed) = out {
            prop_assert!(framed.len() >= data.len(), "framing shrank the payload");
        }
    }

    /// Invariant 2b: AuthChainA post_decrypt never panics on arbitrary bytes,
    /// whether or not they parse (random data mostly fails HMAC -> Err or
    /// buffered-empty, both acceptable; a panic is not).
    #[test]
    fn prop_chain_a_post_no_panic(data in arb_bytes()) {
        let mut p = AuthChainA::new(si(), "auth_chain_a");
        let _ = p.client_post_decrypt(&data); // must not panic
    }

    /// Invariant 2c: AuthAES128/SHA1V4 post_decrypt same contract.
    #[test]
    fn prop_auth_families_post_no_panic(data in arb_bytes()) {
        let mut a = AuthAES128::new_sha1(si());
        let _ = a.client_post_decrypt(&data);
        let mut b = AuthSHA1V4::new(si());
        let _ = b.client_post_decrypt(&data);
    }

    /// UDP hook contract: no panic on arbitrary input, and identity-style
    /// output (when Ok) never inverts length expectations silently for
    /// pre_encrypt (framing may only grow).
    #[test]
    fn prop_udp_hooks_no_panic(data in arb_bytes()) {
        let mut a = AuthChainA::new(si(), "auth_chain_a");
        if let Ok(out) = a.udp_pre_encrypt(&data) {
            prop_assert!(out.len() >= data.len(), "udp pre_encrypt shrank payload");
        }
        let _ = a.udp_post_decrypt(&data);
        let mut b = AuthAES128::new_sha1(si());
        let _ = b.udp_pre_encrypt(&data);
        let _ = b.udp_post_decrypt(&data);
    }

    /// UDP datagram build/parse roundtrips for arbitrary payload and ports,
    /// across all three address types.
    #[test]
    fn prop_udp_datagram_roundtrip(
        payload in arb_bytes(),
        port in 0u16..=65535,
        v4 in proptest::collection::vec(any::<u8>(), 4),
        v6 in proptest::collection::vec(any::<u8>(), 16),
        domain in proptest::collection::vec(any::<u8>(), 1..=255),
    ) {
        let cases = vec![
            TargetAddress::IPv4([v4[0], v4[1], v4[2], v4[3]]),
            {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&v6);
                TargetAddress::IPv6(ip)
            },
            TargetAddress::Domain(domain),
        ];
        for addr in cases {
            let dgram = build_udp_datagram(&addr, port, &payload);
            let parsed = parse_udp_datagram(&dgram)
                .unwrap_or_else(|e| panic!("parse failed on self-built datagram: {e}"));
            prop_assert_eq!(parsed.port, port);
            prop_assert_eq!(parsed.payload, payload.clone());
            prop_assert_eq!(parsed.frag, 0u8);
            prop_assert_eq!(parsed.addr, addr);
        }
    }
}
