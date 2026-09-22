use ssr_client_rs::crypto::cipher_env::CipherEnv;
use ssr_client_rs::utils::hash::hmac_sha1;

fn main() {
    let env = CipherEnv::new("test-password", "aes-256-cfb").unwrap();
    let key = env.key();
    println!("key len={}: {:02x?}", key.len(), key);

    // Our hmac_sha1 with all-zero client_id (what we use in access_google)
    let client_id = [0u8; 32];
    let hmac_key = [key, &client_id[..key.len()]].concat();
    println!("hmac_key len={}: {:02x?}", hmac_key.len(), &hmac_key[..16]);

    // Test HMAC
    let test_msg = b"hello";
    let h = hmac_sha1(&hmac_key, test_msg);
    println!("hmac(16-byte key): {:02x?}", &h[..10]);

    // Full 32-byte key
    let hmac_key32 = [key, &client_id[..]].concat();
    let h2 = hmac_sha1(&hmac_key32, test_msg);
    println!("hmac(32-byte key): {:02x?}", &h2[..10]);
}
