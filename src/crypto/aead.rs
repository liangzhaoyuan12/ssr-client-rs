use aes_gcm::{Aes128Gcm, Nonce};
use aes_gcm::aead::{KeyInit, AeadInOut};

fn main() {
    let key = [0x42u8; 16];
    let n = [0x24u8; 12];
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let nonce = Nonce::clone_from_slice(&n);
    let mut buf = b"hello".to_vec();
    let tag = cipher.encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into()).unwrap();
    buf.extend_from_slice(&tag);
}
