pub mod aead;
/// Password-to-key derivation mirroring the C `bytes_to_key` (ssr-n/src/encrypt.c).
pub mod bytes_to_key;
/// Per-connection cipher state: derived key, IV handling and encrypt/decrypt contexts.
pub mod cipher_env;
/// One-shot encrypt/decrypt for the non-AEAD stream ciphers.
pub mod stream;
/// `table` method: password-derived 256-byte encrypt/decrypt substitution tables.
pub mod table;
/// Wire enums `CipherType`, `ProtocolType`, `ObfsType` and `TargetAddr`.
pub mod types;

pub use types::{CipherType, ObfsType, ProtocolType, TargetAddr};
