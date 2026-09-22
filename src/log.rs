//! Runtime-gated debug logging.
//!
//! Wire-level tracing (hexdumps, per-packet sizes) is noisy and costs time on
//! every relayed chunk, so it is disabled by default. Set `SSR_DEBUG=1` to
//! enable it when diagnosing handshake or framing problems.

use std::sync::OnceLock;

/// Whether verbose wire-level logging is enabled.
pub fn debug_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| matches!(std::env::var("SSR_DEBUG"), Ok(v) if !v.is_empty() && v != "0"))
}

/// `eprintln!` that only fires when `SSR_DEBUG` is set.
#[macro_export]
macro_rules! ssr_debug {
    ($($arg:tt)*) => {
        if $crate::log::debug_enabled() {
            eprintln!($($arg)*);
        }
    };
}
