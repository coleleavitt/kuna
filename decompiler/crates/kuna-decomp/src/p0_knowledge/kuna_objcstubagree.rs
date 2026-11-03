//! (kuna `objcstubagree`) The load-time gate for typing selector stubs only
//! from agreeing declarations.
//!
//! One `objc_msgSend$<sel>` stub serves every receiver of its selector, so the
//! prototype the `objc` pass gives it is a claim about all of them. The pass
//! runs while the loader snapshots the image, upstream of every console
//! `option`, so the choice travels as a process environment variable the way
//! `objcivars` does.

/// Environment variable carrying the `objcstubagree` choice into the load path.
/// Unset means on.
pub const OBJCSTUBAGREE_ENV: &str = "KUNA_OBJCSTUBAGREE";

/// Whether a stub is typed only from agreeing declarations.
pub fn objcstubagree_enabled() -> bool {
    match std::env::var(OBJCSTUBAGREE_ENV) {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false" | "no"),
        Err(_) => true,
    }
}

/// Bridge a `set_kuna_option("objcstubagree", val)` choice to
/// [`OBJCSTUBAGREE_ENV`] so a later `load file` in the same process sees it.
pub fn set_objcstubagree_env(on: bool) {
    std::env::set_var(OBJCSTUBAGREE_ENV, if on { "on" } else { "off" });
}
