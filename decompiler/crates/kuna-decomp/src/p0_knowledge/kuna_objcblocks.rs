//! (kuna `objcblocks`) The load-time gate of the Objective-C block refinements:
//! invokes named the way Clang names them (`__<len><creator>_block_invoke_<n>`),
//! a global block's invoke named after the function that references it, and
//! the `@?` type encoding read as `Block_layout *`. The pass runs while the
//! loader snapshots the image, upstream of every console `option`, so the
//! switch travels as a process environment variable (the `objcivars` pattern).

/// Environment variable carrying the `objcblocks` choice into the load path.
/// Unset means on.
pub const OBJCBLOCKS_ENV: &str = "KUNA_OBJCBLOCKS";

/// Whether the block refinements apply.
pub fn objcblocks_enabled() -> bool {
    match std::env::var(OBJCBLOCKS_ENV) {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false" | "no"),
        Err(_) => true,
    }
}

/// Bridge a `set_kuna_option("objcblocks", val)` choice to [`OBJCBLOCKS_ENV`]
/// so a later `load file` in the same process sees it.
pub fn set_objcblocks_env(on: bool) {
    std::env::set_var(OBJCBLOCKS_ENV, if on { "on" } else { "off" });
}
