//! (kuna) The `machobinds` option gate: name every Mach-O pointer slot a bind
//! fills (chained-fixup binds and classic bind opcodes), not only the slots the
//! indirect-symbol table names.
//!
//! The names are added while the loader resolves imports, inside `load file`,
//! upstream of every `option` command, so the gate travels as the
//! [`MACHOBINDS_ENV`] environment variable (the `dynrelocs` loadtime pattern).

/// Off unless set to an on-token: on a Swift-heavy app the binds name tens of
/// thousands of metadata slots, all of which join the function inventory.
pub const MACHOBINDS_ENV: &str = "KUNA_MACHOBINDS";

pub fn machobinds_enabled() -> bool {
    crate::options::env_toggle(MACHOBINDS_ENV, false)
}

pub fn set_machobinds_env(on: bool) {
    std::env::set_var(MACHOBINDS_ENV, if on { "on" } else { "off" });
}
