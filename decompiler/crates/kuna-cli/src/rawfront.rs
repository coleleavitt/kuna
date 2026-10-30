//! Firmware front end: a raw Cortex-M dump gets the `--raw-image --target
//! --base --entry` arguments it would otherwise need by hand, from its vector
//! table (`kuna_analysis::loader::firmware`).
//!
//! Runs before the subcommand parses its arguments, for the subcommands that
//! take a raw image. The binary must be the first argument.

use kuna_analysis::loader::firmware::cortexm;

const RAW_COMMANDS: [&str; 4] = ["decompile", "decompile-all", "decompile-project", "functions"];
const CORTEX_TARGET: &str = "ARM:LE:32:Cortex";
/// The ARMv7-M/ARMv8-M Device memory regions: Peripheral and System (PPB).
const DEVICE_REGIONS: [&str; 2] = ["0x40000000+0x20000000", "0xe0000000+0x20000000"];

/// The arguments with the firmware layout filled in; `args` unchanged when
/// nothing applies.
pub fn prepare(sub: &str, args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    if !RAW_COMMANDS.contains(&sub) {
        return out;
    }
    let Some(binary) = args.first().filter(|a| !a.starts_with("--")) else { return out };
    let Ok(bytes) = std::fs::read(binary) else { return out };
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let raw = has("--raw-image");
    if !raw && is_object(&bytes) {
        return out;
    }
    let target = value("--target");
    let cortex = match &target {
        Some(t) => raw && t.starts_with("ARM:LE:32"),
        None => !raw,
    };
    if !cortex || has("--base") {
        return out;
    }
    let Some(table) = cortexm::probe(&bytes, None) else { return out };
    if !raw {
        out.push("--raw-image".into());
    }
    if target.is_none() {
        out.extend(["--target".into(), CORTEX_TARGET.into()]);
    }
    out.extend(["--base".into(), format!("{:#x}", table.base)]);
    if !has("--isa") {
        out.extend(["--isa".into(), "thumb".into()]);
    }
    if sub != "decompile" && !has("--entry") && !has("--addr") {
        for h in &table.handlers {
            out.extend(["--entry".into(), format!("{:#x}", h.addr)]);
        }
    }
    for device in DEVICE_REGIONS {
        out.extend(["--assert".into(), format!("volatile {device}")]);
    }
    for h in &table.handlers {
        out.extend(["--define-function".into(), format!("{:#x}={}", h.addr, h.name)]);
    }
    eprintln!(
        "[kuna firmware] Cortex-M vector table: base {:#x}, initial SP {:#x}, {} handlers, reset {:#x}",
        table.base,
        table.initial_sp,
        table.handlers.len(),
        table.reset()
    );
    out
}

/// Formats the loader parses itself.
fn is_object(bytes: &[u8]) -> bool {
    let magic = bytes.get(..4).unwrap_or(&[]);
    magic == b"\x7fELF"
        || magic.starts_with(b"MZ")
        || magic.starts_with(b"VZ")
        || matches!(magic, [0xfe | 0xce | 0xcf | 0xca, 0xed | 0xfa | 0xfe, ..])
        || magic == b"dyld"
        || magic == b"!<ar"
}
