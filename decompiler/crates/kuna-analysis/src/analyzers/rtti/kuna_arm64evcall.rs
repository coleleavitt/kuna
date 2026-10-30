//! (kuna `arm64evcall`) Resolve arm64e C++ virtual calls by their pointer-auth
//! discriminator.
//!
//! arm64e signs every vtable slot with key IA, address diversity and a 16-bit
//! constant: the hash of the method's mangled name. The constant survives in
//! two places a stripped image keeps. Each slot's chained fixup carries it as
//! the entry's diversifier, and every virtual call site re-materializes it to
//! authenticate the loaded pointer:
//!
//! ```text
//!   autda x16, x17           ; the vtable pointer
//!   ldr   x8, [x16, #0x10]!  ; slot 2, x16 = &slot
//!   mov   x9, x16
//!   mov   x17, x9
//!   movk  x17, #0x4444, lsl #48
//!   blraa x8, x17            ; key IA, discriminator &slot | 0x4444 << 48
//! ```
//!
//! So `(slot index, diversifier)` names a method without any class type, the
//! way IDA's arm64 module resolves these calls. [`index_vtables`] files every
//! run of consecutive IA-signed slots in a `__const` section under
//! `(i, diversifier)`; [`call_sites`] walks back from each `blraa`/`braa` with
//! a register modifier to the `movk #d, lsl #48` and the vtable-pointer load,
//! summing the slot offset on the way. The walk reads raw A64 words: the
//! lifted p-code has already dropped the modifier operand.

use std::collections::{BTreeMap, HashMap};

use object::read::{Object, ObjectSection, ObjectSymbol};

use crate::loader::format::macho::{resolve_chained_fixups, ChainedFixups};
use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, Phase};

/// The arm64e virtual-call pass (gate id `arm64evcall`).
#[derive(Clone, Copy, Default)]
pub struct Arm64eVcallPass;

impl AnalysisPass for Arm64eVcallPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "arm64evcall"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        AnalysisOutput { vcall_sites: resolve(ctx.file, ctx.bytes), ..AnalysisOutput::default() }
    }
}

/// An arm64e virtual call site and the methods its slot can hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcallSite {
    /// Address of the `blraa`/`braa`.
    pub site: u64,
    /// Every function a vtable of this image holds at the slot, sorted.
    pub targets: Vec<u64>,
}

/// The IA key, the one C++ virtual-function slots are signed with.
const KEY_IA: u8 = 0;

/// The longest backward walk from a call site, IDA's bound.
const MAX_WALK: usize = 24;

/// Every resolved virtual call site of an arm64e Mach-O `file`. Empty for any
/// other image.
pub fn resolve(file: &object::File, bytes: &[u8]) -> Vec<VcallSite> {
    if file.format() != object::BinaryFormat::MachO || file.architecture() != object::Architecture::Aarch64 {
        return Vec::new();
    }
    let fixups = resolve_chained_fixups(file, bytes);
    let index = index_vtables(file, &fixups);
    if index.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for section in file.sections() {
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        let Ok(data) = section.data() else { continue };
        for (site, slot) in call_sites(section.address(), data) {
            if let Some(targets) = index.get(&slot) {
                out.push(VcallSite { site, targets: targets.clone() });
            }
        }
    }
    out
}

/// `(slot index, diversifier) → sorted method addresses` over every run of
/// consecutive IA-signed, address-diversified slots in a `__const` section. A
/// slot holding a bind (an inherited method of another image) keeps its place
/// in the run but adds no target; so do the pure and deleted virtual traps.
pub fn index_vtables(file: &object::File, fixups: &ChainedFixups) -> HashMap<(u32, u16), Vec<u64>> {
    let ranges: Vec<(u64, u64)> = file
        .sections()
        .filter(|s| s.name() == Ok("__const") && s.kind() != object::SectionKind::Text)
        .map(|s| (s.address(), s.address() + s.size()))
        .collect();
    let mut slots: Vec<(u64, u16)> = fixups
        .auth_slots()
        .filter(|(_, ctx)| ctx.key == KEY_IA && ctx.addr_div)
        .filter(|&(va, _)| ranges.iter().any(|&(lo, hi)| va >= lo && va < hi))
        .map(|(va, ctx)| (va, ctx.diversity))
        .collect();
    slots.sort_unstable();
    let traps: Vec<u64> = file
        .symbols()
        .filter(|s| s.name().is_ok_and(|n| n.contains("cxa_pure_virtual") || n.contains("cxa_deleted_virtual")))
        .map(|s| s.address())
        .collect();
    let mut index: BTreeMap<(u32, u16), Vec<u64>> = BTreeMap::new();
    let mut run_start = 0usize;
    for (i, &(va, diversity)) in slots.iter().enumerate() {
        if i > 0 && slots[i - 1].0 + 8 != va {
            run_start = i;
        }
        let Some(target) = fixups.resolved_ptr(va) else { continue };
        if traps.contains(&target) {
            continue;
        }
        index.entry(((i - run_start) as u32, diversity)).or_default().push(target);
    }
    index
        .into_iter()
        .map(|(key, mut targets)| {
            targets.sort_unstable();
            targets.dedup();
            (key, targets)
        })
        .collect()
}

/// Every `blraa`/`braa Xn, Xm` in `code` (mapped at `base`) whose modifier the
/// backward walk traces to a vtable slot, as `(site, (slot index,
/// diversifier))`.
pub fn call_sites(base: u64, code: &[u8]) -> Vec<(u64, (u32, u16))> {
    let words: Vec<u32> = code.chunks_exact(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
    let mut out = Vec::new();
    for (i, &w) in words.iter().enumerate() {
        if w & 0xFFDF_FC00 != 0xD71F_0800 {
            continue;
        }
        let lo = i.saturating_sub(MAX_WALK);
        if let Some(slot) = trace_modifier(&words[lo..i], (w & 31) as u8) {
            out.push((base + 4 * i as u64, slot));
        }
    }
    out
}

/// Walk `before` (the words ahead of the call, last one adjacent) backwards from
/// the modifier register `rm` to its `movk #d, lsl #48` and on to the
/// authenticated vtable-pointer load, summing every `add #imm` and pre-index
/// `ldr` writeback applied to the slot address. Any branch, or any other write
/// to the tracked register, ends the walk with no answer.
fn trace_modifier(before: &[u32], rm: u8) -> Option<(u32, u16)> {
    let mut tracked = rm;
    let mut diversity: Option<u16> = None;
    let mut offset: i64 = 0;
    for &w in before.iter().rev() {
        let rd = (w & 31) as u8;
        let rn = ((w >> 5) & 31) as u8;
        if is_branch(w) {
            return None;
        }
        if w & 0xFFE0_0000 == 0xF2E0_0000 {
            if rd == tracked {
                if diversity.is_some() {
                    return None;
                }
                diversity = Some(((w >> 5) & 0xFFFF) as u16);
            }
            continue;
        }
        if diversity.is_none() {
            if rd == tracked {
                return None;
            }
            continue;
        }
        if w & 0xFFE0_FFE0 == 0xAA00_03E0 {
            if rd == tracked {
                tracked = ((w >> 16) & 31) as u8;
            }
            continue;
        }
        if w & 0xFF80_0000 == 0x9100_0000 {
            if rd == tracked {
                let imm = ((w >> 10) & 0xFFF) as i64;
                offset += if (w >> 22) & 1 == 1 { imm << 12 } else { imm };
                tracked = rn;
            }
            continue;
        }
        if w & 0xFFE0_0C00 == 0xF840_0C00 {
            if rd == tracked {
                return None;
            }
            if rn == tracked {
                offset += ((((w >> 12) & 0x1FF) << 23) as i32 >> 23) as i64;
            }
            continue;
        }
        let vptr_auth = w & 0xFFFF_F800 == 0xDAC1_1800 || w & 0xFFFF_FBE0 == 0xDAC1_3BE0;
        let vptr_ldra = w & 0xFF20_0400 == 0xF820_0400;
        if (vptr_auth || vptr_ldra) && rd == tracked {
            if offset < 0 || offset % 8 != 0 {
                return None;
            }
            return Some(((offset / 8) as u32, diversity?));
        }
        if rd == tracked {
            return None;
        }
    }
    None
}

/// Is `w` an A64 branch of any kind (immediate, conditional, compare/test,
/// register)?
fn is_branch(w: u32) -> bool {
    w & 0x7C00_0000 == 0x1400_0000
        || w & 0xFF00_0010 == 0x5400_0000
        || w & 0x7E00_0000 == 0x3400_0000
        || w & 0x7E00_0000 == 0x3600_0000
        || w & 0xFE00_0000 == 0xD600_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// debugserver's virtual call: the vtable pointer authenticated with `autda`,
    /// slot 2 loaded with writeback, the slot address copied twice into x17.
    #[test]
    fn traces_the_debugserver_call_shape() {
        let code: [u32; 9] = [
            0xaa1403f1, // mov   x17, x20
            0xf2ec69f1, // movk  x17, #0x634f, lsl #48
            0xdac11a30, // autda x16, x17
            0xf8410e08, // ldr   x8, [x16, #0x10]!
            0xaa1003e9, // mov   x9, x16
            0xaa1403e0, // mov   x0, x20
            0xaa0903f1, // mov   x17, x9
            0xf2e88891, // movk  x17, #0x4444, lsl #48
            0xd73f0911, // blraa x8, x17
        ];
        let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(call_sites(0x1000, &bytes), vec![(0x1020, (2, 0x4444))]);
    }

    /// `macho_arm64e_vcall`: slot 1 holds `_A_g` in both vtables, slot 0 holds
    /// `_A_f` or `_B_f`.
    #[test]
    fn resolves_the_fixture_calls() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/macho_arm64e_vcall");
        let bytes = std::fs::read(path).expect("read fixture");
        let file = object::File::parse(bytes.as_slice()).expect("parse Mach-O");
        assert_eq!(
            resolve(&file, &bytes),
            vec![
                VcallSite { site: 0x10000035c, targets: vec![0x100000328, 0x100000338] },
                VcallSite { site: 0x10000037c, targets: vec![0x100000330] },
            ]
        );
    }

    /// A branch between the slot load and the call, or a modifier with no
    /// `movk`, resolves nothing.
    #[test]
    fn a_branch_or_a_plain_modifier_stops_the_walk() {
        let with_branch: [u32; 6] = [0xdac11a30, 0xf8410e08, 0x14000001, 0xaa1003f1, 0xf2e88891, 0xd73f0911];
        let bytes: Vec<u8> = with_branch.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert!(call_sites(0, &bytes).is_empty());
        let no_disc: [u32; 4] = [0xdac11a30, 0xf8410e08, 0xaa1003f1, 0xd73f0911];
        let bytes: Vec<u8> = no_disc.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert!(call_sites(0, &bytes).is_empty());
    }
}
