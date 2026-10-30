//! (kuna `dwarfscopes`) Where a subprogram's frame base is, and which
//! locals besides its direct children are fixed stack objects.
//!
//! `DW_OP_fbreg` is relative to `DW_AT_frame_base`. gcc states the frame base
//! as `DW_OP_call_frame_cfa`; clang at -O0 states the frame-pointer register
//! (`DW_OP_reg6` RBP on x86-64, `DW_OP_reg5` EBP on i386, `DW_OP_reg29` on
//! AArch64, `DW_OP_reg8` s0 on RISC-V), which the standard prologue leaves at a
//! fixed distance from the CFA. Any other register frame base moves with the
//! function body, so its locals are not placed at all.
//!
//! With `dwarfscopes` on (the default) a local nested in `DW_TAG_lexical_block`
//! scopes is collected like a direct child, and a variable whose location is a
//! location list takes the stack slot when every frame-relative entry of the
//! list names the same one (a value spilled to one slot for part of its life).

use super::{kuna_dwarflocation, Reader};

pub const DWARFSCOPES_ENV: &str = "KUNA_DWARFSCOPES";

pub fn enabled() -> bool {
    std::env::var(DWARFSCOPES_ENV).map_or(true, |v| !matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameBase {
    Cfa,
    Register(u16),
    Other,
}

pub fn frame_base(value: &gimli::AttributeValue<Reader<'_>>) -> Option<FrameBase> {
    let bytes = match value {
        gimli::AttributeValue::Exprloc(e) => e.0.slice(),
        gimli::AttributeValue::Block(b) => b.slice(),
        _ => return Some(FrameBase::Other),
    };
    Some(match bytes {
        [0x9c] => FrameBase::Cfa,
        [op @ 0x50..=0x6f] => FrameBase::Register(u16::from(op - 0x50)),
        [0x90, n] if *n < 0x80 => FrameBase::Register(u16::from(*n)),
        _ => FrameBase::Other,
    })
}

/// The stack offset of the frame base, given the target's CFA constant.
pub fn frame_base_offset(base: Option<FrameBase>, cfa: i64) -> Option<i64> {
    match base {
        None | Some(FrameBase::Cfa) => Some(cfa),
        Some(FrameBase::Register(reg)) => match (cfa, reg) {
            (8, 6) => Some(cfa - 16),
            (4, 5) => Some(cfa - 8),
            (0, 29) => Some(cfa - 16),
            (8, 8) => Some(cfa),
            _ => None,
        },
        Some(FrameBase::Other) => None,
    }
}

/// The one frame-base offset every frame-relative entry of a location list
/// names, when the location is a list.
pub fn loclist_frame_offset<'a>(
    dwarf: &gimli::Dwarf<Reader<'a>>,
    unit: &gimli::Unit<Reader<'a>>,
    location: &gimli::AttributeValue<Reader<'a>>,
) -> Option<i64> {
    if matches!(location, gimli::AttributeValue::Exprloc(_) | gimli::AttributeValue::Block(_)) {
        return None;
    }
    let mut list = dwarf.attr_locations(unit, location.clone()).ok()??;
    let mut found = None;
    for _ in 0..4096 {
        let Some(entry) = list.next().ok()? else { return found };
        if let Some(off) = kuna_dwarflocation::frame_offset(entry.data.0.slice()) {
            if found.is_some_and(|f| f != off) {
                return None;
            }
            found = Some(off);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_pointer_bases_sit_below_the_cfa() {
        assert_eq!(frame_base_offset(Some(FrameBase::Register(6)), 8), Some(-8));
        assert_eq!(frame_base_offset(Some(FrameBase::Register(5)), 4), Some(-4));
        assert_eq!(frame_base_offset(Some(FrameBase::Register(29)), 0), Some(-16));
        assert_eq!(frame_base_offset(Some(FrameBase::Cfa), 8), Some(8));
        assert_eq!(frame_base_offset(Some(FrameBase::Register(7)), 8), None);
    }
}
