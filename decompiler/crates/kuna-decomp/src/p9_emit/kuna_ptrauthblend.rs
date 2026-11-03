//! (kuna `ptrauthblend`) An arm64e blended discriminator as the expression
//! that made it.
//!
//! Signing a pointer stored at an address-diversified slot takes the slot's
//! address with a 16-bit constant moved into its top bits (`movk x8, #d, lsl
//! #48` over `&slot`, which is `<ptrauth.h>`'s
//! `ptrauth_blend_discriminator(&slot, d)`). When that register is left as a
//! call argument the decompiler folds it to one 64-bit constant whose low 48
//! bits are the slot and whose top 16 are the constant, and prints it as a
//! number no reader can place (`0xaea0fff00a64e488`). [`blend`] recognizes a
//! constant whose top 16 bits are neither all zeros nor all ones and whose
//! low 48 bits, with the image's canonical top bits, land in a loaded data
//! section; it prints as `ptrauth_blend_discriminator(&gAKS,0xaea0)`.

use crate::architecture::Architecture;

/// `(slot address, constant)` when the 8-byte constant `val` is a blended
/// discriminator over a slot of a loaded data section.
pub fn blend(arch: &Architecture, val: u64, size: i32) -> Option<(u64, u16)> {
    if !arch.ptrauth_blend || size != 8 {
        return None;
    }
    let disc = (val >> 48) as u16;
    if disc == 0 || disc == 0xffff {
        return None;
    }
    let low = val & 0xffff_ffff_ffff;
    [low | 0xffff_0000_0000_0000, low]
        .into_iter()
        .find(|&p| crate::kuna_globalref::in_ranges(&arch.globalref_ranges, p))
        .map(|p| (p, disc))
}

/// The expression a blended discriminator prints as: the slot by name when
/// a global starts there, else by address.
pub fn expression(fd: &crate::funcdata::Funcdata, arch: &Architecture, slot: u64, disc: u16) -> Option<String> {
    let data = arch.manage().get_default_data_space()?;
    let addr = kuna_base::address::Address::new(data.clone(), slot);
    let named = fd
        .get_arch()
        .name_for_global_varnode_scoped(&addr, 1, &kuna_base::address::Address::new_invalid())
        .filter(|(_, off, _, _)| *off == 0)
        .map(|(name, _, _, mut scopes)| {
            scopes.push(name);
            format!("&{}", scopes.join("::"))
        });
    let slot = named.unwrap_or_else(|| format!("0x{slot:x}"));
    Some(format!("ptrauth_blend_discriminator({slot},0x{disc:x})"))
}
