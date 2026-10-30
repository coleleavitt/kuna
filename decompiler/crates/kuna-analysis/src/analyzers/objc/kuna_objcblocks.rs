//! (kuna) Global blocks: a block literal the compiler laid out in `__const` —
//! `isa = _NSConcreteGlobalBlock, flags, reserved, invoke, descriptor` — is
//! named and typed as a `Block_layout`, and its invoke function is named and,
//! when the descriptor carries a signature (`BLOCK_HAS_SIGNATURE`), typed from
//! it: `long block_invoke_1000071c(Block_layout *block, long arg1)`. The same
//! shape Hex-Rays applies from its TIL's `Block_layout` / `Block_descriptor_1`.
//!
//! A stack block is built by its creator at run time: `isa = _NSConcreteStackBlock`
//! stored to a frame slot, the invoke and descriptor addresses stored 16 and 24
//! bytes after it. [`stack_blocks`] finds those stores in arm64 code (the
//! `adrp`/`ldr` of the isa's GOT slot, the `adrp`/`add` of the two addresses,
//! `str`/`stp` to `sp`), names the invoke after its creator
//! (`-[Runner maker:]_block_invoke`) and types it from the descriptor's
//! signature, the way Hex-Rays reads the creator's microcode for the same stores.

use std::rc::Rc;

use kuna_decomp::dtype::{type_metatype, Datatype, TypeFactory, TypeField};
use kuna_decomp::fspec::PrototypePieces;
use object::read::{Object, ObjectSection};

use super::encoding::{decode_ivar_type, split_method, TypeCtx};
use super::sections::MachoImage;
use crate::pass::{AnalysisOutput, FidMatch, SymFact, SymKind, TypedDataFact};

/// `Block_layout.flags` bit: the descriptor has copy/dispose helpers.
const BLOCK_HAS_COPY_DISPOSE: u32 = 1 << 25;
/// `Block_layout.flags` bit: the descriptor has a signature string.
const BLOCK_HAS_SIGNATURE: u32 = 1 << 30;

/// The `Block_layout` struct, interned once: `isa`, `flags`, `reserved`,
/// `invoke`, `descriptor`.
fn block_layout(tctx: &TypeCtx) -> Option<Rc<Datatype>> {
    let types: &dyn TypeFactory = tctx.types;
    if let Some(t) = types.find_by_name("Block_layout").ok().flatten() {
        return (t.get_metatype() == type_metatype::TYPE_STRUCT).then_some(t);
    }
    let ps = tctx.ptr_size;
    let shell = types.kuna_declare_record("Block_layout", false).ok()?;
    let voidp = decode_ivar_type("^v", tctx)?;
    let int = decode_ivar_type("i", tctx)?;
    let fields = vec![
        TypeField::new(0, 0, "isa".to_string(), Rc::clone(&voidp)),
        TypeField::new(ps, ps, "flags".to_string(), Rc::clone(&int)),
        TypeField::new(ps + 4, ps + 4, "reserved".to_string(), int),
        TypeField::new(2 * ps, 2 * ps, "invoke".to_string(), Rc::clone(&voidp)),
        TypeField::new(3 * ps, 3 * ps, "descriptor".to_string(), voidp),
    ];
    types.set_fields_struct_raw(&shell, fields, Vec::new(), 4 * ps, ps, 0).ok()
}

/// The struct of one block with captures: `Block_layout` at 0, then a word per
/// captured value up to the descriptor's `size` (`Block_layout_<invoke>`).
/// The plain `Block_layout` when the descriptor says nothing is captured.
fn captured_layout(img: &MachoImage, desc: Option<u64>, invoke: u64, tctx: &TypeCtx, layout: &Rc<Datatype>) -> Rc<Datatype> {
    let ps = tctx.ptr_size;
    let Some(size) = desc.and_then(|d| img.read_ptr(d.wrapping_add(8))).map(|s| s as i32) else { return Rc::clone(layout) };
    if size <= 4 * ps || size > 1 << 16 || size % ps != 0 {
        return Rc::clone(layout);
    }
    let name = format!("Block_layout_{invoke:x}");
    let types: &dyn TypeFactory = tctx.types;
    if let Some(t) = types.find_by_name(&name).ok().flatten() {
        return t;
    }
    let Some(word) = decode_ivar_type("Q", tctx) else { return Rc::clone(layout) };
    let mut fields = vec![TypeField::new(0, 0, "block".to_string(), Rc::clone(layout))];
    for (k, off) in (4 * ps..size).step_by(ps as usize).enumerate() {
        fields.push(TypeField::new(off, off, format!("capture_{k}"), Rc::clone(&word)));
    }
    types
        .kuna_declare_record(&name, false)
        .ok()
        .and_then(|shell| types.set_fields_struct_raw(&shell, fields, Vec::new(), size, ps, 0).ok())
        .unwrap_or_else(|| Rc::clone(layout))
}

/// The invoke function's prototype from the block signature
/// (`q16@?0q8` → `long f(Block_layout *block, long arg1)`).
fn invoke_prototype(name: &str, signature: &str, tctx: &TypeCtx, layout: &Rc<Datatype>) -> Option<PrototypePieces> {
    let (ret, args) = split_method(signature)?;
    if args.first().map(String::as_str) != Some("@?") {
        return None;
    }
    let mut p = PrototypePieces {
        name: name.to_string(),
        outtype: Some(decode_ivar_type(&ret, tctx)?),
        first_var_arg_slot: -1,
        ..Default::default()
    };
    p.intypes.push(tctx.types.get_type_pointer(tctx.ptr_size, Rc::clone(layout), tctx.word_size).ok()?);
    p.innames.push("block".into());
    for (i, a) in args.iter().enumerate().skip(1) {
        p.intypes.push(decode_ivar_type(a, tctx)?);
        p.innames.push(format!("arg{i}"));
    }
    Some(p)
}

/// Name and type every global block literal of `file` and its invoke function.
pub fn emit(img: &MachoImage, file: &object::File, tctx: &TypeCtx, out: &mut AnalysisOutput) {
    let ps = img.ptr_size();
    let mut layout = None;
    for sec in file.sections() {
        if sec.name().ok() != Some("__const") {
            continue;
        }
        for i in 0..sec.size() / ps {
            let va = sec.address() + i * ps;
            if img.bind_name(va).map(|n| n.trim_start_matches('_')) != Some("NSConcreteGlobalBlock") {
                continue;
            }
            let Some(flags) = img.read_u32(va + ps) else { continue };
            let Some(invoke) = img.rebase_ptr(va + 2 * ps) else { continue };
            let Some(layout) = layout.get_or_insert_with(|| block_layout(tctx)).as_ref() else { return };
            out.typed_data.push(TypedDataFact {
                addr: va,
                name: format!("block_literal_{va:x}"),
                type_: Rc::clone(layout),
            });
            let label = format!("block_invoke_{invoke:x}");
            out.symbols.push(SymFact { addr: invoke, name: label.clone(), kind: SymKind::Function });
            out.fid_names.push(FidMatch { addr: invoke, name: label.clone() });
            if flags & BLOCK_HAS_SIGNATURE == 0 {
                continue;
            }
            let Some(desc) = img.rebase_ptr(va + 3 * ps) else { continue };
            let sig_slot = desc + 2 * ps + if flags & BLOCK_HAS_COPY_DISPOSE != 0 { 2 * ps } else { 0 };
            let Some(sig) = img.rebase_ptr(sig_slot).and_then(|s| img.read_cstr(s)) else { continue };
            if let Some(p) = invoke_prototype(&label, &sig, tctx, layout) {
                out.prototypes_at.push((invoke, p));
            }
        }
    }
}

/// What an arm64 register holds while the creator is scanned.
#[derive(Clone, Copy, PartialEq)]
enum Held {
    Page(u64),
    Addr(u64),
    Isa,
}

/// The stack blocks of every arm64 function: `(creator pc, invoke, descriptor)`.
fn stack_block_sites(text: &[(u64, &[u8])], isa_slots: &[u64]) -> Vec<(u64, u64, Option<u64>)> {
    let mut out = Vec::new();
    for &(base, data) in text {
        let mut regs: [Option<Held>; 32] = [None; 32];
        let mut isa_at: Vec<(u64, u64)> = Vec::new();
        let mut found: Vec<(u64, u64, Option<u64>)> = Vec::new();
        for (i, c) in data.chunks_exact(4).enumerate() {
            let w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            let pc = base + 4 * i as u64;
            let rd = (w & 0x1f) as usize;
            let rn = ((w >> 5) & 0x1f) as usize;
            if w & 0x9F00_0000 == 0x9000_0000 {
                let imm = ((((w >> 5) & 0x7FFFF) << 2 | (w >> 29) & 0x3) as i32) << 11 >> 11;
                regs[rd] = Some(Held::Page((pc & !0xFFF).wrapping_add((imm as i64 as u64) << 12)));
            } else if w & 0x9F00_0000 == 0x1000_0000 {
                // `adr` (the linker's relaxation of `adrp; add`).
                let imm = ((((w >> 5) & 0x7FFFF) << 2 | (w >> 29) & 0x3) as i32) << 11 >> 11;
                regs[rd] = Some(Held::Addr(pc.wrapping_add(imm as i64 as u64)));
            } else if w & 0xFF00_0000 == 0x5800_0000 {
                // `ldr x, <literal>` (the relaxation of `adrp; ldr` from a GOT slot).
                let imm = (((w >> 5) & 0x7FFFF) as i32) << 13 >> 13;
                let slot = pc.wrapping_add((imm as i64 * 4) as u64);
                regs[rd] = isa_slots.contains(&slot).then_some(Held::Isa);
            } else if w & 0xFF80_0000 == 0x9100_0000 {
                let imm = ((w >> 10) & 0xFFF) as u64;
                let imm = if w & (1 << 22) != 0 { imm << 12 } else { imm };
                regs[rd] = match regs[rn] {
                    Some(Held::Page(p)) if rn != 31 => Some(Held::Addr(p.wrapping_add(imm))),
                    _ => None,
                };
            } else if w & 0xFFC0_0000 == 0xF940_0000 {
                let slot = match regs[rn] {
                    Some(Held::Page(p)) => p.wrapping_add(((w >> 10) & 0xFFF) as u64 * 8),
                    _ => 0,
                };
                regs[rd] = isa_slots.contains(&slot).then_some(Held::Isa);
            } else if w & 0xFFC0_0000 == 0xF900_0000 && rn == 31 {
                stack_store(&mut isa_at, &mut found, pc, ((w >> 10) & 0xFFF) as u64 * 8, regs[rd]);
            } else if w & 0xFFC0_0000 == 0xA900_0000 && rn == 31 {
                let off = (((w >> 15) & 0x7F) as i8) << 1 >> 1;
                let off = (off as i64 * 8) as u64;
                let rt2 = ((w >> 10) & 0x1f) as usize;
                stack_store(&mut isa_at, &mut found, pc, off, regs[rd]);
                stack_store(&mut isa_at, &mut found, pc, off.wrapping_add(8), regs[rt2]);
            } else if w == 0xD65F_03C0 {
                regs = [None; 32];
                isa_at.clear();
            }
        }
        out.extend(found);
    }
    out
}

fn stack_store(isa_at: &mut Vec<(u64, u64)>, found: &mut Vec<(u64, u64, Option<u64>)>, pc: u64, off: u64, held: Option<Held>) {
    match held {
        Some(Held::Isa) => isa_at.push((off, pc)),
        Some(Held::Addr(a)) => {
            if let Some(&(_, at)) = isa_at.iter().find(|&&(o, _)| off == o.wrapping_add(16)) {
                found.push((at, a, None));
            } else if let Some(&(_, at)) = isa_at.iter().find(|&&(o, _)| off == o.wrapping_add(24)) {
                if let Some(f) = found.iter_mut().find(|f| f.0 == at && f.2.is_none()) {
                    f.2 = Some(a);
                }
            }
        }
        _ => {}
    }
}

/// The signature a block descriptor carries, at +16 (no copy/dispose helpers)
/// or +32 (with them): the one that reads as a block encoding.
fn descriptor_signature(img: &MachoImage, desc: u64) -> Option<String> {
    [16u64, 32].iter().find_map(|&at| {
        let s = img.rebase_ptr(desc.wrapping_add(at)).and_then(|p| img.read_cstr(p))?;
        s.contains("@?").then_some(s)
    })
}

/// Name every stack block's invoke function after the function that builds it
/// and type it from the block descriptor's signature.
pub fn stack_blocks(img: &MachoImage, file: &object::File, tctx: &TypeCtx, creators: &[(u64, String)], out: &mut AnalysisOutput) {
    if file.architecture() != object::Architecture::Aarch64 {
        return;
    }
    let ps = img.ptr_size();
    let mut isa_slots = Vec::new();
    for sec in file.sections() {
        if !sec.name().ok().is_some_and(|n| n.ends_with("got") || n.ends_with("symbol_ptr")) {
            continue;
        }
        for i in 0..sec.size() / ps {
            let va = sec.address() + i * ps;
            if img.bind_name(va).map(|n| n.trim_start_matches('_')) == Some("NSConcreteStackBlock") {
                isa_slots.push(va);
            }
        }
    }
    if isa_slots.is_empty() {
        return;
    }
    let text: Vec<(u64, &[u8])> = file
        .sections()
        .filter(|s| s.name().ok() == Some("__text"))
        .filter_map(|s| Some((s.address(), s.data().ok()?)))
        .collect();
    let mut creators: Vec<(u64, String)> = creators.to_vec();
    creators.sort();
    let mut layout = None;
    let mut per_creator: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for (pc, invoke, desc) in stack_block_sites(&text, &isa_slots) {
        if img.read(invoke, 4).is_none() {
            continue;
        }
        let creator = match creators.iter().rev().find(|(start, _)| *start <= pc) {
            Some((_, name)) => name.clone(),
            None => format!("sub_{pc:x}"),
        };
        let n = per_creator.entry(creator.clone()).or_default();
        *n += 1;
        let label = if *n == 1 { format!("{creator}_block_invoke") } else { format!("{creator}_block_invoke_{n}") };
        out.symbols.push(SymFact { addr: invoke, name: label.clone(), kind: SymKind::Function });
        out.fid_names.push(FidMatch { addr: invoke, name: label.clone() });
        let Some(sig) = desc.and_then(|d| descriptor_signature(img, d)) else { continue };
        let Some(layout) = layout.get_or_insert_with(|| block_layout(tctx)).as_ref() else { return };
        let this = captured_layout(img, desc, invoke, tctx, layout);
        if let Some(p) = invoke_prototype(&label, &sig, tctx, &this) {
            out.prototypes_at.push((invoke, p));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuna_decomp::dtype::TypeFactoryImpl;

    /// `-[Runner maker:]` at 0x1000: `adrp x9, got; ldr x9, [x9, #0x10]` (the
    /// `_NSConcreteStackBlock` slot at 0x8010), `str x9, [sp, #8]`, then the
    /// invoke and descriptor materialized and stored as a pair at `[sp, #24]`.
    #[test]
    fn stack_block_stores_name_the_invoke_and_descriptor() {
        let words: [u32; 8] = [
            0x9000_0009, // adrp x9, page (imm 0: the page of pc, 0x1000)
            0xF940_0929, // ldr x9, [x9, #0x10]
            0xF900_07E9, // str x9, [sp, #8]
            0x9000_0009, // adrp x9, page
            0x9100_8129, // add x9, x9, #0x20
            0x9000_000A, // adrp x10, page
            0x9101_014A, // add x10, x10, #0x40
            0xA901_ABE9, // stp x9, x10, [sp, #24]
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let sites = stack_block_sites(&[(0x1000, &bytes)], &[0x1010]);
        assert_eq!(sites, vec![(0x1008, 0x1020, Some(0x1040))]);
        assert!(stack_block_sites(&[(0x1000, &bytes)], &[0x9999]).is_empty(), "another slot is not the isa");
    }

    #[test]
    fn signature_names_the_block_first() {
        let f = TypeFactoryImpl::new();
        f.set_default_alignment_map();
        f.set_max_basetype_size(8);
        f.setup_sizes(Some(8), 8, 4);
        let _ = f.cache_core_types();
        let tctx = TypeCtx::new(&f, 8, 1);
        let layout = block_layout(&tctx).unwrap();
        assert_eq!(layout.get_size(), 32);
        let p = invoke_prototype("block_invoke_1", "q16@?0q8", &tctx, &layout).unwrap();
        assert_eq!(p.innames, ["block", "arg1"]);
        assert_eq!(p.intypes[0].get_ptr_to().unwrap().get_name(), "Block_layout");
        assert!(invoke_prototype("b", "v16@0:8", &tctx, &layout).is_none(), "a method signature is not a block's");
    }
}
