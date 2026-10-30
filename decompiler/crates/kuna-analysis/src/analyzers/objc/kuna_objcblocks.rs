//! (kuna) Global blocks: a block literal the compiler laid out in `__const` —
//! `isa = _NSConcreteGlobalBlock, flags, reserved, invoke, descriptor` — is
//! named and typed as a `Block_layout`, and its invoke function is named and,
//! when the descriptor carries a signature (`BLOCK_HAS_SIGNATURE`), typed from
//! it: `long block_invoke_1000071c(Block_layout *block, long arg1)`. The same
//! shape Hex-Rays applies from its TIL's `Block_layout` / `Block_descriptor_1`.
//!
//! A stack block is built by its creator at run time (the isa store to a frame
//! slot); recognizing one needs the creator's dataflow and is not done here.

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

#[cfg(test)]
mod tests {
    use super::*;
    use kuna_decomp::dtype::TypeFactoryImpl;

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
