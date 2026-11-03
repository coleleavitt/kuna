//! (kuna `dyldcrossrefs`) An untyped address inside another dyld cache image's
//! data prints relative to the symbol holding it.
//!
//! A load through a GOT slot the cache builder bound to another image's data
//! folds to that data's address, so `slot + 8` folds to a bare constant eight
//! bytes into the symbol (Swift's full type metadata address points). The
//! constant pointer recovery names only a constant that hits a symbol's start,
//! or lands inside a symbol a pointer type already reaches; this one is
//! neither. The loader reports the extent of each symbol the image takes the
//! address of (`Architecture::interior_data`, empty off the dyld cache path),
//! and a pointer-sized, non-pointer constant past the start of one prints
//! `((unsigned char *)&sym + 0x8)`, the spelling `kuna_namedglobals` gives a
//! pointer into a named object.

use kuna_base::address::Address;

use crate::architecture::Architecture;
use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;

/// The expression for the `ct`-typed constant `offset`, when it lies past the
/// start of an extent the loader reported.
pub fn expression(fd: &Funcdata, arch: &Architecture, ct: &Datatype, offset: u64) -> Option<String> {
    let context = fd.get_arch();
    if context.interior_data.is_empty()
        || matches!(
            ct.get_metatype(),
            type_metatype::TYPE_PTR | type_metatype::TYPE_PTRREL | type_metatype::TYPE_FLOAT | type_metatype::TYPE_CODE
        )
        || ct.get_size() != arch.types().get_size_of_pointer()
    {
        return None;
    }
    let start = context.interior_data_start(offset)?;
    let delta = offset.checked_sub(start).filter(|&d| d != 0)?;
    let data = arch.manage().get_default_data_space()?;
    if data.get_word_size() != 1 {
        return None;
    }
    let base = Address::new(data.clone(), start);
    let invalid = Address::new_invalid();
    let entry = context.query_container_global(&base, 1, &invalid)?;
    if entry.entry_addr != base || entry.symbol_offset != 0 {
        return None;
    }
    let (name, _, _) = context.name_for_global_varnode(&base, 1, &invalid)?;
    Some(format!("((unsigned char *)&{name} + 0x{delta:x})"))
}
