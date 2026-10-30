//! (kuna `xnutables`) What a typed allocation returns, from its view.
//!
//! XNU's typed allocators (`kalloc_type_impl`, `IOMallocTypeImpl`,
//! `OSObject_typed_operator_new`, ...) take a `kalloc_type_view` whose
//! `kt_signature` describes the allocated type one 8-byte granule per
//! character, and return a `void *`. The XNU table analysis
//! (`kuna-analysis/src/analyzers/iokit/tables.rs`) builds a struct from every
//! view's signature and hands the engine the map from view to struct
//! ([`KallocTypes`]). [`allocated_type`] answers `TypeOpCall::getOutputLocal`
//! for a call to one of the allocators whose view argument folds to a view in
//! that map, so `v = OSObject_typed_operator_new(IOSurfaceClient_ktv, 0x98)`
//! is an `IOSurfaceClient *` and the stores into it are its fields.

use std::collections::HashMap;
use std::rc::Rc;

use crate::context::OpId;
use crate::dtype::Datatype;
use crate::funcdata::Funcdata;
use crate::p4_calls::fspec::FuncCallSpecs;

/// XNU's typed allocator entry points: (name, returns the allocation,
/// parameter count). The first parameter is the view.
pub const TYPED_ALLOCATORS: &[(&str, bool, usize)] = &[
    ("kalloc_type_impl", true, 2),
    ("kalloc_type_impl_external", true, 2),
    ("kfree_type_impl_external", false, 2),
    ("kalloc_type_var_impl", true, 4),
    ("kfree_type_var_impl", false, 3),
    ("IOMallocTypeImpl", true, 1),
    ("IOFreeTypeImpl", false, 2),
    ("IOMallocTypeVarImpl", true, 2),
    ("IOFreeTypeVarImpl", false, 3),
    ("OSObject_typed_operator_new", true, 2),
    ("OSObject_typed_operator_delete", false, 3),
];

/// View address -> the struct the view allocates.
pub type KallocTypes = HashMap<u64, Rc<Datatype>>;

/// `TypeOpCall::getOutputLocal` for a typed allocation: a pointer to the
/// struct of the view the call passes, when that view is known.
pub fn allocated_type(data: &Funcdata, op: OpId, fc: &FuncCallSpecs) -> Option<Rc<Datatype>> {
    let arch = data.get_arch();
    if arch.kuna_kalloc_types.is_empty() {
        return None;
    }
    let name = fc.get_name();
    TYPED_ALLOCATORS.iter().find(|(n, returns, _)| *returns && *n == name)?;
    let view = data.obank().get(op)?.get_in(1)?;
    let st = arch.kuna_kalloc_types.get(&crate::kuna_objcrettype::constant_address(data, view, 0)?)?;
    let types = arch.types()?;
    let space = arch.manage.get_default_data_space()?;
    types.get_type_pointer(space.get_addr_size() as i32, Rc::clone(st), space.get_word_size()).ok()
}
