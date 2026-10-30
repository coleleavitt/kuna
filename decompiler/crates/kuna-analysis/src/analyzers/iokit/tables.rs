//! (kuna `xnutables`) XNU data tables that need no class knowledge to find:
//! `kalloc_type` views, `IOExternalMethodDispatch` tables, and pointer slots
//! (`__got`, `__auth_got`, `__auth_ptr`) the indirect-symbol table does not name.

use std::collections::{BTreeMap, HashMap};

use object::read::{Object, ObjectSection};

use super::{in_ranges, is_xnu_image, macho_flags, Recovered};
use crate::loader::format::macho::resolve_chained_fixups;
use crate::objc::sections::MachoImage;
use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, DataObjectFact, FidMatch, Phase, SymFact, SymKind};

const KALLOC_TYPE_VIEW: u64 = 0x40;
const KALLOC_TYPE_VAR_VIEW: u64 = 0x50;
const DISPATCH: u64 = 0x18;
const DISPATCH_2022: u64 = 0x28;
const MIN_DISPATCH_RUN: usize = 4;
const VARIABLE_SIZE: u32 = 0xffff_ffff;
const OWNER_SCAN: usize = 0x100;

#[derive(Default)]
pub struct XnuTablesPass;

impl AnalysisPass for XnuTablesPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "xnutables"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut out = AnalysisOutput::default();
        if ctx.file.format() != object::BinaryFormat::MachO
            || ctx.file.architecture() != object::Architecture::Aarch64
            || !is_xnu_image(ctx.file, ctx.bytes)
        {
            return out;
        }
        let img = MachoImage::with_fixups(ctx.file, resolve_chained_fixups(ctx.file, ctx.bytes));
        let rec = super::recover(ctx.file, &img);
        kalloc_views(ctx.file, &img, &rec, &mut out);
        allocator_prototypes(ctx, &rec, &mut out);
        dispatch_tables(ctx.file, &img, &rec, &mut out);
        pointer_slots(ctx.file, ctx.bytes, &img, &rec, &mut out);
        out
    }
}

/// A `site.<type>` view name as an identifier: `struct ` dropped, `*` spelled
/// `_ptr`, anything else outside `[A-Za-z0-9_]` turned into `_`.
fn view_type(site: &str) -> Option<String> {
    let t = site.strip_prefix("site.")?.trim();
    let t = t.strip_prefix("struct ").unwrap_or(t);
    let mut s = String::new();
    for c in t.chars() {
        match c {
            '*' => s.push_str("_ptr"),
            ' ' => {}
            c if c.is_ascii_alphanumeric() || c == '_' => s.push(c),
            _ => s.push('_'),
        }
    }
    let s = s.trim_matches('_').to_string();
    (!s.is_empty()).then_some(s)
}

fn unique(seen: &mut HashMap<String, usize>, name: String) -> String {
    let n = seen.entry(name.clone()).or_default();
    *n += 1;
    if *n == 1 { name } else { format!("{name}_{n}") }
}

/// `__kalloc_type` holds `kalloc_type_view` records (0x40 bytes, the view name
/// at +0x10 and the size at +0x2c); `__kalloc_var` holds `kalloc_type_var_view`
/// records (0x50 bytes, the name at +0x10). Each becomes a sized data object,
/// under its symbol or else named after its type (`kalloc_type_view_<T>`), and the typed allocator entry points get
/// prototypes whose view parameter is a pointer, so a view passed to one
/// renders by name.
pub(super) fn kalloc_views(file: &object::File, img: &MachoImage, rec: &Recovered, out: &mut AnalysisOutput) {
    let mut seen = HashMap::new();
    for sec in file.sections() {
        let (stride, suffix) = match sec.name() {
            Ok("__kalloc_type") => (KALLOC_TYPE_VIEW, "kalloc_type_view"),
            Ok("__kalloc_var") => (KALLOC_TYPE_VAR_VIEW, "kalloc_type_var_view"),
            _ => continue,
        };
        for k in 0..sec.size() / stride {
            let view = sec.address() + k * stride;
            let Some(t) = img.read_ptr(view + 0x10).and_then(|p| img.read_cstr(p)).and_then(|s| view_type(&s)) else {
                continue;
            };
            let name = match rec.names.get(&view) {
                Some(symbol) => symbol.clone(),
                None => unique(&mut seen, format!("{suffix}_{t}")),
            };
            out.data_objects.push(DataObjectFact { addr: view, name, size: stride as u32 });
        }
    }
}

/// XNU's typed allocator entry points: (name, returns a pointer, parameter
/// count). The first parameter is the view.
const TYPED_ALLOCATORS: &[(&str, bool, usize)] = &[
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

/// Prototypes for the typed allocators, parked by name and at every address
/// this image calls one at (its own definition, a stub, or a collection-bound
/// import), since a by-name lookup can answer with an import slot instead.
pub(super) fn allocator_prototypes(ctx: &AnalysisCtx, rec: &Recovered, out: &mut AnalysisOutput) {
    let arch = ctx.arch;
    let mut at: Vec<(u64, String)> = crate::loader::macho_stubs::resolve_macho_imports(ctx.file, ctx.bytes)
        .into_iter()
        .map(|i| (i.addr, String::from_utf8_lossy(&i.name).into_owned()))
        .collect();
    at.extend(rec.names.iter().map(|(&a, n)| (a, n.clone())));
    use kuna_decomp::dtype::type_metatype;
    let types = arch.types();
    let (ptr_size, word_size) = arch.data_org();
    let (Ok(void), Ok(word)) = (types.get_type_void(), types.get_base(8, type_metatype::TYPE_UINT)) else { return };
    let Ok(ptr) = types.get_type_pointer(ptr_size, void.clone(), word_size) else { return };
    for &(name, returns, params) in TYPED_ALLOCATORS {
        let mut intypes = vec![ptr.clone()];
        intypes.extend((1..params).map(|_| word.clone()));
        let pieces = kuna_decomp::fspec::PrototypePieces {
            name: name.to_string(),
            outtype: Some(if returns { ptr.clone() } else { void.clone() }),
            innames: vec![String::new(); intypes.len()],
            intypes,
            first_var_arg_slot: -1,
            output_storage: None,
            input_storage: Vec::new(),
            kuna_library_names: None,
        };
        for (addr, _) in at.iter().filter(|(_, n)| n == name) {
            out.prototypes_at.push((*addr, pieces.clone()));
        }
        out.prototypes.push(pieces);
    }
}

struct Dispatch {
    stride: u64,
    functions: Vec<u64>,
}

/// One `IOExternalMethodDispatch` (0x18 bytes) or `IOExternalMethodDispatch2022`
/// (0x28: plus `allowAsync` and a `checkEntitlement` string) record at `va`, as
/// IDA's kcu validates it: a code pointer, at most 16 scalars each way, struct
/// sizes up to 256 KiB or variable.
fn dispatch_record(img: &MachoImage, code: &[(u64, u64)], va: u64, stride: u64) -> Option<(u64, bool)> {
    let f = img.read_ptr(va).filter(|&f| in_ranges(code, f))?;
    let counts: Vec<u32> = (0..4).map(|i| img.read_u32(va + 8 + 4 * i)).collect::<Option<_>>()?;
    let size_ok = |s: u32| s <= 0x40000 || s == VARIABLE_SIZE;
    if counts[0] > 16 || counts[2] > 16 || !size_ok(counts[1]) || !size_ok(counts[3]) {
        return None;
    }
    if stride == DISPATCH_2022 {
        let flag_word = img.read_ptr(va + 0x18)?;
        let entitlement = img.read_ptr(va + 0x20)?;
        if flag_word > 1 || (entitlement != 0 && img.read_cstr(entitlement).is_none()) {
            return None;
        }
    }
    Some((f, counts[1] == VARIABLE_SIZE || counts[3] == VARIABLE_SIZE))
}

fn find_dispatch_tables(file: &object::File, img: &MachoImage, code: &[(u64, u64)]) -> BTreeMap<u64, Dispatch> {
    let mut tables = BTreeMap::new();
    for sec in file.sections() {
        if sec.name() != Ok("__const") || macho_flags(&sec) & 0xff != 0 || in_ranges(code, sec.address()) {
            continue;
        }
        let (lo, hi) = (sec.address(), sec.address() + sec.size());
        for stride in [DISPATCH_2022, DISPATCH] {
            let mut va = lo + (8 - lo % 8) % 8;
            while va + stride <= hi {
                let mut functions = Vec::new();
                let mut variable = false;
                while va + stride * (functions.len() as u64 + 1) <= hi {
                    let Some((f, var)) = dispatch_record(img, code, va + stride * functions.len() as u64, stride) else {
                        break;
                    };
                    functions.push(f);
                    variable |= var;
                }
                let overlaps = tables.range(..va + stride * functions.len() as u64).next_back().is_some_and(
                    |(&t, d): (&u64, &Dispatch)| t + d.stride * d.functions.len() as u64 > va,
                );
                if functions.len() >= MIN_DISPATCH_RUN && variable && !overlaps {
                    let len = functions.len() as u64;
                    tables.insert(va, Dispatch { stride, functions });
                    va += stride * len;
                } else {
                    va += 8;
                }
            }
        }
    }
    tables
}

/// Name each dispatch table `<Owner>_sMethods` and each unnamed dispatched
/// function `<Owner>::externalMethod_<selector>`. The owner is the class whose
/// vtable holds a method that computes the table's address, else the class
/// the table's named functions belong to.
pub(super) fn dispatch_tables(file: &object::File, img: &MachoImage, rec: &Recovered, out: &mut AnalysisOutput) {
    let tables = find_dispatch_tables(file, img, &rec.own_code);
    if tables.is_empty() {
        return;
    }
    let mut owner_of: HashMap<u64, String> = HashMap::new();
    for c in &rec.classes {
        for &f in c.vtable.iter().flat_map(|(_, s)| s.iter()).filter(|&&f| in_ranges(&rec.own_code, f)) {
            for v in super::a64::constants(img, f, OWNER_SCAN) {
                if tables.contains_key(&v) {
                    owner_of.entry(v).or_insert_with(|| c.name.clone());
                }
            }
        }
    }
    for (&table, d) in &tables {
        let owner = owner_of.get(&table).cloned().or_else(|| {
            d.functions.iter().find_map(|f| rec.names.get(f)).and_then(|n| n.rsplit_once("::")).map(|(c, _)| c.to_string())
        });
        let prefix = owner.unwrap_or_else(|| format!("IOExternalMethods_{table:x}"));
        let size = (d.stride * d.functions.len() as u64) as u32;
        let name = rec.names.get(&table).cloned().unwrap_or_else(|| format!("{prefix}_sMethods"));
        out.data_objects.push(DataObjectFact { addr: table, name, size });
        for (sel, &f) in d.functions.iter().enumerate() {
            if rec.names.contains_key(&f) || !in_ranges(&rec.own_code, f) {
                continue;
            }
            let name = format!("{prefix}::externalMethod_{sel}");
            out.entries.push(f);
            out.symbols.push(SymFact { addr: f, name: name.clone(), kind: SymKind::Function });
            out.fid_names.push(FidMatch { addr: f, name });
        }
    }
}

/// `__got`, `__auth_got` and `__auth_ptr` slots the indirect-symbol table does
/// not name: `<target>_ptr` for a slot whose rebased pointer reaches a named
/// function or object of this image.
fn pointer_slots(file: &object::File, bytes: &[u8], img: &MachoImage, rec: &Recovered, out: &mut AnalysisOutput) {
    let named: std::collections::HashSet<u64> = crate::loader::macho_stubs::resolve_macho_import_slots(file, bytes)
        .into_iter()
        .flat_map(|(lo, hi)| (lo..hi).step_by(8))
        .collect();
    for sec in file.sections() {
        if !matches!(sec.name(), Ok("__got" | "__auth_got" | "__auth_ptr")) {
            continue;
        }
        for k in 0..sec.size() / 8 {
            let slot = sec.address() + 8 * k;
            if named.contains(&slot) || rec.names.contains_key(&slot) {
                continue;
            }
            let Some(target) = img.read_ptr(slot).and_then(|t| rec.names.get(&t)) else { continue };
            out.data_objects.push(DataObjectFact { addr: slot, name: format!("{target}_ptr"), size: 8 });
        }
    }
}
