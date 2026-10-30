//! The `.fid` generator — kuna's `FidServiceLibraryIngest` analog.
//!
//! Disassembles every named function in a parsed object (a `.o` member or a
//! linked image) through the live SLEIGH decoder, runs the byte-exact PR2
//! [`FidHasher`](crate::fid::hash::FidHasher) over each function's extent, and
//! emits the deduplicated [`FidRecord`](crate::fid::db::FidRecord) rows the
//! [`FidDb`](crate::fid::db::FidDb) serializes.
//!
//! This is the §5.2 generator the `kuna fid build` CLI subcommand drives
//! (PR3). It is **not** wired into the decompile path — it is a build-time tool
//! that produces the fixture `.fid`, never reached from a decompilation.
//!
//! # The function extent
//!
//! The generator's body source is the loader's **rebased** function symbols
//! ([`ObjectLoadImage::func_symbols`]) — the `(load_vma, name)` pairs the engine
//! installs. For an `ET_REL` `.o` these are the *load* VMAs (the loader laid each
//! `SHF_ALLOC` section out above `RELOC_BASE`); the raw `object::File` symbol
//! addresses are section-relative and would miss every instruction.
//!
//! A function's extent is the **address-contiguous clip** `[entry, next_entry)`
//! (the same approximation [`crate::fid::extent`] documents), reconstructed by
//! a **linear decode** from `entry` through the live `Translate` (driving
//! [`crate::listing::decode::decode_one`] + [`crate::listing::classify::classify`]
//! for the per-instruction flow). This is independent of the Listing/xref tier's
//! exec-range universe — which is computed from the *unrebased* `object::File`
//! section addresses and so is wrong for an `ET_REL` `.o`.
//!
//! # Faithfulness to Ghidra's `hashAllTheFunctions`
//!
//! Only functions that (a) have a **real** symbol name and (b) hash to a
//! non-`None` quad (≥ 4 code units after skips) are kept. Functions whose body
//! fails to decode are skipped, not fatal. The per-instruction fingerprint
//! assembly (`InsnMask` + `is_call` + the address range →
//! [`InsnFingerprint`](crate::fid::hash::InsnFingerprint)) is the same
//! projection the PR4 matching pass uses, so a function fingerprints identically
//! whether it is *built into* a DB here or *looked up* against one later.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_decomp::architecture::Architecture;
use kuna_sleigh::sleigh::{OpObject as SleighOpObject, Sleigh};

use crate::listing::classify::classify;
use crate::listing::decode::decode_one;
use crate::loadimage_object::ObjectLoadImage;
use crate::fid::db::{FidRecord, FLAG_HAS_TERMINATOR};
use crate::fid::hash::{
    FidHasher, InsnFingerprint, OpObject, OperandFingerprint, RelocationQuery,
};
use crate::fid::skipper::{InstructionSkipper, X86InstructionSkipper};

/// One decoded instruction in a function's extent (the linear-decode result the
/// fingerprint is assembled from).
struct ExtentInsn {
    addr: u64,
    len: u32,
    is_call: bool,
    is_jump: bool,
    is_terminal: bool,
    flows: Vec<u64>,
}

/// Build the FID records for every named, hashable function in `bytes` (a parsed
/// object image).
///
/// The arguments mirror [`crate::passes::run_listing_consumers`]: the raw image
/// `bytes`, the opened `image` loader (the rebased funcsym source), the resolved
/// `arch`, and the engine `translate` (the live SLEIGH decoder, reached as
/// `arch.translate()`). The caller (the CLI) bootstraps these via
/// `kuna_console::bootstrap_from_object`.
///
/// Returns the records in function (address) order. Identical `(full, specific,
/// name)` rows are deduplicated. Never panics: a function whose body fails to
/// decode is skipped, not fatal.
pub fn build_records(
    bytes: &[u8],
    image: &ObjectLoadImage,
    arch: &Architecture,
    translate: &Sleigh,
) -> Vec<FidRecord> {
    let Ok(file) = object::File::parse(bytes) else {
        return Vec::new();
    };

    // The code space the per-instruction Addresses are built in (the space the
    // engine decodes through).
    let Some(code_space) = arch.manage().get_default_code_space() else {
        return Vec::new();
    };
    let code_space = Rc::clone(code_space);

    // The loader's REBASED function symbols `(load_vma, name)`, sorted by address
    // so each function's exclusive upper bound is the next entry. This is the
    // load-bearing seed/name source (see the module doc): for an `ET_REL` `.o`
    // the raw `object::File` symbol address is section-relative.
    let mut funcs = functions_by_address(image);
    funcs.dedup_by_key(|(a, _)| *a);

    // The relocation oracle for the 4-way scalar rule: a relocation overlapping
    // an operand's value bytes suppresses that scalar to the `0xfeeddead`
    // placeholder (so a relocatable reference does not leak into the hash).
    let relocs = ObjectRelocations::from_object(&file);

    // The per-architecture skipper set (x86 ⇒ the NOP/alignment skipper; non-x86
    // ⇒ empty, never skips).
    let is_x86 = arch.archid.starts_with("x86:");

    let dbg = std::env::var("KUNA_FID_DEBUG").is_ok();
    if dbg {
        eprintln!("[fid] funcs={} archid={} is_x86={is_x86}", funcs.len(), arch.archid);
    }

    let mut records: Vec<FidRecord> = Vec::new();
    let mut seen: std::collections::HashSet<(u64, u64, String)> = std::collections::HashSet::new();

    for (idx, (entry, name)) in funcs.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        // The exclusive upper bound: the next function entry strictly after this
        // one (the `[entry, next)` clip). `None` ⇒ decode until a terminal / error.
        let next = funcs.get(idx + 1).map(|(a, _)| *a);

        let extent = decode_extent(translate, *entry, next, &code_space);
        if extent.len() < 4 {
            if dbg {
                eprintln!("[fid] {name} @ {entry:#x}: extent {} < 4, skip", extent.len());
            }
            continue;
        }

        // Assemble the per-instruction fingerprints via the SLEIGH mask. A decode
        // failure on any instruction drops the whole function (a partially-masked
        // body would mis-hash).
        let mut fps: Vec<InsnFingerprint> = Vec::with_capacity(extent.len());
        let mut decode_ok = true;
        for ins in &extent {
            let addr = Address::new(Rc::clone(&code_space), ins.addr);
            match translate.instruction_mask(&addr) {
                Ok(mask) => fps.push(fingerprint_from_mask(ins.addr, ins.len, ins.is_call, mask)),
                Err(e) => {
                    if dbg {
                        eprintln!("[fid]   instruction_mask @ {:#x} err: {e}", ins.addr);
                    }
                    decode_ok = false;
                    break;
                }
            }
        }
        if !decode_ok {
            if dbg {
                eprintln!("[fid] {name} @ {entry:#x}: instruction_mask failed, skip");
            }
            continue;
        }
        let mut extent = extent;
        while is_x86 && fps.len() > 1 && fps.last().is_some_and(|fp| is_x86_padding(&fp.bytes)) {
            fps.pop();
            extent.pop();
        }

        let skippers: Vec<Box<dyn InstructionSkipper>> = if is_x86 {
            vec![Box::new(X86InstructionSkipper)]
        } else {
            vec![]
        };
        let mut hasher = FidHasher::new(skippers);
        let Some(quad) = hasher.hash(&fps, &relocs) else {
            if dbg {
                eprintln!("[fid] {name} @ {entry:#x}: hash None (< 4 usable), skip");
            }
            continue;
        };

        // Dedup identical (full, specific, name) rows.
        let key = (quad.full_hash, quad.specific_hash, name.clone());
        if !seen.insert(key) {
            continue;
        }

        // The terminator flag is informational for the PR5 seeker; set it when the
        // body's last code unit is a return/terminal flow.
        let flags = match extent.last() {
            Some(last) if last.is_terminal => FLAG_HAS_TERMINATOR,
            _ => 0,
        };

        if dbg {
            eprintln!(
                "[fid] {name} @ {entry:#x}: full={:#018x} spec={:#018x} cus={} addl={}",
                quad.full_hash, quad.specific_hash, quad.code_unit_size, quad.specific_addl_size
            );
        }

        let callees = callee_names(&extent, *entry, &relocs, &funcs);
        records.push(FidRecord {
            full_hash: quad.full_hash,
            specific_hash: quad.specific_hash,
            code_unit_size: quad.code_unit_size,
            specific_addl: quad.specific_addl_size,
            flags,
            name: name.clone(),
            callees,
        });
    }

    records
}

/// The named callees of a function: each call or jump in `extent` that carries a
/// relocation against a named symbol (an external callee in a `.o`), or whose
/// target leaves the function and is a named function entry, as `(offset from
/// entry, name)`.
fn callee_names(
    extent: &[ExtentInsn],
    entry: u64,
    relocs: &ObjectRelocations,
    funcs: &[(u64, String)],
) -> Vec<(u32, String)> {
    let end = extent.last().map_or(entry, |i| i.addr + u64::from(i.len));
    let mut out = Vec::new();
    for ins in extent.iter().filter(|i| i.is_call || i.is_jump) {
        let off = (ins.addr - entry) as u32;
        let last = ins.addr + u64::from(ins.len).max(1) - 1;
        if let Some(name) = relocs.symbol_in(ins.addr, last) {
            out.push((off, name.to_string()));
            continue;
        }
        let Some(&t) = ins.flows.first() else { continue };
        if t > entry && t < end {
            continue;
        }
        if let Ok(i) = funcs.binary_search_by_key(&t, |(a, _)| *a) {
            out.push((off, funcs[i].1.clone()));
        }
    }
    out
}

/// The function symbols of `image` by address; at one address the public
/// spelling comes first (no `.` suffix, fewest leading underscores, shortest),
/// so `fflush` is kept over its alias `_IO_fflush` and `malloc` over
/// `__libc_malloc`.
fn functions_by_address(image: &ObjectLoadImage) -> Vec<(u64, String)> {
    let mut funcs = image.func_symbols();
    funcs.extend(image.func_symbol_aliases());
    funcs.sort_by_key(|(a, n)| (*a, n.contains('.'), n.len() - n.trim_start_matches('_').len(), n.len()));
    funcs
}

/// Every function name in `image` paired with the name [`build_records`] keeps
/// for its address (the first symbol there), so a callee recorded under an
/// alias (`__libc_malloc` for `malloc`) can be rewritten to the kept name.
pub fn alias_names(image: &ObjectLoadImage) -> Vec<(String, String)> {
    let funcs = functions_by_address(image);
    let mut out = Vec::new();
    let mut kept: Option<(u64, String)> = None;
    for (addr, name) in funcs {
        match &kept {
            Some((a, k)) if *a == addr => out.push((name, k.clone())),
            _ => kept = Some((addr, name)),
        }
    }
    out
}

/// Alignment padding after a function's last instruction: `int3`, or a NOP
/// (`90` or the `0F 1F` family) under any number of `66`/`2E` prefixes, the
/// `data16 cs nopw` runs gcc pads with. The Listing never decodes unreachable
/// padding, so the generator drops it from the end of the `[entry, next)`
/// clip; inside a function only the Ghidra skipper patterns apply.
fn is_x86_padding(bytes: &[u8]) -> bool {
    let body = &bytes[bytes.iter().take_while(|&&b| b == 0x66 || b == 0x2e).count()..];
    body == [0x90] || body == [0xcc] || body.starts_with(&[0x0f, 0x1f])
}

/// Linear-decode a function's extent: the contiguous instructions in
/// `[entry, next)` (with `next = None` ⇒ stop at the first terminal or decode
/// error). Each instruction is decoded once through `decode_one` and classified
/// for its flow (`is_call` / `is_terminal`).
fn decode_extent(
    translate: &Sleigh,
    entry: u64,
    next: Option<u64>,
    code_space: &Rc<kuna_base::space::AddrSpace>,
) -> Vec<ExtentInsn> {
    let mut out: Vec<ExtentInsn> = Vec::new();
    let mut vma = entry;
    // A generous guard against a runaway decode (a body that never reaches a
    // terminal and has no `next` bound): cap at a large instruction count.
    let mut guard = 1 << 20;
    loop {
        if let Some(n) = next {
            if vma >= n {
                break; // reached the next function entry (exclusive clip)
            }
        }
        if guard == 0 {
            break;
        }
        guard -= 1;

        // `want_assembly = false`: the extent clip reads only `len` and `ops`.
        let Ok(dec) = decode_one(translate, vma, code_space, false, false) else {
            break; // an undecodable byte ends the clip
        };
        let len = dec.len.max(1); // never advance by 0 (avoid an infinite loop)
        let cls = classify(&dec.ops, vma, dec.len);
        let is_terminal = cls.flow.is_terminal;
        out.push(ExtentInsn {
            addr: vma,
            len,
            is_call: cls.flow.is_call,
            is_jump: cls.flow.is_jump,
            is_terminal,
            flows: cls.flows,
        });

        // When there is no `next` bound, a terminal (return / unconditional
        // branch out) ends the contiguous body.
        if next.is_none() && is_terminal {
            break;
        }
        vma = vma.wrapping_add(u64::from(len));
    }
    out
}

/// Project a decoded [`InsnMask`](kuna_sleigh::sleigh::InsnMask) + the flow/address
/// info into the hasher's [`InsnFingerprint`]. The field mapping is 1:1 (the
/// hasher's `OpObject` mirrors the SLEIGH one); the only translation is the enum
/// re-tag.
///
/// `pub(crate)` so the FID matching pass ([`crate::fid::FidPass`]) assembles a
/// looked-up function's fingerprints with the **exact same** projection the
/// generator uses — a function fingerprints identically whether it is built into a
/// DB here or matched against one later (the load-bearing build/lookup symmetry).
pub(crate) fn fingerprint_from_mask(
    addr: u64,
    len: u32,
    is_call: bool,
    mask: kuna_sleigh::sleigh::InsnMask,
) -> InsnFingerprint {
    let operands = mask
        .operands
        .into_iter()
        .map(|op| OperandFingerprint {
            value_mask: op.value_mask,
            objects: op.objects.into_iter().map(map_op_object).collect(),
        })
        .collect();
    InsnFingerprint {
        min_addr: addr,
        // getMaxAddress = min + len - 1 (the inclusive end).
        max_addr: addr.wrapping_add(u64::from(len)).wrapping_sub(1),
        bytes: mask.bytes,
        fixed_mask: mask.fixed_mask,
        is_call,
        operands,
    }
}

/// Re-tag the SLEIGH op-object to the hasher's mirror enum (identical shape).
fn map_op_object(o: SleighOpObject) -> OpObject {
    match o {
        SleighOpObject::Scalar { signed, whole_operand, is_address } => {
            OpObject::Scalar { signed, whole_operand, is_address }
        }
        SleighOpObject::Register { offset } => OpObject::Register { offset },
        SleighOpObject::Address => OpObject::Address,
    }
}

/// A [`RelocationQuery`] over a parsed object: holds the sorted load-VMA ranges
/// covered by every relocation, rebased the same way [`crate::loader::reloc_object`]
/// lays a relocatable object out (each `SHF_ALLOC` section at/above
/// [`RELOC_BASE`](crate::loader::reloc_object::RELOC_BASE)). A query is a range
/// overlap against that sorted set.
///
/// For a `.o` whose `.text` carries no relocations (a fully self-contained body —
/// the FID fixture), this is empty and every query is `false`, exactly as
/// `NoRelocations` would be — but it is *correct* for the general `.o` with
/// `.rela.text` (an external call's `R_X86_64_PLT32` displacement), where the
/// scalar must be suppressed.
struct ObjectRelocations {
    /// `(start_vma, end_vma_inclusive)` per relocation, sorted by `start_vma`.
    ranges: Vec<(u64, u64)>,
    /// `(start_vma, symbol name)` for each relocation against a named symbol,
    /// sorted by `start_vma`.
    symbols: Vec<(u64, String)>,
}

impl ObjectRelocations {
    fn from_object(file: &object::File) -> Self {
        use object::read::{Object, ObjectSection, ObjectSymbol};
        use object::SectionIndex;
        use std::collections::HashMap;

        const SHF_ALLOC: u64 = 0x2;
        const RELOC_BASE: u64 = crate::loader::reloc_object::RELOC_BASE;

        // Replicate the reloc_object layout pass-1 section→VMA map so a section-
        // relative reloc offset maps to the same load VMA the loader assigned.
        let mut vma_of: HashMap<SectionIndex, u64> = HashMap::new();
        let mut cursor = RELOC_BASE;
        for sec in file.sections() {
            let sh_flags = match sec.flags() {
                object::SectionFlags::Elf { sh_flags } => sh_flags,
                _ => 0,
            };
            if sh_flags & SHF_ALLOC == 0 {
                continue;
            }
            let align = sec.align().max(1);
            let vma = align_up(cursor, align);
            vma_of.insert(sec.index(), vma);
            cursor = vma.wrapping_add(sec.size());
        }

        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut symbols: Vec<(u64, String)> = Vec::new();
        for sec in file.sections() {
            let Some(&sec_vma) = vma_of.get(&sec.index()) else {
                continue; // a non-loaded section's relocs do not land in any body
            };
            for (offset, reloc) in sec.relocations() {
                // The relocation patches `reloc.size()` bits at `sec_vma + offset`.
                let start = sec_vma.wrapping_add(offset);
                let nbytes = (reloc.size() as u64 / 8).max(1);
                let end = start.wrapping_add(nbytes - 1);
                ranges.push((start, end));
                if let object::RelocationTarget::Symbol(idx) = reloc.target() {
                    let named = file
                        .symbol_by_index(idx)
                        .ok()
                        .filter(|sym| sym.kind() != object::SymbolKind::Section)
                        .and_then(|sym| sym.name().ok().map(str::to_string))
                        .filter(|n| !n.is_empty());
                    if let Some(name) = named {
                        symbols.push((start, name));
                    }
                }
            }
        }
        ranges.sort_unstable_by_key(|r| r.0);
        symbols.sort_unstable_by_key(|r| r.0);
        Self { ranges, symbols }
    }

    /// The symbol a relocation inside `[min_addr, max_addr]` names.
    fn symbol_in(&self, min_addr: u64, max_addr: u64) -> Option<&str> {
        let i = self.symbols.partition_point(|(s, _)| *s < min_addr);
        self.symbols.get(i).filter(|(s, _)| *s <= max_addr).map(|(_, n)| n.as_str())
    }
}

impl RelocationQuery for ObjectRelocations {
    fn has_relocation_in(&self, min_addr: u64, max_addr: u64) -> bool {
        // Any stored range overlapping the inclusive query range [min, max].
        self.ranges.iter().any(|&(s, e)| s <= max_addr && min_addr <= e)
    }
}

/// `align_up(x, a)` for a power-of-two alignment (mirrors `reloc_object`).
fn align_up(x: u64, align: u64) -> u64 {
    if align <= 1 {
        return x;
    }
    x.wrapping_add(align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::is_x86_padding;

    #[test]
    fn trailing_padding_forms() {
        assert!(is_x86_padding(&[0x90]));
        assert!(is_x86_padding(&[0xcc]));
        assert!(is_x86_padding(&[0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]));
        assert!(is_x86_padding(&[0x0f, 0x1f, 0x44, 0, 0]));
        assert!(!is_x86_padding(&[0xc3]));
        assert!(!is_x86_padding(&[0x66, 0x0f, 0xef, 0xc0]));
    }
}
