//! Name the references a cache image makes into other images.
//!
//! The cache builder routes an image's calls into other images past its own
//! stubs. On iOS 16 a `bl` lands on a stub island in a `__TEXT_STUBS` sub-cache
//! (`adrp x16; add x16; br x16` to the callee); on iOS 14 it lands on another
//! image's rewritten stub; within branch range it lands on the callee itself.
//! The builder also binds `__got` slots in place and drops their indirect-symbol
//! entries (an untyped section, or `INDIRECT_SYMBOL_LOCAL|ABS` entries), and
//! rewrites a GOT load in range into a direct `adrp`/`add` or `adrp`/`ldr` of
//! the target, so a load through one names nothing. None of these targets is in
//! the rebuilt image, so nothing there names them.
//!
//! [`collect`] finds every branch target outside the image, every bound GOT
//! slot holding an address outside it, and every `adrp` page plus offset and
//! data-section pointer that lands outside it. It follows a stub to its final
//! target, then names that target from the symbol table of the image holding
//! it (exports, else the locals in the local-symbols file). A data address is
//! named by the symbol containing it, as [`XrefKind::Data`] reaching eight
//! bytes past the last address referenced in it (within the symbol), so an
//! interior reference renders as a part of it, and a GOT
//! slot holding one is [`XrefKind::Bound`]: constant, so a load through it
//! folds to that address. The result
//! rides in the rebuilt image as an `LC_NOTE` owned by [`NOTE_OWNER`].
//! `macho_stubs` reads the note back as imports and data symbols, under the
//! `dyldcrossrefs` option.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use std::rc::Rc;

use super::extract::{ImageLayout, Nlist};
use super::{u32_at, u64_at, DyldCache};

/// The `LC_NOTE` `data_owner` of the cross-image reference table.
pub const NOTE_OWNER: &[u8; 16] = b"kuna.dyld.xrefs\0";

/// What an [`Xref`] address is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefKind {
    /// A branch target: calling it calls the named function.
    Call,
    /// A pointer slot holding the named symbol's address.
    Slot,
    /// A data symbol of another image: `size` bytes from `addr`.
    Data,
    /// A bound pointer slot of the image holding the address of another
    /// image's data: its `size` bytes are constant, so a load from it may fold.
    Bound,
    /// The `size`-byte extent of the holding symbol at `addr` of a
    /// [`XrefKind::Data`] symbol whose address the image takes (a bound slot, a
    /// data pointer, an `adrp`/`add`): code may offset such a pointer, as Swift
    /// does to reach a full type metadata record's address point. Unnamed, and
    /// written after every other entry so an older reader stops before it.
    Extent,
}

/// One named reference into another image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xref {
    pub addr: u64,
    pub kind: XrefKind,
    /// The raw symbol name, leading underscore included.
    pub name: Vec<u8>,
    /// The extent of a [`XrefKind::Data`], [`XrefKind::Bound`] or
    /// [`XrefKind::Extent`] entry; 0 for the other kinds.
    pub size: u64,
}

/// Serialize: `u32 count`, then per entry `u64 addr, u32 kind, u32 name offset,
/// u64 size`, then the NUL-terminated names.
pub fn encode(xrefs: &[Xref]) -> Vec<u8> {
    let mut table = (xrefs.len() as u32).to_le_bytes().to_vec();
    let mut names = Vec::new();
    for x in xrefs {
        table.extend(x.addr.to_le_bytes());
        table.extend((x.kind as u32).to_le_bytes());
        table.extend((names.len() as u32).to_le_bytes());
        table.extend(x.size.to_le_bytes());
        names.extend(&x.name);
        names.push(0);
    }
    table.extend(names);
    table
}

/// The bytes of one encoded entry.
const ENTRY: usize = 24;

/// The inverse of [`encode`]; a malformed blob yields the entries before the fault.
pub fn decode(blob: &[u8]) -> Vec<Xref> {
    let Some(count) = blob.get(..4).map(|b| u32_at(b, 0) as usize) else {
        return Vec::new();
    };
    let names_at = count.checked_mul(ENTRY).and_then(|n| n.checked_add(4)).unwrap_or(usize::MAX);
    let Some(names) = blob.get(names_at..) else {
        return Vec::new();
    };
    blob[4..names_at]
        .chunks_exact(ENTRY)
        .map_while(|e| {
            let kind = match u32_at(e, 8) {
                0 => XrefKind::Call,
                1 => XrefKind::Slot,
                2 => XrefKind::Data,
                3 => XrefKind::Bound,
                4 => XrefKind::Extent,
                _ => return None,
            };
            let name = names.get(u32_at(e, 12) as usize..)?;
            let name = &name[..name.iter().position(|&b| b == 0)?];
            Some(Xref { addr: u64_at(e, 0), kind, name: name.to_vec(), size: u64_at(e, 16) })
        })
        .collect()
}

/// The cross-image references a thin 64-bit Mach-O carries in its
/// `kuna.dyld.xrefs` note; empty for any other input.
pub fn read_note(bytes: &[u8]) -> Vec<Xref> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    if bytes.len() < 32 || u32_at(bytes, 0) != MH_MAGIC_64 {
        return Vec::new();
    }
    let (ncmds, sizeofcmds) = (u32_at(bytes, 16) as usize, u32_at(bytes, 20) as usize);
    let Some(cmds) = bytes.get(32..32 + sizeofcmds) else {
        return Vec::new();
    };
    let mut at = 0;
    for _ in 0..ncmds {
        let Some(c) = cmds.get(at..at + 8) else {
            break;
        };
        let (cmd, size) = (u32_at(c, 0), u32_at(c, 4) as usize);
        if cmd == super::extract::LC_NOTE && size >= 40 && cmds.get(at + 8..at + 24) == Some(NOTE_OWNER) {
            let (off, len) = (u64_at(cmds, at + 24) as usize, u64_at(cmds, at + 32) as usize);
            return bytes.get(off..off.saturating_add(len)).map(decode).unwrap_or_default();
        }
        if size < 8 {
            break;
        }
        at += size;
    }
    Vec::new()
}

/// The [`XrefKind::Bound`] slots of a rebuilt image's note, as inclusive
/// `[first, last]` byte ranges.
pub fn bound_slots(bytes: &[u8]) -> Vec<(u64, u64)> {
    read_note(bytes)
        .into_iter()
        .filter(|x| x.kind == XrefKind::Bound && x.size > 0)
        .filter_map(|x| Some((x.addr, x.addr.checked_add(x.size - 1)?)))
        .collect()
}

/// The [`XrefKind::Data`] symbols of a rebuilt image's note, as `(address, raw
/// name, size)`: the data of other images its code and data reach.
pub fn data_symbols(bytes: &[u8]) -> Vec<(u64, Vec<u8>, u64)> {
    read_note(bytes).into_iter().filter(|x| x.kind == XrefKind::Data).map(|x| (x.addr, x.name, x.size)).collect()
}

/// The `[start, stop]` (inclusive) extents of the other images' data a thin
/// 64-bit Mach-O's `kuna.dyld.xrefs` note says the image takes the address of.
pub fn interior_extents(bytes: &[u8]) -> Vec<(u64, u64)> {
    read_note(bytes)
        .into_iter()
        .filter(|x| x.kind == XrefKind::Extent && x.size > 0)
        .filter_map(|x| Some((x.addr, x.addr.checked_add(x.size - 1)?)))
        .collect()
}

/// Collect image `index`'s references into other images; `layout` is its
/// layout. `view(va, len)` reads the image's slid bytes. Branches and `adrp`
/// pairs are decoded only for an arm64 image (`a64`); an x86_64 image gets its
/// GOT slots and data pointers alone.
pub(super) fn collect<'v>(
    cache: &DyldCache,
    index: usize,
    layout: &ImageLayout,
    a64: bool,
    view: &dyn Fn(u64, usize) -> Option<&'v [u8]>,
) -> Vec<Xref> {
    const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
    let mut targets = BTreeSet::new();
    let mut slots = Vec::new();
    let mut data: BTreeMap<u64, bool> = BTreeMap::new();
    let mut indirect = None;
    for seg in &layout.segments {
        for sec in &seg.sections {
            let Some(bytes) = view(sec.addr, sec.size as usize) else {
                continue;
            };
            let got = matches!(sec.sectname.as_str(), "__got" | "__auth_got" | "__auth_ptr");
            if sec.is_code() {
                if !a64 {
                    continue;
                }
                for (i, w) in bytes.chunks_exact(4).enumerate() {
                    let w = u32_at(w, 0);
                    if w & 0x7C00_0000 == 0x1400_0000 {
                        let pc = sec.addr + i as u64 * 4;
                        let target = pc.wrapping_add_signed(sign_extend(w & 0x03FF_FFFF, 26) << 2);
                        if !layout.holds(target) {
                            targets.insert(target);
                        }
                    }
                }
                adrp_targets(sec.addr, bytes, &mut |t, taken| {
                    if !layout.holds(t) {
                        *data.entry(t).or_default() |= taken;
                    }
                });
            } else if got && matches!(sec.section_type(), 0 | S_NON_LAZY_SYMBOL_POINTERS) {
                let typed = sec.section_type() != 0;
                let table: &[u32] = if typed {
                    indirect.get_or_insert_with(|| cache.image_indirect_symbols(index).unwrap_or_default())
                } else {
                    &[]
                };
                for (i, p) in bytes.chunks_exact(8).enumerate() {
                    let value = u64_at(p, 0);
                    if value == 0 || layout.holds(value) {
                        continue;
                    }
                    let entry = (sec.reserved1 as usize).checked_add(i).and_then(|e| table.get(e));
                    if typed && entry.is_some_and(|&e| e & INDIRECT_LOCAL_OR_ABS == 0) {
                        continue;
                    }
                    slots.push((sec.addr + i as u64 * 8, value));
                }
            } else if !got && !sec.is_zerofill() && sec.addr % 8 == 0 {
                for p in bytes.chunks_exact(8) {
                    let value = u64_at(p, 0);
                    if value != 0 && !layout.holds(value) {
                        data.insert(value, true);
                    }
                }
            }
        }
    }
    if targets.is_empty() && slots.is_empty() && data.is_empty() {
        return Vec::new();
    }
    let names = Names::new(cache);
    let mut out = Vec::new();
    for &target in &targets {
        if let Some(name) = names.call_target(target) {
            out.push(Xref { addr: target, kind: XrefKind::Call, name, size: 0 });
        }
    }
    for (addr, value) in slots {
        match names.image_at(value).and_then(|image| names.containing(image, value)) {
            Some(Held::Data { name, .. }) => {
                out.push(Xref { addr, kind: XrefKind::Bound, name, size: 8 });
                data.insert(value, true);
            }
            _ => {
                if let Some(name) = names.at(value) {
                    out.push(Xref { addr, kind: XrefKind::Slot, name, size: 0 });
                }
            }
        }
    }
    let mut by_image: BTreeMap<usize, Vec<(u64, bool)>> = BTreeMap::new();
    for (addr, taken) in data {
        if let Some(image) = names.image_at(addr) {
            by_image.entry(image).or_default().push((addr, taken));
        }
    }
    let mut code = BTreeMap::new();
    let mut spans = BTreeMap::new();
    let mut extents = BTreeMap::new();
    for (image, addrs) in by_image {
        for (addr, taken) in addrs {
            match names.containing(image, addr) {
                Some(Held::Code(name)) if !targets.contains(&addr) => {
                    code.insert(addr, name);
                }
                Some(Held::Data { start, name, size }) => {
                    let need = (addr - start).saturating_add(MIN_DATA_SIZE);
                    let span = spans.entry(start).or_insert((name, 0));
                    span.1 = span.1.max(need.min(size));
                    if taken {
                        extents.insert(start, size);
                    }
                }
                _ => {}
            }
        }
    }
    out.extend(code.into_iter().map(|(addr, name)| Xref { addr, kind: XrefKind::Call, name, size: 0 }));
    out.extend(spans.into_iter().map(|(addr, (name, size))| Xref { addr, kind: XrefKind::Data, name, size }));
    out.extend(extents.into_iter().map(|(addr, size)| Xref { addr, kind: XrefKind::Extent, name: Vec::new(), size }));
    out
}

/// The indirect-symbol flags of an entry the cache builder bound in place.
const INDIRECT_LOCAL_OR_ABS: u32 = 0xC000_0000;

/// Every address an `adrp` page plus a later `add` or unsigned-offset load or
/// store immediate forms in `code` at `base`, and whether it was an `add` (an
/// address taken rather than accessed). The page is tracked per register
/// in one linear pass: `b`, `br` and `ret` forget every page, `bl` the pages of
/// the registers a call clobbers, conditional branches and system instructions
/// none, and any other instruction the page of the register in its low five
/// bits. An address formed
/// through a page set in another block is missed, and one formed after an
/// undecoded write of the base register is wrong; both only cost a name.
fn adrp_targets(base: u64, code: &[u8], found: &mut dyn FnMut(u64, bool)) {
    let mut pages = [None::<u64>; 32];
    for (i, w) in code.chunks_exact(4).enumerate() {
        let w = u32_at(w, 0);
        let pc = base + i as u64 * 4;
        let rd = (w & 31) as usize;
        let rn = ((w >> 5) & 31) as usize;
        if w & 0x9F00_0000 == 0x9000_0000 {
            let imm = ((w >> 3) & 0x001F_FFFC) | ((w >> 29) & 3);
            pages[rd] = Some((pc & !0xFFF).wrapping_add_signed(sign_extend(imm, 21) << 12));
            continue;
        }
        if w & 0xFC00_0000 == 0x9400_0000 {
            pages[..19].fill(None);
            continue;
        }
        if w & 0xFC00_0000 == 0x1400_0000 || w & 0xFE00_0000 == 0xD600_0000 {
            pages = [None; 32];
            continue;
        }
        if w & 0xFF00_0010 == 0x5400_0000 || w & 0x7C00_0000 == 0x3400_0000 || w & 0xFFC0_0000 == 0xD500_0000 {
            continue;
        }
        if w & 0xFF80_0000 == 0x9100_0000 {
            if let Some(page) = pages[rn] {
                let shift = if w & (1 << 22) != 0 { 12 } else { 0 };
                found(page.wrapping_add((((w >> 10) & 0xFFF) as u64) << shift), true);
            }
        } else if w & 0x3B00_0000 == 0x3900_0000 {
            let simd = w & (1 << 26) != 0;
            if let Some(page) = pages[rn] {
                let scale = if simd && w & (1 << 23) != 0 && w >> 30 == 0 { 4 } else { w >> 30 };
                found(page.wrapping_add((((w >> 10) & 0xFFF) as u64) << scale), false);
            }
            let load = w & (3 << 22) != 0;
            if simd || !load {
                continue;
            }
        }
        pages[rd] = None;
    }
}

fn sign_extend(v: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v as i64) << shift) >> shift
}

/// Follow the stub at `addr` to the address it jumps to: up to four
/// instructions of `adrp`, `add`, `ldr` (through slid data) ending in `br`,
/// `braa`/`brab` or `braaz`/`brabz`. `None` for anything else.
fn follow_stub(cache: &DyldCache, addr: u64) -> Option<u64> {
    let code = cache.read_va(addr, 16).ok()?;
    let mut regs = [None::<u64>; 32];
    for (i, w) in code.chunks_exact(4).enumerate() {
        let w = u32_at(w, 0);
        let pc = addr + i as u64 * 4;
        let rd = (w & 31) as usize;
        let rn = ((w >> 5) & 31) as usize;
        if w & 0x9F00_0000 == 0x9000_0000 {
            let imm = ((w >> 3) & 0x001F_FFFC) | ((w >> 29) & 3);
            regs[rd] = Some((pc & !0xFFF).wrapping_add_signed(sign_extend(imm, 21) << 12));
        } else if w & 0xFF80_0000 == 0x9100_0000 {
            let imm = ((w >> 10) & 0xFFF) as u64;
            let shift = if w & (1 << 22) != 0 { 12 } else { 0 };
            regs[rd] = Some(regs[rn]?.wrapping_add(imm << shift));
        } else if w & 0xFFC0_0000 == 0xF940_0000 {
            let slot = regs[rn]?.wrapping_add((((w >> 10) & 0xFFF) as u64) * 8);
            regs[rd] = Some(u64_at(&cache.read_slid(slot, 8).ok()?, 0));
        } else if w & 0xFFFF_FC1F == 0xD61F_0000 || w & 0xFFFF_F800 == 0xD71F_0800 || w & 0xFFFF_F81F == 0xD61F_081F {
            return regs[rn];
        } else {
            return None;
        }
    }
    None
}

/// The most stubs a call target is followed through before it is left unnamed.
const MAX_STUB_HOPS: usize = 4;

/// One image's names: by address, their sorted addresses, and the symbol
/// table and indirect-symbol table its stubs index.
#[derive(Default)]
struct ImageNames {
    by_addr: HashMap<u64, Vec<u8>>,
    starts: Vec<u64>,
    symbols: Vec<Nlist>,
    indirect: Vec<u32>,
}

/// What [`Names::containing`] finds at an address.
enum Held {
    /// A code address a symbol starts at.
    Code(Vec<u8>),
    /// A data address inside the `size`-byte symbol `name` at `start`.
    Data { start: u64, name: Vec<u8>, size: u64 },
}

/// The widest a data symbol is taken to reach when no later symbol of its
/// section bounds it sooner.
const MAX_DATA_EXTENT: u64 = 0x1_0000;

/// The extent a [`XrefKind::Data`] symbol takes past the last address the
/// image loads or stores in it, as `macho_stubs::data_symbols` sizes a symbol
/// table's data: one 64-bit scalar or pointer.
const MIN_DATA_SIZE: u64 = 8;

/// The most images whose names are held at once.
const MAX_IMAGES: usize = 64;

/// Symbol names by address across the whole cache, built per image on demand.
struct Names<'a> {
    cache: &'a DyldCache,
    ranges: Vec<(u64, u64, usize)>,
    images: RefCell<HashMap<usize, Rc<ImageNames>>>,
}

impl<'a> Names<'a> {
    fn new(cache: &'a DyldCache) -> Names<'a> {
        let mut ranges: Vec<(u64, u64, usize)> = (0..cache.images().len())
            .filter_map(|i| cache.image_layout(i).ok().map(|l| (i, l)))
            .flat_map(|(i, layout)| {
                layout
                    .segments
                    .iter()
                    .filter(|s| s.name != "__LINKEDIT")
                    .map(|s| (s.vmaddr, s.vmaddr + s.vmsize, i))
                    .collect::<Vec<_>>()
            })
            .collect();
        ranges.sort_unstable();
        Names { cache, ranges, images: RefCell::default() }
    }

    fn image_at(&self, addr: u64) -> Option<usize> {
        let i = self.ranges.partition_point(|r| r.0 <= addr).checked_sub(1)?;
        let (lo, hi, image) = self.ranges[i];
        (addr >= lo && addr < hi).then_some(image)
    }

    fn image(&self, index: usize) -> Rc<ImageNames> {
        if let Some(names) = self.images.borrow().get(&index) {
            return names.clone();
        }
        let names = Rc::new(self.load(index));
        let mut images = self.images.borrow_mut();
        if images.len() >= MAX_IMAGES {
            images.clear();
        }
        images.insert(index, names.clone());
        names
    }

    /// The symbol of image `index` that holds `addr`: one starting there in a
    /// code section, else the last one at or below it in its data section,
    /// reaching to the next symbol, the section end or [`MAX_DATA_EXTENT`].
    fn containing(&self, index: usize, addr: u64) -> Option<Held> {
        let layout = self.cache.image_layout(index).ok()?;
        let sec = layout
            .segments
            .iter()
            .filter(|s| s.name != "__LINKEDIT")
            .flat_map(|s| &s.sections)
            .find(|s| addr >= s.addr && addr - s.addr < s.size)?;
        let image = self.image(index);
        if sec.is_code() {
            return image.by_addr.get(&addr).cloned().map(Held::Code);
        }
        let at = image.starts.partition_point(|&s| s <= addr).checked_sub(1)?;
        let start = image.starts[at];
        if start < sec.addr {
            return None;
        }
        let next = image.starts.get(at + 1).copied().unwrap_or(u64::MAX);
        let end = next.min(sec.addr.saturating_add(sec.size)).min(start.saturating_add(MAX_DATA_EXTENT));
        (addr < end).then(|| Held::Data { start, name: image.by_addr[&start].clone(), size: end - start })
    }

    /// Image `index`'s names: locals first, so an export of the same address
    /// replaces them.
    fn load(&self, index: usize) -> ImageNames {
        let locals = self.cache.local_symbols(index).unwrap_or_default();
        let symbols = self.cache.image_symbols(index).unwrap_or_default();
        let mut by_addr = HashMap::new();
        for sym in locals.iter().chain(symbols.iter().filter(|s| !s.is_external())) {
            if sym.names_address() {
                by_addr.entry(sym.n_value).or_insert_with(|| sym.name.clone());
            }
        }
        for sym in symbols.iter().filter(|s| s.is_external() && s.names_address()) {
            by_addr.insert(sym.n_value, sym.name.clone());
        }
        let indirect = self.cache.image_indirect_symbols(index).unwrap_or_default();
        let mut starts: Vec<u64> = by_addr.keys().copied().collect();
        starts.sort_unstable();
        ImageNames { by_addr, starts, symbols, indirect }
    }

    fn at(&self, addr: u64) -> Option<Vec<u8>> {
        self.image(self.image_at(addr)?).by_addr.get(&addr).cloned()
    }

    /// The function a branch to `addr` calls: a symbol at `addr`, else the
    /// import a stub at `addr` is for, else whatever the stub jumps to.
    fn call_target(&self, mut addr: u64) -> Option<Vec<u8>> {
        for _ in 0..MAX_STUB_HOPS {
            if let Some(name) = self.at(addr).or_else(|| self.stub_import(addr)) {
                return Some(name);
            }
            addr = follow_stub(self.cache, addr)?;
        }
        None
    }

    /// The symbol an image's own `S_SYMBOL_STUBS` entry at `addr` stands for,
    /// from that image's indirect-symbol table.
    fn stub_import(&self, addr: u64) -> Option<Vec<u8>> {
        const S_SYMBOL_STUBS: u32 = 0x8;
        let index = self.image_at(addr)?;
        let layout = self.cache.image_layout(index).ok()?;
        let sec = layout
            .segments
            .iter()
            .flat_map(|s| &s.sections)
            .find(|s| s.section_type() == S_SYMBOL_STUBS && addr >= s.addr && addr < s.addr + s.size)?;
        let stride = sec.reserved2 as u64;
        if stride == 0 || (addr - sec.addr) % stride != 0 {
            return None;
        }
        let image = self.image(index);
        let slot = sec.reserved1 as usize + ((addr - sec.addr) / stride) as usize;
        let symbol = *image.indirect.get(slot)?;
        if symbol & 0xC000_0000 != 0 {
            return None;
        }
        let name = &image.symbols.get(symbol as usize)?.name;
        (!name.is_empty()).then(|| name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_round_trips() {
        let xrefs = vec![
            Xref { addr: 0x1_8c99_b570, kind: XrefKind::Call, name: b"___stack_chk_fail".to_vec(), size: 0 },
            Xref { addr: 0x1_dc07_f118, kind: XrefKind::Slot, name: b"_objc_debug_isa_class_mask".to_vec(), size: 0 },
            Xref { addr: 0x1_dc68_1000, kind: XrefKind::Data, name: b"_$sSTTL".to_vec(), size: 0x18 },
            Xref { addr: 0x1_dc68_1000, kind: XrefKind::Extent, name: Vec::new(), size: 0x40 },
        ];
        assert_eq!(decode(&encode(&xrefs)), xrefs);
        assert!(decode(&[1, 0]).is_empty());
        assert!(decode(&encode(&xrefs)[..20]).is_empty());
    }

    #[test]
    fn adrp_immediates_decode_with_sign() {
        assert_eq!(sign_extend(0x1F_FFFF, 21), -1);
        assert_eq!(sign_extend(0x03FF_FFFF, 26) << 2, -4);
    }
}
