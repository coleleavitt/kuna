//! Rebuild one cache image as a standalone thin Mach-O.
//!
//! Every segment keeps its cache virtual address, so an address kuna prints is
//! the address in the cache. The segments' bytes are copied with slide info
//! applied, and the image gets a private `__LINKEDIT`: the cache shares one
//! `__LINKEDIT` across all images, and the load commands point into it.
//!
//! The private `__LINKEDIT` holds the image's own nlists, with the local symbols
//! the cache moved to its local-symbols file in place of the `<redacted>`
//! placeholders left behind (left nameless when that file is missing). It also holds a compact string table, the
//! indirect-symbol table renumbered to match, copies of the export trie,
//! function starts and data-in-code, and a `kuna.dyld.xrefs` `LC_NOTE` naming
//! the image's references into other images ([`super::xrefs`]). Linkedit data
//! the rebuild does not carry (code signature, split-seg info, rebase and bind
//! opcodes the cache builder already applied) is zeroed in its command.

use std::rc::Rc;

use super::{u32_at, u64_at, DyldCache};

const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
pub(crate) const LC_NOTE: u32 = 0x31;
const LINKEDIT_DATA_COMMANDS: &[u32] =
    &[0x1d, 0x1e, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, 0x2b, 0x2e, LC_DYLD_EXPORTS_TRIE, 0x8000_0034, 0x36, 0x37, 0x38];
/// Section types that index the indirect-symbol table, which a companion's
/// sections must not do in a merged image: the table there is the primary's.
const INDIRECT_SECTION_TYPES: [u32; 6] = [0x5, 0x6, 0x7, 0x8, 0x10, 0x15];
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_SECT: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_PEXT: u8 = 0x10;
const PAGE: u64 = 0x4000;
/// The name the cache builder leaves on a local it moved to the local-symbols file.
const REDACTED: &[u8] = b"<redacted>";

/// The field layout of a 64-bit or 32-bit Mach-O: the header, segment and
/// section commands and the nlist differ only in width and offsets.
#[derive(Clone, Copy, Debug)]
pub struct Width {
    pub wide: bool,
    header: usize,
    seg_cmd: u32,
    seg: [usize; 5],
    sect0: usize,
    sect_size: usize,
    sect: [usize; 7],
    nlist: usize,
}

/// `seg`: vmaddr, vmsize, fileoff, filesize, nsects. `sect`: addr, size,
/// offset, reloff, flags, reserved1, reserved2.
const WIDE: Width = Width {
    wide: true,
    header: 32,
    seg_cmd: 0x19,
    seg: [24, 32, 40, 48, 64],
    sect0: 72,
    sect_size: 80,
    sect: [32, 40, 48, 56, 64, 68, 72],
    nlist: 16,
};
const NARROW: Width = Width {
    wide: false,
    header: 28,
    seg_cmd: 0x1,
    seg: [24, 28, 32, 36, 48],
    sect0: 56,
    sect_size: 68,
    sect: [32, 36, 40, 48, 56, 60, 64],
    nlist: 12,
};

impl Width {
    pub fn ptr(&self) -> usize {
        if self.wide { 8 } else { 4 }
    }

    fn word(&self, b: &[u8], at: usize) -> u64 {
        if self.wide { u64_at(b, at) } else { u64::from(u32_at(b, at)) }
    }

    fn put_word(&self, b: &mut [u8], at: usize, v: u64) {
        if self.wide { put_u64(b, at, v) } else { put_u32(b, at, v as u32) }
    }
}

/// A section header inside a segment command.
#[derive(Clone, Debug)]
pub struct Section {
    pub sectname: String,
    pub addr: u64,
    pub size: u64,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    /// Byte offset of this section header within the load commands.
    cmd_offset: usize,
}

impl Section {
    pub fn section_type(&self) -> u32 {
        self.flags & 0xff
    }

    pub fn is_code(&self) -> bool {
        self.flags & 0x8000_0400 != 0
    }

    fn is_zerofill(&self) -> bool {
        matches!(self.section_type(), 0x1 | 0xc | 0x12)
    }
}

/// A segment command of a cache image.
#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub sections: Vec<Section>,
    cmd_offset: usize,
}

impl Segment {
    pub fn contains(&self, va: u64) -> bool {
        va >= self.vmaddr && va < self.vmaddr + self.vmsize
    }
}

/// An image's Mach-O header and load commands, read from the cache.
#[derive(Debug)]
pub struct ImageLayout {
    pub address: u64,
    pub width: Width,
    header: Vec<u8>,
    cmds: Vec<u8>,
    pub segments: Vec<Segment>,
    symtab: Option<usize>,
    dysymtab: Option<usize>,
}

impl ImageLayout {
    fn linkedit(&self) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == "__LINKEDIT")
    }

    /// The address a `__LINKEDIT` file offset of this image names.
    fn linkedit_va(&self, offset: u32) -> Option<u64> {
        let le = self.linkedit()?;
        (offset as u64).checked_sub(le.fileoff).map(|d| le.vmaddr + d)
    }

    pub(crate) fn header_flags(&self) -> u32 {
        u32_at(&self.header, 24)
    }

    fn cmd_u32(&self, at: usize) -> u32 {
        u32_at(&self.cmds, at)
    }

    /// The commands, as `(cmd, offset)` pairs.
    fn commands(&self) -> Vec<(u32, usize)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 8 <= self.cmds.len() {
            let size = u32_at(&self.cmds, at + 4) as usize;
            out.push((u32_at(&self.cmds, at), at));
            if size < 8 {
                break;
            }
            at += size;
        }
        out
    }

    /// Does any segment other than `__LINKEDIT` hold `va`?
    pub fn holds(&self, va: u64) -> bool {
        self.segments.iter().any(|s| s.name != "__LINKEDIT" && s.contains(va))
    }
}

fn parse_layout(address: u64, width: Width, header: Vec<u8>, cmds: Vec<u8>) -> ImageLayout {
    let mut layout = ImageLayout { address, width, header, cmds, segments: Vec::new(), symtab: None, dysymtab: None };
    let w = width;
    let [vmaddr, vmsize, fileoff, filesize, nsects] = w.seg;
    let [addr, size, _, _, flags, reserved1, reserved2] = w.sect;
    for (cmd, at) in layout.commands() {
        let c = &layout.cmds[at..];
        match cmd {
            c_ if c_ == w.seg_cmd && c.len() >= w.sect0 => {
                let n = u32_at(c, nsects) as usize;
                let sections = (0..n)
                    .map(|i| w.sect0 + i * w.sect_size)
                    .take_while(|&s| s + w.sect_size <= c.len())
                    .map(|s| Section {
                        sectname: fixed_name(&c[s..s + 16]),
                        addr: w.word(c, s + addr),
                        size: w.word(c, s + size),
                        flags: u32_at(c, s + flags),
                        reserved1: u32_at(c, s + reserved1),
                        reserved2: u32_at(c, s + reserved2),
                        cmd_offset: at + s,
                    })
                    .collect();
                layout.segments.push(Segment {
                    name: fixed_name(&c[8..24]),
                    vmaddr: w.word(c, vmaddr),
                    vmsize: w.word(c, vmsize),
                    fileoff: w.word(c, fileoff),
                    filesize: w.word(c, filesize),
                    sections,
                    cmd_offset: at,
                });
            }
            LC_SYMTAB => layout.symtab = Some(at),
            LC_DYSYMTAB => layout.dysymtab = Some(at),
            _ => {}
        }
    }
    layout
}

fn fixed_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())]).into_owned()
}

/// One symbol-table entry with its name resolved.
#[derive(Clone, Debug)]
pub struct Nlist {
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
    pub name: Vec<u8>,
}

impl Nlist {
    pub(crate) fn parse_all(raw: &[u8], size: usize, pool: &super::StringPool) -> Vec<Nlist> {
        raw.chunks_exact(size)
            .map(|n| Nlist {
                n_type: n[4],
                n_sect: n[5],
                n_desc: u16::from_le_bytes([n[6], n[7]]),
                n_value: if size == 16 { u64_at(n, 8) } else { u64::from(u32_at(n, 8)) },
                name: pool.get(u32_at(n, 0)).to_vec(),
            })
            .collect()
    }

    /// A defined, named, non-debug symbol: one that names an address.
    pub fn names_address(&self) -> bool {
        self.n_type & N_STAB == 0
            && self.n_type & N_TYPE == N_SECT
            && !self.name.is_empty()
            && self.name != REDACTED
    }

    pub fn is_external(&self) -> bool {
        self.n_type & N_EXT != 0
    }
}

impl DyldCache {
    /// The header and load commands of image `index`, read once.
    pub fn image_layout(&self, index: usize) -> Result<Rc<ImageLayout>, String> {
        if let Some(cached) = self.layouts.borrow().get(&index) {
            return cached.clone().ok_or_else(|| format!("image {index} has no readable Mach-O header"));
        }
        let read = || -> Result<ImageLayout, String> {
            let address = self.images.get(index).ok_or("image index out of range")?.address;
            let width = match u32_at(&self.read_va(address, 4)?, 0) {
                MH_MAGIC_64 => WIDE,
                MH_MAGIC => NARROW,
                _ => return Err(format!("image at {address:#x} is not a Mach-O")),
            };
            let header = self.read_va(address, width.header)?;
            let cmds = self.read_va(address + width.header as u64, u32_at(&header, 20) as usize)?;
            Ok(parse_layout(address, width, header, cmds))
        };
        let layout = read().map(Rc::new);
        self.layouts.borrow_mut().insert(index, layout.as_ref().ok().cloned());
        layout
    }

    /// The nlists of image `index`'s own symbol table, names resolved.
    pub(crate) fn image_symbols(&self, index: usize) -> Result<Vec<Nlist>, String> {
        let layout = self.image_layout(index)?;
        let Some(at) = layout.symtab else {
            return Ok(Vec::new());
        };
        let (symoff, nsyms) = (layout.cmd_u32(at + 8), layout.cmd_u32(at + 12) as usize);
        let (stroff, strsize) = (layout.cmd_u32(at + 16), layout.cmd_u32(at + 20) as u64);
        if nsyms == 0 {
            return Ok(Vec::new());
        }
        let sym_va = layout.linkedit_va(symoff).ok_or("symbol table lies outside __LINKEDIT")?;
        let str_va = layout.linkedit_va(stroff).ok_or("string table lies outside __LINKEDIT")?;
        let raw = self.read_va(sym_va, nsyms * layout.width.nlist)?;
        let pool = super::StringPool::read(&|off, len| self.read_va(str_va + off, len), layout.width.nlist, strsize, &raw)?;
        Ok(Nlist::parse_all(&raw, layout.width.nlist, &pool))
    }

    /// Image `index`'s indirect-symbol table, as read from the cache.
    pub(crate) fn image_indirect_symbols(&self, index: usize) -> Result<Vec<u32>, String> {
        let layout = self.image_layout(index)?;
        let Some(at) = layout.dysymtab else {
            return Ok(Vec::new());
        };
        let count = layout.cmd_u32(at + 60) as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let va = layout
            .linkedit_va(layout.cmd_u32(at + 56))
            .ok_or("indirect-symbol table lies outside __LINKEDIT")?;
        Ok(self.read_va(va, count * 4)?.chunks_exact(4).map(|c| u32_at(c, 0)).collect())
    }

    /// Image `index`'s named, defined symbols (its locals from the
    /// local-symbols file first) as locals of a merged image whose section
    /// ordinals for this image start after `section_base`. A symbol whose
    /// ordinal would pass 255 is dropped.
    fn companion_symbols(&self, index: usize, section_base: usize) -> Result<Vec<Nlist>, String> {
        let locals = self.local_symbols(index)?;
        let own = self.image_symbols(index)?;
        Ok(locals
            .into_iter()
            .chain(own)
            .filter(|s| s.names_address())
            .filter_map(|mut s| {
                s.n_sect = u8::try_from(usize::from(s.n_sect) + section_base).ok()?;
                s.n_type &= !(N_EXT | N_PEXT);
                Some(s)
            })
            .collect())
    }

    /// Image `index`'s export trie bytes, empty when it has none.
    pub(crate) fn image_export_trie(&self, index: usize) -> Result<Vec<u8>, String> {
        let layout = self.image_layout(index)?;
        for (cmd, at) in layout.commands() {
            let (off, size) = match cmd {
                LC_DYLD_EXPORTS_TRIE => (layout.cmd_u32(at + 8), layout.cmd_u32(at + 12)),
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => (layout.cmd_u32(at + 40), layout.cmd_u32(at + 44)),
                _ => continue,
            };
            if size == 0 {
                continue;
            }
            let va = layout.linkedit_va(off).ok_or("export trie lies outside __LINKEDIT")?;
            return self.read_va(va, size as usize);
        }
        Ok(Vec::new())
    }

    /// Image `index`'s dylib load commands in ordinal order: `(cmd, install name)`.
    pub(crate) fn image_dependencies(&self, index: usize) -> Result<Vec<(u32, String)>, String> {
        const DYLIB_COMMANDS: [u32; 5] = [0xc, 0x8000_0018, 0x8000_001f, 0x20, 0x8000_0023];
        let layout = self.image_layout(index)?;
        Ok(layout
            .commands()
            .into_iter()
            .filter(|(cmd, _)| DYLIB_COMMANDS.contains(cmd))
            .map(|(cmd, at)| {
                let name_at = at + layout.cmd_u32(at + 8) as usize;
                let size = layout.cmd_u32(at + 4) as usize;
                let raw = layout.cmds.get(name_at..at + size).unwrap_or(&[]);
                (cmd, fixed_name(raw))
            })
            .collect())
    }

    /// Rebuild image `index` as a standalone thin Mach-O.
    pub fn extract(&self, index: usize) -> Result<Vec<u8>, String> {
        self.extract_with(index, &[])
    }

    /// Rebuild image `index` with the segments and symbols of `companions`
    /// added, so code in those images is mapped, named and decompilable in the
    /// same program. A companion's symbols become locals; the primary image
    /// keeps its own imports, exports and cross-image names.
    pub fn extract_with(&self, index: usize, companions: &[usize]) -> Result<Vec<u8>, String> {
        let layout = self.image_layout(index)?;
        let cputype = u32_at(&layout.header, 4);
        if ![CPU_TYPE_ARM64, CPU_TYPE_ARM64_32, CPU_TYPE_X86_64].contains(&cputype) {
            return Err(format!("dyld cache image cputype {cputype:#x} is not arm64, arm64_32 or x86_64"));
        }
        let w = layout.width;
        layout.linkedit().ok_or("image has no __LINKEDIT segment")?;
        let companions: Vec<(usize, Rc<ImageLayout>)> = companions
            .iter()
            .filter(|&&c| c != index)
            .map(|&c| self.image_layout(c).map(|l| (c, l)))
            .collect::<Result<_, _>>()?;
        if companions.iter().any(|(_, l)| l.width.wide != w.wide) {
            return Err("companion images must have the primary image's pointer width".into());
        }

        let mut out = Vec::new();
        let mut placed: Vec<(usize, u64)> = Vec::new();
        let text = layout.segments.iter().position(|s| s.vmaddr == layout.address).unwrap_or(0);
        let reserved = if companions.is_empty() {
            None
        } else {
            let extra: usize = companions
                .iter()
                .flat_map(|(_, l)| companion_cmds(l).into_iter().map(|(i, _)| segment_cmd_size(l, i)))
                .sum();
            Some(align((w.header + layout.cmds.len() + 40 + extra) as u64, PAGE))
        };
        out.resize(reserved.unwrap_or(0) as usize, 0);
        let order = std::iter::once(text).chain((0..layout.segments.len()).filter(|&i| i != text));
        for i in order {
            let seg = &layout.segments[i];
            if seg.name == "__LINKEDIT" {
                continue;
            }
            let offset = if i == text && reserved.is_none() { 0 } else { align(out.len() as u64, PAGE) };
            out.resize(offset as usize, 0);
            if seg.filesize > 0 {
                out.extend(self.read_slid(seg.vmaddr, seg.filesize as usize)?);
            }
            placed.push((i, offset));
        }
        let file_offset_of = |i: usize| placed.iter().find(|p| p.0 == i).map(|p| p.1);
        let mut companion_placed: Vec<Vec<(usize, u64)>> = Vec::new();
        for (_, l) in &companions {
            let mut segs = Vec::new();
            for (i, seg) in companion_cmds(l) {
                let offset = align(out.len() as u64, PAGE);
                out.resize(offset as usize, 0);
                if seg.filesize > 0 {
                    out.extend(self.read_slid(seg.vmaddr, seg.filesize as usize)?);
                }
                segs.push((i, offset));
            }
            companion_placed.push(segs);
        }

        let mut xrefs = {
            let view = |va: u64, len: usize| -> Option<&[u8]> {
                let (i, off) = placed.iter().find(|(i, _)| {
                    let s = &layout.segments[*i];
                    va >= s.vmaddr && va + len as u64 <= s.vmaddr + s.filesize
                })?;
                let start = (off + (va - layout.segments[*i].vmaddr)) as usize;
                out.get(start..start + len)
            };
            super::xrefs::collect(self, index, &layout, cputype != CPU_TYPE_X86_64, false, &view)
        };

        for ((c, l), segs) in companions.iter().zip(&companion_placed) {
            let view = |va: u64, len: usize| -> Option<&[u8]> {
                let (i, off) = segs.iter().find(|(i, _)| {
                    let s = &l.segments[*i];
                    va >= s.vmaddr && va + len as u64 <= s.vmaddr + s.filesize
                })?;
                let start = (off + (va - l.segments[*i].vmaddr)) as usize;
                out.get(start..start + len)
            };
            xrefs.extend(super::xrefs::collect(self, *c, l, cputype != CPU_TYPE_X86_64, true, &view));
        }
        let mut section_base = layout.segments.iter().map(|s| s.sections.len()).sum::<usize>();
        let mut extra_symbols = Vec::new();
        for (c, l) in &companions {
            extra_symbols.extend(self.companion_symbols(*c, section_base)?);
            section_base += l.segments.iter().map(|s| s.sections.len()).sum::<usize>();
        }
        let linkedit = self.build_linkedit(index, &layout, &xrefs, extra_symbols)?;
        let le_offset = align(out.len() as u64, PAGE);
        out.resize(le_offset as usize, 0);
        out.extend(&linkedit.bytes);

        let mut cmds = layout.cmds.clone();
        for (seg_index, seg) in layout.segments.iter().enumerate() {
            let at = seg.cmd_offset;
            let [_, vmsize, fileoff, filesize, _] = w.seg;
            let [_, _, sect_offset, reloff, ..] = w.sect;
            if seg.name == "__LINKEDIT" {
                w.put_word(&mut cmds, at + vmsize, align(linkedit.bytes.len() as u64, PAGE));
                w.put_word(&mut cmds, at + fileoff, le_offset);
                w.put_word(&mut cmds, at + filesize, linkedit.bytes.len() as u64);
                continue;
            }
            let base = file_offset_of(seg_index).unwrap_or(0);
            w.put_word(&mut cmds, at + fileoff, base);
            for sec in &seg.sections {
                let offset = if sec.is_zerofill() || sec.size == 0 { 0 } else { base + (sec.addr - seg.vmaddr) };
                put_u32(&mut cmds, sec.cmd_offset + sect_offset, offset as u32);
                put_u32(&mut cmds, sec.cmd_offset + reloff, 0);
                put_u32(&mut cmds, sec.cmd_offset + reloff + 4, 0);
            }
        }
        let rel = |off: u64| (le_offset + off) as u32;
        for (cmd, at) in layout.commands() {
            match cmd {
                LC_SYMTAB => {
                    put_u32(&mut cmds, at + 8, rel(linkedit.symoff));
                    put_u32(&mut cmds, at + 12, linkedit.nsyms);
                    put_u32(&mut cmds, at + 16, rel(linkedit.stroff));
                    put_u32(&mut cmds, at + 20, linkedit.strsize);
                }
                LC_DYSYMTAB => {
                    let [ilocal, nlocal, iextdef, nextdef, iundef, nundef] = linkedit.dysymtab;
                    for (field, value) in [ilocal, nlocal, iextdef, nextdef, iundef, nundef].into_iter().enumerate() {
                        put_u32(&mut cmds, at + 8 + field * 4, value);
                    }
                    for field in (32..80).step_by(4) {
                        put_u32(&mut cmds, at + field, 0);
                    }
                    if linkedit.nindirect > 0 {
                        put_u32(&mut cmds, at + 56, rel(linkedit.indirectoff));
                        put_u32(&mut cmds, at + 60, linkedit.nindirect);
                    }
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    for field in (8..48).step_by(4) {
                        put_u32(&mut cmds, at + field, 0);
                    }
                    if let Some((off, size)) = linkedit.copied(LC_DYLD_EXPORTS_TRIE) {
                        put_u32(&mut cmds, at + 40, rel(off));
                        put_u32(&mut cmds, at + 44, size);
                    }
                }
                c if LINKEDIT_DATA_COMMANDS.contains(&c) => {
                    let (off, size) = linkedit.copied(c).map(|(o, s)| (rel(o), s)).unwrap_or((0, 0));
                    put_u32(&mut cmds, at + 8, off);
                    put_u32(&mut cmds, at + 12, size);
                }
                _ => {}
            }
        }
        let mut ncmds = u32_at(&layout.header, 16);
        for ((_, l), segs) in companions.iter().zip(&companion_placed) {
            let [_, _, fileoff, _, _] = w.seg;
            let [_, _, sect_offset, reloff, ..] = w.sect;
            for &(i, base) in segs {
                let seg = &l.segments[i];
                let start = seg.cmd_offset;
                let mut cmd = l.cmds[start..start + segment_cmd_size(l, i)].to_vec();
                w.put_word(&mut cmd, fileoff, base);
                for sec in &seg.sections {
                    let at = sec.cmd_offset - start;
                    let offset = if sec.is_zerofill() || sec.size == 0 { 0 } else { base + (sec.addr - seg.vmaddr) };
                    put_u32(&mut cmd, at + sect_offset, offset as u32);
                    put_u32(&mut cmd, at + reloff, 0);
                    put_u32(&mut cmd, at + reloff + 4, 0);
                    if INDIRECT_SECTION_TYPES.contains(&sec.section_type()) {
                        let flags = w.sect[4];
                        put_u32(&mut cmd, at + flags, sec.flags & !0xff);
                    }
                }
                cmds.extend(cmd);
                ncmds += 1;
            }
        }
        if let Some((off, size)) = linkedit.note {
            let mut note = Vec::with_capacity(40);
            note.extend(LC_NOTE.to_le_bytes());
            note.extend(40u32.to_le_bytes());
            note.extend(super::xrefs::NOTE_OWNER);
            note.extend((le_offset + off).to_le_bytes());
            note.extend(size.to_le_bytes());
            cmds.extend(note);
            ncmds += 1;
        }

        let room = layout.segments[text]
            .sections
            .iter()
            .filter(|s| s.size > 0 && !s.is_zerofill())
            .map(|s| s.addr - layout.segments[text].vmaddr)
            .min()
            .unwrap_or(layout.segments[text].filesize);
        if (w.header + cmds.len()) as u64 > reserved.unwrap_or(room) {
            return Err(format!(
                "no room for {} bytes of load commands before the first section of {}",
                cmds.len(),
                self.images[index].path
            ));
        }
        let mut header = layout.header.clone();
        put_u32(&mut header, 16, ncmds);
        put_u32(&mut header, 20, cmds.len() as u32);
        out[..w.header].copy_from_slice(&header);
        out[w.header..w.header + cmds.len()].copy_from_slice(&cmds);
        Ok(out)
    }

    fn build_linkedit(
        &self,
        index: usize,
        layout: &ImageLayout,
        xrefs: &[super::xrefs::Xref],
        extra_symbols: Vec<Nlist>,
    ) -> Result<Linkedit, String> {
        let mut symbols = self.image_symbols(index)?;
        let mut dysymtab = [0u32; 6];
        let mut indirect = Vec::new();
        if let Some(at) = layout.dysymtab {
            for (i, field) in dysymtab.iter_mut().enumerate() {
                *field = layout.cmd_u32(at + 8 + i * 4);
            }
            let [ilocal, nlocal, ..] = dysymtab;
            let locals = self.local_symbols(index)?;
            let local_end = (ilocal + nlocal) as usize;
            let replace = !locals.is_empty() && local_end <= symbols.len();
            let added = if replace { locals.len() as i64 - nlocal as i64 } else { 0 };
            let remap = |old: u32| -> u32 {
                if !replace || old < ilocal {
                    old
                } else if (old as usize) < local_end {
                    INDIRECT_SYMBOL_LOCAL
                } else {
                    (old as i64 + added) as u32
                }
            };
            indirect = self
                .image_indirect_symbols(index)?
                .into_iter()
                .map(|v| if v & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 { v } else { remap(v) })
                .collect();
            if replace {
                let count = locals.len() as u32;
                symbols.splice(ilocal as usize..local_end, locals);
                dysymtab[1] = count;
                dysymtab[2] = remap(dysymtab[2]);
                dysymtab[4] = remap(dysymtab[4]);
            }
        }

        if !extra_symbols.is_empty() {
            let at = if layout.dysymtab.is_some() { (dysymtab[0] + dysymtab[1]) as usize } else { symbols.len() };
            let at = at.min(symbols.len());
            let n = extra_symbols.len() as u32;
            symbols.splice(at..at, extra_symbols);
            if layout.dysymtab.is_some() {
                dysymtab[1] += n;
                dysymtab[2] += n;
                dysymtab[4] += n;
            }
            for v in indirect.iter_mut().filter(|v| **v & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) == 0) {
                if *v as usize >= at {
                    *v += n;
                }
            }
        }
        for sym in symbols.iter_mut().filter(|s| s.name == REDACTED) {
            sym.name.clear();
        }
        let mut le = Linkedit::default();
        let mut strings = vec![0u8];
        let w = layout.width;
        let mut nlists = Vec::with_capacity(symbols.len() * w.nlist);
        for sym in &symbols {
            let strx = if sym.name.is_empty() {
                0
            } else {
                let at = strings.len() as u32;
                strings.extend(&sym.name);
                strings.push(0);
                at
            };
            nlists.extend(strx.to_le_bytes());
            nlists.extend([sym.n_type, sym.n_sect]);
            nlists.extend(sym.n_desc.to_le_bytes());
            if w.wide {
                nlists.extend(sym.n_value.to_le_bytes());
            } else {
                nlists.extend((sym.n_value as u32).to_le_bytes());
            }
        }
        le.symoff = le.push(&nlists);
        le.nsyms = symbols.len() as u32;
        le.dysymtab = dysymtab;
        if !indirect.is_empty() {
            let raw: Vec<u8> = indirect.iter().flat_map(|v| v.to_le_bytes()).collect();
            le.indirectoff = le.push(&raw);
            le.nindirect = indirect.len() as u32;
        }
        for (cmd, at) in layout.commands() {
            let (kind, off, size) = match cmd {
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    (LC_DYLD_EXPORTS_TRIE, layout.cmd_u32(at + 40), layout.cmd_u32(at + 44))
                }
                LC_DYLD_EXPORTS_TRIE | LC_FUNCTION_STARTS | LC_DATA_IN_CODE => {
                    (cmd, layout.cmd_u32(at + 8), layout.cmd_u32(at + 12))
                }
                _ => continue,
            };
            if size == 0 || le.copied(kind).is_some() {
                continue;
            }
            let va = layout.linkedit_va(off).ok_or("linkedit data lies outside __LINKEDIT")?;
            let bytes = self.read_va(va, size as usize)?;
            let at = le.push(&bytes);
            le.copies.push((kind, at, size));
        }
        if !xrefs.is_empty() {
            let blob = super::xrefs::encode(xrefs);
            let at = le.push(&blob);
            le.note = Some((at, blob.len() as u64));
        }
        le.stroff = le.push(&strings);
        le.strsize = strings.len() as u32;
        Ok(le)
    }
}

/// The private `__LINKEDIT` being assembled; offsets are from its start.
#[derive(Default)]
struct Linkedit {
    bytes: Vec<u8>,
    symoff: u64,
    nsyms: u32,
    stroff: u64,
    strsize: u32,
    dysymtab: [u32; 6],
    indirectoff: u64,
    nindirect: u32,
    copies: Vec<(u32, u64, u32)>,
    note: Option<(u64, u64)>,
}

impl Linkedit {
    fn push(&mut self, data: &[u8]) -> u64 {
        let at = align(self.bytes.len() as u64, 8);
        self.bytes.resize(at as usize, 0);
        self.bytes.extend(data);
        at
    }

    fn copied(&self, cmd: u32) -> Option<(u64, u32)> {
        self.copies.iter().find(|c| c.0 == cmd).map(|c| (c.1, c.2))
    }
}

/// The segments of `layout` a merged image copies: all but `__LINKEDIT`.
fn companion_cmds(layout: &ImageLayout) -> Vec<(usize, &Segment)> {
    layout.segments.iter().enumerate().filter(|(_, s)| s.name != "__LINKEDIT").collect()
}

/// The byte size of segment command `index` of `layout`.
fn segment_cmd_size(layout: &ImageLayout, index: usize) -> usize {
    u32_at(&layout.cmds, layout.segments[index].cmd_offset + 4) as usize
}

fn align(v: u64, to: u64) -> u64 {
    v.div_ceil(to) * to
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
