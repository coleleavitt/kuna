//! (kuna `dexmodel`) The DEX `LoadImage`: each DEX file mapped whole, read-only.
//!
//! Ghidra's `DexLoader` maps the file as one `.dex` block at offset 0 and
//! copies each method's instructions to a second block; kuna decodes the
//! instructions where they are, so the one mapping is the whole image. An APK is
//! a zip of `classes.dex`, `classes2.dex`, ...: its DEX files are mapped one
//! after another, each at a 64 KiB boundary. The method tables and constant
//! pools live in [`kuna_decomp::kuna_dex::DexModel`].

use std::rc::Rc;

use kuna_base::address::{Address, RangeList};
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::AddrSpace;
use kuna_decomp::kuna_dex::DexModel;
use kuna_sleigh::loadimage::{section_flags, LoadImage, LoadImageSection};

/// The language a DEX file decodes with unless the caller names another.
pub const DEX_LANGUAGE: &str = "Dalvik:LE:32:DEX_Android12";

pub use kuna_decomp::kuna_dex::format::is_dex;

/// Alignment of each DEX file's mapping after the first.
const DEX_ALIGN: u64 = 0x1_0000;

/// Largest DEX file kuna inflates out of an APK.
const MAX_DEX_SIZE: usize = 1 << 30;

/// Is `bytes` a zip whose root holds a `classes.dex`?
pub fn is_apk(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") && apk_dex_names(bytes).is_ok_and(|names| !names.is_empty())
}

/// Parse a DEX file, or every `classes*.dex` of an APK, mapping them in
/// order from address 0.
pub fn load_dex_models(bytes: Vec<u8>) -> KunaResult<Vec<Rc<DexModel>>> {
    let files = if is_dex(&bytes) { vec![bytes] } else { apk_dex_files(&bytes)? };
    let mut models = Vec::with_capacity(files.len());
    let mut base: u64 = 0;
    for file in files {
        let len = file.len() as u64;
        models.push(Rc::new(DexModel::parse(file, base)?));
        base = (base + len).div_ceil(DEX_ALIGN) * DEX_ALIGN;
        if base > u64::from(u32::MAX) {
            return Err(KunaError::lowlevel("DEX files do not fit in the 32-bit address space"));
        }
    }
    Ok(models)
}

struct ZipEntry {
    name: String,
    method: u16,
    compressed: usize,
    size: usize,
    local: usize,
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn bad_zip(what: &str) -> KunaError {
    KunaError::lowlevel(format!("malformed APK: {what}"))
}

/// The `classes.dex`, `classes2.dex`, ... index from an entry name.
fn dex_number(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    match digits {
        "" => Some(1),
        _ if digits.starts_with('0') => None,
        _ => digits.parse().ok().filter(|&n| n >= 2),
    }
}

/// The zip central directory's `classes*.dex` entries, in load order.
fn apk_dex_names(bytes: &[u8]) -> KunaResult<Vec<(u32, ZipEntry)>> {
    let floor = bytes.len().saturating_sub(22 + 0xffff);
    let eocd = (floor..=bytes.len().saturating_sub(22))
        .rev()
        .find(|&at| le32(bytes, at) == Some(0x0605_4b50))
        .ok_or_else(|| bad_zip("no end of central directory"))?;
    let count = le16(bytes, eocd + 10).ok_or_else(|| bad_zip("truncated directory"))?;
    let mut at = le32(bytes, eocd + 16).ok_or_else(|| bad_zip("truncated directory"))? as usize;
    let mut entries = Vec::new();
    for _ in 0..count {
        if le32(bytes, at) != Some(0x0201_4b50) {
            return Err(bad_zip("bad central directory entry"));
        }
        let field = |off: usize| le32(bytes, at + off).ok_or_else(|| bad_zip("truncated directory"));
        let short = |off: usize| le16(bytes, at + off).ok_or_else(|| bad_zip("truncated directory"));
        let (name_len, extra_len, comment_len) = (short(28)? as usize, short(30)? as usize, short(32)? as usize);
        let name = bytes.get(at + 46..at + 46 + name_len).ok_or_else(|| bad_zip("truncated name"))?;
        let entry = ZipEntry {
            name: String::from_utf8_lossy(name).into_owned(),
            method: short(10)?,
            compressed: field(20)? as usize,
            size: field(24)? as usize,
            local: field(42)? as usize,
        };
        if let Some(number) = dex_number(&entry.name) {
            entries.push((number, entry));
        }
        at += 46 + name_len + extra_len + comment_len;
    }
    entries.sort_by_key(|(number, _)| *number);
    Ok(entries)
}

/// Inflate an APK's `classes*.dex` files, in load order.
pub fn apk_dex_files(bytes: &[u8]) -> KunaResult<Vec<Vec<u8>>> {
    let mut files = Vec::new();
    for (_, entry) in apk_dex_names(bytes)? {
        if entry.size > MAX_DEX_SIZE || entry.compressed == u32::MAX as usize {
            return Err(bad_zip(&format!("{} is too large", entry.name)));
        }
        if le32(bytes, entry.local) != Some(0x0403_4b50) {
            return Err(bad_zip("bad local header"));
        }
        let name_len = le16(bytes, entry.local + 26).ok_or_else(|| bad_zip("truncated local header"))? as usize;
        let extra_len = le16(bytes, entry.local + 28).ok_or_else(|| bad_zip("truncated local header"))? as usize;
        let start = entry.local + 30 + name_len + extra_len;
        let data = bytes.get(start..start + entry.compressed).ok_or_else(|| bad_zip("truncated entry"))?;
        let file = match entry.method {
            0 => data.to_vec(),
            8 => {
                let mut out = Vec::with_capacity(entry.size);
                std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(data), &mut out)
                    .map_err(|e| bad_zip(&format!("{}: {e}", entry.name)))?;
                out
            }
            other => return Err(bad_zip(&format!("{} uses compression method {other}", entry.name))),
        };
        if file.len() != entry.size {
            return Err(bad_zip(&format!("{} inflates to the wrong size", entry.name)));
        }
        files.push(file);
    }
    if files.is_empty() {
        return Err(bad_zip("no classes.dex"));
    }
    Ok(files)
}

/// DEX files mapped in the attached space.
pub struct DexLoadImage {
    filename: String,
    models: Vec<Rc<DexModel>>,
    space: Option<Rc<AddrSpace>>,
    section_cursor: std::cell::Cell<usize>,
}

impl DexLoadImage {
    pub fn new(filename: &str, models: Vec<Rc<DexModel>>) -> DexLoadImage {
        DexLoadImage { filename: filename.to_string(), models, space: None, section_cursor: std::cell::Cell::new(0) }
    }

    /// The default code space the image maps into.
    pub fn attach_to_space(&mut self, space: Rc<AddrSpace>) {
        self.space = Some(space);
    }

    fn mappings(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.models.iter().map(|m| (m.base, m.file.bytes().len() as u64))
    }
}

impl LoadImage for DexLoadImage {
    fn get_file_name(&self) -> &str {
        &self.filename
    }

    fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
        let start = addr.get_offset();
        let attached = match (addr.get_space(), self.space.as_ref()) {
            (Some(space), Some(own)) => Rc::ptr_eq(space, own),
            _ => false,
        };
        let model = self.models.iter().find(|m| m.contains(start)).filter(|_| attached);
        let Some(model) = model else {
            return Err(KunaError::data_unavail(format!(
                "Unable to load {} bytes at {}:0x{start:x}",
                ptr.len(),
                addr.get_shortcut()
            )));
        };
        let bytes = model.file.bytes();
        let off = (start - model.base) as usize;
        let count = ptr.len().min(bytes.len() - off);
        ptr[..count].copy_from_slice(&bytes[off..off + count]);
        ptr[count..].fill(0);
        Ok(())
    }

    fn open_section_info(&self) {
        self.section_cursor.set(0);
    }

    fn get_next_section(&self, record: &mut LoadImageSection) -> bool {
        let index = self.section_cursor.get();
        let (Some(space), Some((base, len))) = (self.space.as_ref(), self.mappings().nth(index)) else {
            return false;
        };
        record.address = Address::new(Rc::clone(space), base);
        record.size = len;
        record.flags = section_flags::CODE | section_flags::READONLY;
        self.section_cursor.set(index + 1);
        index + 1 < self.models.len()
    }

    fn get_segments(&self) -> Vec<(u64, u64, u32)> {
        self.mappings().map(|(base, len)| (base, len, section_flags::CODE | section_flags::READONLY)).collect()
    }

    fn get_readonly(&self, list: &mut RangeList) {
        if let Some(space) = self.space.as_ref() {
            for (base, len) in self.mappings() {
                list.insert_range(Rc::clone(space), base, base + len.saturating_sub(1));
            }
        }
    }

    fn get_arch_type(&self) -> Vec<u8> {
        DEX_LANGUAGE.as_bytes().to_vec()
    }

    fn adjust_vma(&mut self, _adjust: i64) {}
}


#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Vec<u8> {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tests/stages/fixtures/dex/hello.dex")).to_vec()
    }

    /// A zip of `entries` (`name`, `method`, `data`), with the central directory
    /// listing them in the order given.
    fn zip(entries: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, method, data) in entries {
            let stored = if *method == 8 {
                let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                std::io::Write::write_all(&mut encoder, data).unwrap();
                encoder.finish().unwrap()
            } else {
                data.clone()
            };
            let local = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&stored);
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 8]);
            central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&local.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn an_apk_maps_its_dex_files_in_classes_order() {
        let apk = zip(&[
            ("classes2.dex", 0, hello()),
            ("res/raw/classes.dex.txt", 0, b"not code".to_vec()),
            ("classes.dex", 8, hello()),
        ]);
        assert!(is_apk(&apk));
        let models = load_dex_models(apk).unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].base, 0);
        assert_eq!(models[1].base, 0x1_0000);
        let first = models[0].functions();
        let second = models[1].functions();
        assert_eq!(second[0].addr, first[0].addr + 0x1_0000);
    }

    #[test]
    fn a_zip_without_classes_dex_is_not_an_apk() {
        assert!(!is_apk(&zip(&[("classes.jar", 0, hello())])));
        assert!(load_dex_models(zip(&[("classes.dex", 0, b"dex\n035\0".to_vec())])).is_err());
    }
}
