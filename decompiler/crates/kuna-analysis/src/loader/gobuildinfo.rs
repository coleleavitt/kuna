//! (kuna) The Go toolchain version off the `.go.buildinfo` blob.
//!
//! The runtime's own struct layouts drift release to release (go1.23 inserted
//! `g.syscallbp`, go1.25 dropped `gobuf.ret`), so the `goreg` shells must know
//! which release built the image. The version string is embedded in the
//! build-info blob the detection section carries (`debug/buildinfo` format):
//! a 32-byte header — the 14-byte magic `"\xff Go buildinf:"`, a pointer-size
//! byte, a flags byte — then, when flags bit 1 is set (every toolchain since
//! go1.18, the whole register-ABI era), two varint-length-prefixed strings:
//! the version (`"go1.22.10"`) and the modinfo. Older toolchains store two
//! pointers at offset 16 instead, each to a Go string header; that form is
//! read through the image's sections ([`go_version_any`]), because it is what
//! tells a go1.16 image (stack ABI0 on x86-64) from a go1.17 one (register ABI).

use object::read::{Object, ObjectSection};

/// Section names the build-info blob lives under, per format.
const BUILDINFO_SECTIONS: [&str; 2] = [".go.buildinfo", "__go_buildinfo"];

/// The build-info magic (14 bytes).
const MAGIC: &[u8; 14] = b"\xff Go buildinf:";

/// Parse `"go<maj>.<min>[...]"` into `(maj, min)`.
fn parse_go_version(s: &str) -> Option<(u16, u16)> {
    let rest = s.strip_prefix("go")?;
    let mut it = rest.split('.');
    let maj: u16 = it.next()?.parse().ok()?;
    let min_tok = it.next()?;
    // A devel or rc suffix stops the digits ("1.25rc1"): take the digit run.
    let digits: String = min_tok.chars().take_while(|c| c.is_ascii_digit()).collect();
    let min: u16 = digits.parse().ok()?;
    Some((maj, min))
}

/// Read a uvarint; returns `(value, len)`.
fn uvarint(b: &[u8]) -> Option<(u64, usize)> {
    let mut x: u64 = 0;
    let mut s = 0u32;
    for (i, &c) in b.iter().take(10).enumerate() {
        if c < 0x80 {
            return Some((x | (u64::from(c) << s), i + 1));
        }
        x |= u64::from(c & 0x7f) << s;
        s += 7;
    }
    None
}

/// The toolchain version from a raw build-info blob (the section's bytes).
pub fn version_from_blob(blob: &[u8]) -> Option<(u16, u16)> {
    if blob.len() < 34 || &blob[..14] != MAGIC {
        return None;
    }
    let flags = blob[15];
    if flags & 0x2 == 0 {
        return None; // pointer-indirection form: pre-go1.18, pre-register-ABI
    }
    let (len, n) = uvarint(&blob[32..])?;
    let start = 32 + n;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    let s = core::str::from_utf8(blob.get(start..end)?).ok()?;
    parse_go_version(s.trim())
}

/// The version from a pre-go1.18 build-info blob at `blob_vma`: word 16 points
/// to a `{data, len}` string header holding the version.
fn version_from_pointer_blob(file: &object::File, blob: &[u8]) -> Option<(u16, u16)> {
    if blob.len() < 32 || &blob[..14] != MAGIC || blob[15] & 0x2 != 0 {
        return None;
    }
    let ps = usize::from(blob[14]);
    let big = blob[15] & 0x1 != 0;
    let word = |b: &[u8]| -> Option<u64> {
        let b = b.get(..ps)?;
        let mut v = 0u64;
        for (i, &c) in b.iter().enumerate() {
            let shift = if big { 8 * (ps - 1 - i) } else { 8 * i };
            v |= u64::from(c) << shift;
        }
        Some(v)
    };
    if ps != 4 && ps != 8 {
        return None;
    }
    let hdr = read_va(file, word(&blob[16..])?, 2 * ps)?;
    let (data, len) = (word(&hdr)?, word(&hdr[ps..])?);
    let text = read_va(file, data, usize::try_from(len).ok().filter(|&l| l <= 64)?)?;
    parse_go_version(core::str::from_utf8(&text).ok()?.trim())
}

/// `len` bytes at virtual address `va`, from the section holding them.
fn read_va(file: &object::File, va: u64, len: usize) -> Option<Vec<u8>> {
    file.sections().find_map(|s| {
        let off = va.checked_sub(s.address())?;
        let data = s.data().ok()?;
        let start = usize::try_from(off).ok()?;
        data.get(start..start.checked_add(len)?).map(<[u8]>::to_vec)
    })
}

/// The Go toolchain version from either build-info form.
pub fn go_version_any(bytes: &[u8]) -> Option<(u16, u16)> {
    go_version_of(&object::File::parse(bytes).ok()?)
}

/// [`go_version_any`] over an already parsed image.
pub fn go_version_of(file: &object::File) -> Option<(u16, u16)> {
    for name in BUILDINFO_SECTIONS {
        if let Some(data) = file.section_by_name(name).and_then(|s| s.data().ok()) {
            if let Some(v) = version_from_blob(data).or_else(|| version_from_pointer_blob(file, data)) {
                return Some(v);
            }
        }
    }
    None
}

/// Whether a Go image passes arguments on the stack (ABI0) rather than in
/// registers (ABIInternal). The register ABI arrived in go1.17 on amd64 and in
/// go1.18 on arm64, ppc64 and riscv64; 386 and the rest never got it. The
/// build-info version decides; without one, the pclntab magic gives a range,
/// and `None` means the range straddles the switch (amd64 go1.16-1.17).
pub fn go_uses_stack_abi(bytes: &[u8], arm64: bool) -> Option<bool> {
    let first_regabi = if arm64 { 18 } else { 17 };
    if let Some((1, minor)) = go_version_any(bytes) {
        return Some(minor < first_regabi);
    }
    let file = object::File::parse(bytes).ok()?;
    let img = crate::pclntab::ImageBytes::new(&file);
    let hdr: [u8; 4] = img.read(crate::pclntab::locate_header(&file, &img)?, 4)?.try_into().ok()?;
    let magic = if file.is_little_endian() { u32::from_le_bytes(hdr) } else { u32::from_be_bytes(hdr) };
    match magic {
        0xffff_fffb => Some(true),
        0xffff_fffa if arm64 => Some(true),
        0xffff_fffa => None,
        0xffff_fff0 | 0xffff_fff1 => Some(false),
        _ => None,
    }
}

/// The Go toolchain version that built `bytes`, if it is a Go image with an
/// inline-strings build-info blob. Pure and total over arbitrary bytes.
pub fn go_toolchain_version(bytes: &[u8]) -> Option<(u16, u16)> {
    let file = object::File::parse(bytes).ok()?;
    for name in BUILDINFO_SECTIONS {
        if let Some(data) = file.section_by_name(name).and_then(|s| s.data().ok()) {
            if let Some(v) = version_from_blob(data) {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(version: &str, flags: u8) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.push(8); // ptr size
        b.push(flags);
        b.resize(32, 0);
        b.push(u8::try_from(version.len()).unwrap()); // uvarint (short)
        b.extend_from_slice(version.as_bytes());
        b
    }

    #[test]
    fn inline_blob_parses_and_old_forms_refuse() {
        assert_eq!(version_from_blob(&blob("go1.22.10", 2)), Some((1, 22)));
        assert_eq!(version_from_blob(&blob("go1.25.3", 2)), Some((1, 25)));
        assert_eq!(version_from_blob(&blob("go1.25rc1", 2)), Some((1, 25)));
        // pointer-indirection form (pre-1.18) is deliberately unparsed
        assert_eq!(version_from_blob(&blob("go1.16.5", 0)), None);
        // wrong magic / truncation / junk
        assert_eq!(version_from_blob(b"not a blob"), None);
        assert_eq!(version_from_blob(&blob("devel +abc", 2)), None);
        assert_eq!(version_from_blob(&[]), None);
    }

    #[test]
    fn corpus_binaries_state_their_toolchains() {
        // The campaign corpus carries both eras; missing files skip (the
        // corpus is machine-local state, not a repo fixture).
        for (p, want) in [
            ("/home/mahaloz/kwt/multilang/corpus/go/hello", (1u16, 22u16)),
        ] {
            if let Ok(bytes) = std::fs::read(p) {
                assert_eq!(go_toolchain_version(&bytes), Some(want), "{p}");
            }
        }
    }
}
