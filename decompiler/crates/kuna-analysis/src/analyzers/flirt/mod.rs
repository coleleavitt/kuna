//! (kuna `flirt`) Name library functions with IDA FLIRT `.sig` signatures.
//!
//! The `.sig` files ship with IDA (`<ida>/sig/<proc>/*.sig`); kuna reads them
//! ([`sig`]) and matches every discovered function entry against them, the way
//! IDA's `AU_LIBF` pass does (`libida.so` 0x8b2260 trie walk, 0x8b04c0 leaf
//! check):
//!
//! 1. walk the byte trie over the first `pattern_len` bytes at the entry;
//! 2. at a leaf, a module matches when the CRC-16 of the `crc_len` bytes after
//!    the prefix, its tail bytes (offsets after the CRC region) and its
//!    expected instruction bits agree;
//! 3. a module that names a referenced function is accepted only when the
//!    instruction at the reference offset branches or calls to a function of
//!    that name. Names found in one round can satisfy references in the next,
//!    so matching runs up to [`MAX_ROUNDS`] rounds (IDA's three `AU_LIBF`
//!    queues).
//!
//! A function is renamed only when every matching module at its entry agrees on
//! the name, a name is given to one address only (IDA's collision rule
//! without `AF_SIGMLT`), and a module no longer than the trie prefix with no
//! reference is skipped (IDA's tiny-module guard: a few bytes match too many
//! stubs). The names go out as [`FidMatch`] renames, so they only replace
//! `sub_` placeholders.
//!
//! The signature files are named by `KUNA_FLIRT_SIGS` (`:`-separated paths).

pub mod sig;

use std::collections::{BTreeMap, HashMap, HashSet};

use object::read::{Object, ObjectSection};

use crate::listing::Listing;
use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, FidMatch, Phase};
use sig::{crc16, Module, Node, Sig};

/// The environment variable that lists the `.sig` files.
pub const FLIRT_SIGS_ENV: &str = "KUNA_FLIRT_SIGS";

/// Matching rounds: a module whose reference names a function another module
/// names is accepted in the round after that name exists.
pub const MAX_ROUNDS: usize = 3;

/// The FLIRT matcher pass (a Listing consumer).
pub struct FlirtPass;

impl AnalysisPass for FlirtPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "flirt"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut out = AnalysisOutput::default();
        let Some(listing) = ctx.listing else { return out };
        let sigs = load_sigs();
        if sigs.is_empty() {
            return out;
        }
        let image = Image::new(ctx.file);
        let entries: Vec<u64> = listing.functions().map(|(&a, _)| a).collect();
        let known: HashMap<u64, String> = listing
            .functions()
            .filter_map(|(&a, f)| f.name.clone().map(|n| (a, n)))
            .collect();
        for (addr, name) in match_all(&sigs, &image, listing, &entries, known) {
            out.fid_names.push(FidMatch { addr, name });
        }
        out
    }
}

/// Parse every file `KUNA_FLIRT_SIGS` names; unreadable or malformed files are
/// skipped.
pub fn load_sigs() -> Vec<Sig> {
    let Some(list) = std::env::var_os(FLIRT_SIGS_ENV) else { return Vec::new() };
    std::env::split_paths(&list)
        .filter_map(|p| std::fs::read(p).ok())
        .filter_map(|d| sig::parse(&d).ok())
        .collect()
}

/// The image bytes by address: every section with file content.
pub struct Image<'a> {
    spans: Vec<(u64, &'a [u8])>,
}

impl<'a> Image<'a> {
    pub fn new(file: &'a object::File<'a>) -> Self {
        let mut spans: Vec<(u64, &[u8])> = file
            .sections()
            .filter(|s| s.address() != 0)
            .filter_map(|s| Some((s.address(), s.data().ok()?)))
            .filter(|(_, d)| !d.is_empty())
            .collect();
        spans.sort_by_key(|&(a, _)| a);
        Image { spans }
    }

    /// The bytes from `addr` to the end of its section.
    pub fn from(&self, addr: u64) -> &'a [u8] {
        self.spans
            .iter()
            .find(|&&(a, d)| addr >= a && addr - a < d.len() as u64)
            .map_or(&[], |&(a, d)| &d[(addr - a) as usize..])
    }
}

/// Run every round of matching and return the accepted `(entry, name)` pairs.
pub fn match_all(
    sigs: &[Sig],
    image: &Image<'_>,
    listing: &Listing,
    entries: &[u64],
    mut known: HashMap<u64, String>,
) -> BTreeMap<u64, String> {
    let mut named: BTreeMap<u64, String> = BTreeMap::new();
    let mut refused: HashSet<String> = HashSet::new();
    for _ in 0..MAX_ROUNDS {
        let mut found: BTreeMap<u64, String> = BTreeMap::new();
        for &ea in entries {
            if named.contains_key(&ea) {
                continue;
            }
            let code = image.from(ea);
            let mut names: Vec<String> = Vec::new();
            for s in sigs {
                for m in candidates(s, code) {
                    if module_matches(s, m, code) && reference_ok(m, ea, listing, &known) {
                        if let Some(name) = function_name(m, s.pattern_len) {
                            names.push(name);
                        }
                    }
                }
            }
            names.sort();
            names.dedup();
            if let [name] = names.as_slice() {
                found.insert(ea, name.clone());
            }
        }
        let mut by_name: HashMap<&str, usize> = HashMap::new();
        for n in found.values().chain(named.values()) {
            *by_name.entry(n.as_str()).or_default() += 1;
        }
        let colliding: Vec<String> =
            by_name.iter().filter(|&(_, &c)| c > 1).map(|(n, _)| n.to_string()).collect();
        refused.extend(colliding);
        let before = named.len();
        for (ea, name) in found {
            if !refused.contains(&name) && !known.values().any(|k| k == &name) {
                known.insert(ea, name.clone());
                named.insert(ea, name);
            }
        }
        named.retain(|_, n| !refused.contains(n));
        if named.len() == before {
            break;
        }
    }
    named
}

/// The modules whose trie path matches `code`.
fn candidates<'s>(s: &'s Sig, code: &[u8]) -> Vec<&'s Module> {
    fn walk<'s>(node: &'s Node, code: &[u8], at: usize, out: &mut Vec<&'s Module>) {
        out.extend(node.modules.iter());
        for c in &node.children {
            let end = at + c.pattern.len();
            let Some(bytes) = code.get(at..end) else { continue };
            if c.pattern.iter().zip(bytes).all(|(p, b)| p.is_none_or(|p| p == *b)) {
                walk(c, code, end, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(&s.root, code, 0, &mut out);
    out
}

/// The CRC, tail-byte and instruction-bit checks of one module at `code`.
fn module_matches(s: &Sig, m: &Module, code: &[u8]) -> bool {
    let p = s.pattern_len;
    let crc_end = p + m.crc_len as usize;
    if m.length as usize > code.len() {
        return false;
    }
    let Some(crc_bytes) = code.get(p.min(crc_end)..crc_end) else { return false };
    if m.crc_len > 0 && crc16(crc_bytes) != m.crc {
        return false;
    }
    if m.tails.iter().any(|&(off, want)| code.get(crc_end + off as usize) != Some(&want)) {
        return false;
    }
    let word = |off: i64| -> Option<u32> {
        let off = usize::try_from(off).ok()?;
        let b = code.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let bits_ok = |off: i64, bits: Option<(u32, u32)>| match bits {
        Some((mask, value)) => word(off).is_some_and(|w| (w ^ value) & mask == 0),
        None => true,
    };
    m.publics.iter().all(|p| bits_ok(p.off, p.bits))
        && m.sites.iter().all(|s| bits_ok(i64::from(s.off), s.bits))
}

/// The module's own name: the public at offset 0, unless it is unnamed (`?`),
/// doubtful (flag 4) or a module too short to tell apart (no longer than the
/// trie prefix, with nothing referenced to check).
fn function_name(m: &Module, pattern_len: usize) -> Option<String> {
    let p = m.publics.iter().find(|p| p.off == 0)?;
    if p.name.is_empty() || p.name.starts_with('?') || p.flags & 0x04 != 0 {
        return None;
    }
    if m.length as usize <= pattern_len && m.reference.is_none() && m.sites.iter().all(|s| s.name.len() < 2) {
        return None;
    }
    Some(p.name.clone())
}

/// A module's reference (and, for a module of at most 16 bytes, its named v11
/// sites) must name a function the instruction at that offset branches or calls
/// to. A target with no name yet leaves the module for a later round.
fn reference_ok(m: &Module, ea: u64, listing: &Listing, known: &HashMap<u64, String>) -> bool {
    let mut wanted: Vec<(i64, &str)> = Vec::new();
    if let Some((off, name)) = &m.reference {
        if name != "." {
            wanted.push((*off, name.as_str()));
        }
    }
    if m.length <= 0x10 {
        wanted.extend(
            m.sites
                .iter()
                .filter(|s| s.name.len() >= 2 && s.flags & 0x08 == 0)
                .map(|s| (i64::from(s.off), s.name.as_str())),
        );
    }
    wanted.into_iter().all(|(off, name)| {
        let Some(at) = ea.checked_add_signed(off) else { return false };
        let Some(insn) = listing.instruction_before(at.saturating_add(1)) else { return false };
        if at >= insn.addr + u64::from(insn.len) {
            return false;
        }
        insn.flows.iter().any(|t| known.get(t).is_some_and(|k| same_name(k, name)))
    })
}

/// FLIRT names carry the object file's spelling (`_strlen` on a Mach-O or COFF
/// library); compare under the `nameladder` spellings.
fn same_name(have: &str, want: &str) -> bool {
    let strip = |s: &str| s.trim_start_matches('_').to_string();
    have == want
        || strip(have) == strip(want)
        || crate::analyzers::protos::kuna_nameladder::fallbacks(have).iter().any(|f| f == want)
}

#[cfg(test)]
mod tests;
