//! S1 FID (Function-ID) fingerprinting — the byte-exact port of Ghidra's
//! FunctionID hashing mechanism.
//!
//! FID re-identifies a function by fingerprinting its instruction stream with an
//! operand-masked FNV-1a64 hash, then matching that fingerprint against a
//! database of known-library hashes — the capability that renames a `FUN_<addr>`
//! in a stripped binary back to (say) `kuna_crc32`. See `docs/history/fid-design.md` for
//! the full plan.
//!
//! # Module set
//!
//! - [`hash`] — [`hash::Fnv1a64`] (the FNV-1a64 digest), [`hash::FidHasher`] (the
//!   operand-masked per-instruction fingerprinter), and [`hash::FidHashQuad`]
//!   (the four-field result). A line-faithful, **byte-exact** port of Ghidra's
//!   `MessageDigestFidHasher` / `FNV1a64MessageDigest`.
//! - [`extent`] — the `FunctionBodyFunctionExtentGenerator` analog: the
//!   address-contiguous `[entry, next_function_after(entry))` body clip over the
//!   Listing.
//! - [`skipper`] — the [`skipper::InstructionSkipper`] trait and
//!   [`skipper::X86InstructionSkipper`] (the x86 NOP/alignment skipper).
//! - [`db`] — the kuna-native `.fid` format ([`db::FidDb`] / [`db::FidRecord`]):
//!   a flat, full-hash-indexed, version-stamped file modeled field-for-field on
//!   Ghidra's FID `FunctionsTable`+`StringsTable`, behind the [`db::FidDatabase`]
//!   trait so a future `.fidbf` reader (deferred PR6) is a serialization swap.
//! - [`build`] — the `FidServiceLibraryIngest` analog ([`build::build_records`]):
//!   disassembles every named function in a parsed object through the Listing
//!   path, runs the [`hash::FidHasher`] over its extent, and emits the
//!   deduplicated records. Drives the `kuna fid build` CLI subcommand.
//!
//! # PR4 (this module) — the gated matching pass
//!
//! [`FidPass`] is the Listing/xref **consumer** (structurally cloned from
//! [`crate::noreturn_disc::NoReturnDiscoveredPass`]): over the built Listing it
//! hashes every function with the byte-exact [`hash::FidHasher`] (driving the PR1
//! [`Sleigh::instruction_mask`](kuna_sleigh::sleigh::Sleigh::instruction_mask)),
//! looks the full hash up in a `.fid` database, and — when the bucket collapses to
//! exactly one name ([`pick_unique_name`], conservative; never guesses on a tie) —
//! emits a [`crate::pass::FidMatch`]. The engine's commit seam then **renames** the
//! function (only if it still carries an engine `FUN_*`/`sub_*` placeholder — the
//! label gate). Default-OFF, real-ELF path only, inert without the Listing AND
//! without a DB — so the parity oracles are structurally untouched.
//!
//! The database path is read from the `kuna_fid_db` environment variable (mirroring
//! how the i386-PIE-PLT loader gate reads `kuna_i386_pie_plt`); a real `--fidb
//! <path>` flag is a deferred follow-on (`docs/history/fid-design.md` §7.2). Absent / empty
//! / unreadable ⇒ the pass is a no-op.

pub mod build;
pub mod db;
pub mod extent;
pub mod hash;
pub mod skipper;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;

use kuna_base::address::Address;

use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, FidMatch, Phase};
use crate::fid::db::{FidDatabase, FidDb, FidRecord};
use crate::fid::hash::{FidHasher, InsnFingerprint, NoRelocations};
use crate::fid::skipper::{InstructionSkipper, X86InstructionSkipper};

/// The environment variable naming the `.fid` fingerprint database to match
/// against. Mirrors the loader-tier `kuna_i386_pie_plt` env gate: the DB source is
/// kept out of the per-decompilation `--option` surface in v1 (a real `--fidb
/// <path>` flag is deferred, `docs/history/fid-design.md` §7.2). Absent / empty ⇒ the pass
/// is inert (no DB to match against).
pub const FID_DB_ENV: &str = "kuna_fid_db";

/// The FID matching consumer pass — the kuna analog of Ghidra's FID identification
/// analyzer (`FidServiceImpl` over the function-id query service), the third
/// Listing/xref consumer.
///
/// Default-OFF (gate id `fid`). Doubly inert by default: it short-circuits to an
/// empty output when no Listing is built (`ctx.listing.is_none()`, the
/// `--option listing on` flag is off) AND when no `.fid` database is configured
/// (`FID_DB_ENV` unset / empty / unreadable). Every emitted [`FidMatch`] is a
/// *rename* fact the engine commit seam applies only to an engine `FUN_*`/`sub_*`
/// placeholder (the label gate) — a real `.symtab`/DWARF name is never overwritten.
#[derive(Default)]
pub struct FidPass;

impl AnalysisPass for FidPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "fid"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut out = AnalysisOutput::default();
        // Listing-dependent: a no-op when the Listing is absent (the `--option
        // listing on` flag is off). Keeps the pass inert by default even if its own
        // gate is flipped on without the Listing.
        let Some(listing) = ctx.listing else {
            return out;
        };
        // DB-dependent: a no-op without a configured, loadable `.fid` database
        // (`kuna_fid_db` unset / empty / unreadable / bad bytes). The DB carries the
        // language id the hashes were computed for; matching across languages is not
        // meaningful, so the absence of a DB is the inert path (faithful to Ghidra,
        // which only queries a language-matched FID DB).
        let Some(db) = load_fid_db(ctx) else {
            return out;
        };

        // The per-architecture skipper set: x86 ⇒ the NOP/alignment skipper
        // (matching the generator); non-x86 ⇒ empty (never skips). Must match the
        // skipper set the DB was built with or the hashes diverge.
        let is_x86 = ctx.arch.archid.starts_with("x86:");

        let Some(code_space) = ctx.arch.manage().get_default_code_space() else {
            return out;
        };
        let code_space = Rc::clone(code_space);
        // FID hashing decodes through the concrete SLEIGH engine
        // (`Sleigh::instruction_mask`); this re-identification path only ever
        // runs on the standalone engine, so downcast through the seam.
        let translate = ctx
            .arch
            .translate()
            .as_sleigh()
            .expect("FID build: standalone Sleigh engine");

        // The relocation oracle: a fully-linked image (the stripped `-static
        // -no-pie` re-identification target) carries no dynamic relocations over its
        // text, so `NoRelocations` is correct — and it matches the build side, which
        // sees no relocations for a self-contained body (the full hash is identical
        // either way; see `hash.rs`'s relocation test). A future PIE/relocatable
        // lookup path can supply an `reloc_object`-backed oracle here.
        let relocs = NoRelocations;

        let chunks = ctx
            .arch
            .analysis_funcchunks
            .then(|| crate::listing::kuna_funcchunks::ChunkModel::build(listing));
        let mut hits: Vec<Hit<'_>> = Vec::new();
        for (&entry, _f) in listing.functions() {
            // §4.3 extent: the address-contiguous `[entry, next)` clip, or the
            // flow body (main chunk plus tails) under `funcchunks`.
            let extent = match &chunks {
                Some(model) => extent::chunk_extent(listing, model, entry),
                None => extent::calculate_extent(listing, entry),
            };
            if extent.len() < hash::SHORT_HASH_CODE_UNIT_LENGTH as usize {
                continue;
            }

            // Assemble each instruction's fingerprint via the PR1 SLEIGH mask —
            // the SAME projection the generator (`build::fingerprint_from_mask`)
            // uses, so a function fingerprints identically whether built into the DB
            // or matched against it. A decode failure on any instruction drops the
            // whole function (a partially-masked body would mis-hash).
            let mut fps: Vec<InsnFingerprint> = Vec::with_capacity(extent.len());
            let mut decode_ok = true;
            for insn in &extent {
                let addr = Address::new(Rc::clone(&code_space), insn.addr);
                match translate.instruction_mask(&addr) {
                    Ok(mask) => fps.push(build::fingerprint_from_mask(
                        insn.addr,
                        insn.len,
                        insn.flow.is_call,
                        mask,
                    )),
                    Err(_) => {
                        decode_ok = false;
                        break;
                    }
                }
            }
            if !decode_ok {
                continue;
            }

            let skippers: Vec<Box<dyn InstructionSkipper>> = if is_x86 {
                vec![Box::new(X86InstructionSkipper)]
            } else {
                vec![]
            };
            let mut hasher = FidHasher::new(skippers);
            let Some(quad) = hasher.hash(&fps, &relocs) else {
                continue;
            };

            // The only hot-path query: the full-hash bucket (§5.1 / §6.1).
            let recs = db.find_by_full_hash(quad.full_hash);
            if std::env::var_os("KUNA_FID_DEBUG").is_some() {
                eprintln!("[fid] {entry:#x}: full={:#018x} n={} recs={}", quad.full_hash, extent.len(), recs.len());
            }
            if recs.is_empty() {
                continue;
            }
            let body = extent
                .iter()
                .zip(&fps)
                .filter(|(_, fp)| !(is_x86 && X86InstructionSkipper.should_skip(&fp.bytes, fp.bytes.len())))
                .map(|(i, _)| (i.addr, i.addr + u64::from(i.len)))
                .collect();
            hits.push(Hit { entry, body, recs });
        }

        if !ctx.arch.analysis_fidcallees {
            for h in &hits {
                if let Some(name) = pick_unique_name(h.recs) {
                    out.fid_names.push(FidMatch { addr: h.entry, name });
                }
            }
            return out;
        }
        let known: HashMap<u64, String> =
            listing.functions().filter_map(|(&a, f)| f.name.clone().map(|n| (a, n))).collect();
        let target_at = |at: u64| listing.instruction_at(at).and_then(|i| i.flows.first().copied());
        for (addr, name) in arbitrate(&hits, known, target_at) {
            out.fid_names.push(FidMatch { addr, name });
        }

        out
    }
}

/// A function whose full hash is in the database: its entry, the address
/// ranges of its instructions other than padding (ascending) and the records
/// of the bucket.
pub struct Hit<'a> {
    pub entry: u64,
    pub body: Vec<(u64, u64)>,
    pub recs: &'a [FidRecord],
}

impl Hit<'_> {
    fn contains(&self, addr: u64) -> bool {
        let i = self.body.partition_point(|&(s, _)| s <= addr);
        i > 0 && addr < self.body[i - 1].1
    }

    fn size(&self) -> u64 {
        self.body.iter().map(|&(s, e)| e - s).sum()
    }
}

/// Matching rounds: a function whose callees are not named yet is decided in a
/// later round, after the functions it calls have been matched (IDA's three
/// `AU_LIBF` queues).
pub const MAX_ROUNDS: usize = 3;

/// A function no longer than this many bytes is renamed only when at least one
/// of its callees confirms the match (IDA's tiny-module guard: a few bytes match
/// too many stubs).
pub const TINY_STUB_BYTES: u64 = 16;

/// (kuna `fidcallees`) Choose a name for each hit by checking each candidate's
/// recorded callees against the names already at the call targets: +4 for a
/// callee whose target has the recorded name, -4 for one whose target has
/// another name, 0 when the target is unnamed (IDA 9.x FLIRT arbitration,
/// `libida.so` 0x70c280). The best score wins; a tie, a negative score, or a
/// tiny stub with no confirming callee names nothing. A decision that an
/// unnamed callee could still change waits for the next round, and each
/// round's names feed the next. A name already in the binary is not given
/// again, and a name found at several addresses in one round goes only to the
/// one with the strictly best score.
pub fn arbitrate(
    hits: &[Hit<'_>],
    mut known: HashMap<u64, String>,
    target_at: impl Fn(u64) -> Option<u64>,
) -> BTreeMap<u64, String> {
    let mut named: BTreeMap<u64, String> = BTreeMap::new();
    let mut pending: Vec<&Hit<'_>> = hits.iter().filter(|h| !known.contains_key(&h.entry)).collect();
    for round in 0..MAX_ROUNDS {
        let last = round + 1 == MAX_ROUNDS;
        let mut found: Vec<(u64, String, i32)> = Vec::new();
        pending.retain(|h| match decide(h, &known, &target_at) {
            Decision::Name(n, s) => {
                found.push((h.entry, n, s));
                false
            }
            Decision::Wait => !last,
            Decision::Nothing => false,
        });
        if found.is_empty() {
            break;
        }
        let used: HashSet<&str> = known.values().map(String::as_str).collect();
        let mut scores: HashMap<&str, Vec<i32>> = HashMap::new();
        for (_, n, s) in &found {
            scores.entry(n.as_str()).or_default().push(*s);
        }
        let unique_best = |n: &str, s: i32| scores[n].iter().filter(|&&o| o >= s).count() == 1;
        let accepted: Vec<(u64, String)> = found
            .iter()
            .filter(|(_, n, s)| !used.contains(n.as_str()) && unique_best(n, *s))
            .map(|(a, n, _)| (*a, n.clone()))
            .collect();
        for (addr, name) in accepted {
            known.insert(addr, name.clone());
            named.insert(addr, name);
        }
    }
    named
}

enum Decision {
    Name(String, i32),
    Wait,
    Nothing,
}

fn decide(h: &Hit<'_>, known: &HashMap<u64, String>, target_at: &impl Fn(u64) -> Option<u64>) -> Decision {
    let mut best: BTreeMap<&str, (i32, bool)> = BTreeMap::new();
    for rec in h.recs {
        let s = score(rec, h, known, target_at);
        let e = best.entry(rec.name.as_str()).or_insert(s);
        if s.0 > e.0 {
            *e = s;
        }
    }
    let mut ranked: Vec<(&str, i32, bool)> = best.into_iter().map(|(n, (s, p))| (n, s, p)).collect();
    ranked.sort_by_key(|&(_, s, _)| std::cmp::Reverse(s));
    let unsettled = ranked.iter().any(|&(_, _, p)| p);
    let (name, top, _) = ranked[0];
    if std::env::var_os("KUNA_FID_DEBUG").is_some() && ranked.len() > 1 {
        eprintln!("[fidtrace] {:#x} {:?}", h.entry, ranked);
    }
    let tie = ranked.get(1).is_some_and(|&(_, s, _)| s == top);
    let tiny = h.size() <= TINY_STUB_BYTES;
    let ok = !tie && top >= 0 && !(tiny && top <= 0) && !(ranked.len() > 1 && top == 0 && unsettled);
    if ok {
        Decision::Name(name.to_string(), top)
    } else if unsettled {
        Decision::Wait
    } else {
        Decision::Nothing
    }
}

/// A record's callee score at `h`, and whether an unnamed callee target leaves
/// it open.
fn score(
    rec: &FidRecord,
    h: &Hit<'_>,
    known: &HashMap<u64, String>,
    target_at: &impl Fn(u64) -> Option<u64>,
) -> (i32, bool) {
    let mut total = 0;
    let mut open = false;
    for (off, want) in &rec.callees {
        let Some(t) = target_at(h.entry + u64::from(*off)) else { continue };
        if t != h.entry && h.contains(t) {
            continue;
        }
        match known.get(&t) {
            Some(have) if same_name(have, want) => total += 4,
            Some(_) => total -= 4,
            None => open = true,
        }
    }
    (total, open)
}

/// Names compared without leading underscores (`__memcpy` and `memcpy` are the
/// same libc function).
fn same_name(have: &str, want: &str) -> bool {
    have.trim_start_matches('_') == want.trim_start_matches('_')
}

/// Resolve + load the `.fid` database named by [`FID_DB_ENV`]. `None` (the inert
/// path) when the variable is unset / empty, the file is unreadable, or its bytes
/// are not a valid `.fid` — every failure is a silent no-op (FID never fails a
/// decompilation, faithful to the analysis-pass contract).
fn load_fid_db(_ctx: &AnalysisCtx) -> Option<FidDb> {
    let path = std::env::var_os(FID_DB_ENV)?;
    if path.is_empty() {
        return None;
    }
    let bytes = std::fs::read(PathBuf::from(path)).ok()?;
    FidDb::load(&bytes).ok()
}

/// §6.1 — exact full-hash match → a unique name.
///
/// Returns a name ONLY when the full-hash bucket collapses to exactly one distinct
/// name (one record, or several records that all carry the same name — e.g. the
/// same function fingerprinted under aliased symbols). Genuine multi-name buckets
/// (a real collision or two differently-named functions sharing a full hash) →
/// `None`: the v1 matcher is conservative and **never guesses on a tie**. The
/// specific hash / `code_unit_size` tiebreak is the deferred PR5 seeker's job; v1
/// stores those fields but does not score on them.
fn pick_unique_name(recs: &[FidRecord]) -> Option<String> {
    let first = recs.first()?;
    if recs.iter().all(|r| r.name == first.name) {
        Some(first.name.clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_identity() {
        let p = FidPass;
        assert_eq!(p.id(), "fid");
        assert_eq!(p.phase(), Phase::P1);
    }

    fn rec(full: u64, name: &str) -> FidRecord {
        FidRecord {
            full_hash: full,
            specific_hash: 0,
            code_unit_size: 10,
            specific_addl: 0,
            flags: 0,
            name: name.to_string(),
            callees: Vec::new(),
        }
    }

    fn calling(name: &str, callees: &[(u32, &str)]) -> FidRecord {
        let mut r = rec(0x1234, name);
        r.callees = callees.iter().map(|&(o, n)| (o, n.to_string())).collect();
        r
    }

    /// Every call site at `0x1000 + off` targets `0x2000 + off`.
    fn targets(at: u64) -> Option<u64> {
        Some(at + 0x1000)
    }

    fn names(m: &BTreeMap<u64, String>) -> Vec<(u64, &str)> {
        m.iter().map(|(&a, n)| (a, n.as_str())).collect()
    }

    #[test]
    fn a_confirmed_callee_settles_a_multi_name_bucket() {
        let recs = [calling("strcpy", &[(8, "strlen")]), calling("stpcpy", &[(8, "memcpy")])];
        let hits = [Hit { entry: 0x1000, body: vec![(0x1000, 0x1040)], recs: &recs }];
        let known = HashMap::from([(0x2008, "strlen".to_string())]);
        assert_eq!(names(&arbitrate(&hits, known, targets)), [(0x1000, "strcpy")]);
    }

    #[test]
    fn an_unsettled_tie_names_nothing() {
        let recs = [calling("strcpy", &[(8, "strlen")]), calling("stpcpy", &[(8, "memcpy")])];
        let hits = [Hit { entry: 0x1000, body: vec![(0x1000, 0x1040)], recs: &recs }];
        assert!(arbitrate(&hits, HashMap::new(), targets).is_empty());
    }

    #[test]
    fn a_contradicted_single_candidate_is_dropped() {
        let recs = [calling("strcpy", &[(8, "strlen")])];
        let hits = [Hit { entry: 0x1000, body: vec![(0x1000, 0x1040)], recs: &recs }];
        let known = HashMap::from([(0x2008, "abort".to_string())]);
        assert!(arbitrate(&hits, known, targets).is_empty());
    }

    #[test]
    fn a_tiny_stub_needs_a_confirming_callee() {
        let bare = [rec(0x1234, "tiny")];
        let hits = [Hit { entry: 0x1000, body: vec![(0x1000, 0x1010)], recs: &bare }];
        assert!(arbitrate(&hits, HashMap::new(), targets).is_empty());
        let stub = [calling("tiny", &[(4, "exit")])];
        let hits = [Hit { entry: 0x1000, body: vec![(0x1000, 0x1010)], recs: &stub }];
        let known = HashMap::from([(0x2004, "_exit".to_string())]);
        assert_eq!(names(&arbitrate(&hits, known, targets)), [(0x1000, "tiny")]);
    }

    #[test]
    fn a_later_round_uses_names_an_earlier_round_found() {
        let stub = [calling("xexit", &[(4, "exit")])];
        let exit = [rec(0x99, "exit")];
        let hits = [
            Hit { entry: 0x1000, body: vec![(0x1000, 0x1008)], recs: &stub },
            Hit { entry: 0x2004, body: vec![(0x2004, 0x2100)], recs: &exit },
        ];
        assert_eq!(names(&arbitrate(&hits, HashMap::new(), targets)), [(0x1000, "xexit"), (0x2004, "exit")]);
    }

    #[test]
    fn a_name_found_twice_goes_to_the_better_scored_address() {
        let recs = [calling("get_phys_pages", &[(8, "sysinfo")])];
        let hits = [
            Hit { entry: 0x1000, body: vec![(0x1000, 0x1040)], recs: &recs },
            Hit { entry: 0x1100, body: vec![(0x1100, 0x1140)], recs: &recs },
        ];
        let known = HashMap::from([(0x2008, "sysinfo".to_string())]);
        assert_eq!(names(&arbitrate(&hits, known, targets)), [(0x1000, "get_phys_pages")]);
        assert!(arbitrate(&hits, HashMap::new(), targets).is_empty());
    }

    #[test]
    fn a_name_already_in_the_binary_is_not_given_again() {
        let recs = [rec(0x1234, "memcpy")];
        let hits = [Hit { entry: 0x1000, body: vec![(0x1000, 0x1040)], recs: &recs }];
        let known = HashMap::from([(0x5000, "memcpy".to_string())]);
        assert!(arbitrate(&hits, known, targets).is_empty());
    }

    #[test]
    fn unique_single_record_yields_its_name() {
        let recs = [rec(0x1234, "kuna_crc32")];
        assert_eq!(pick_unique_name(&recs).as_deref(), Some("kuna_crc32"));
    }

    #[test]
    fn empty_bucket_yields_nothing() {
        assert!(pick_unique_name(&[]).is_none());
    }

    #[test]
    fn collapsing_aliases_yield_the_shared_name() {
        // Several records that all carry the same name collapse to it (the same
        // function fingerprinted under aliased symbols).
        let recs = [rec(0x1234, "kuna_crc32"), rec(0x1234, "kuna_crc32")];
        assert_eq!(pick_unique_name(&recs).as_deref(), Some("kuna_crc32"));
    }

    #[test]
    fn genuine_multi_name_bucket_is_a_tie_no_guess() {
        // Two differently-named functions sharing a full hash → never guess.
        let recs = [rec(0x1234, "foo"), rec(0x1234, "bar")];
        assert!(pick_unique_name(&recs).is_none());
    }
}
