//! (kuna `fidcallees`) FID callee checks on a stripped binary.
//!
//! Fixture `tests/fixtures/fid/callees` (recipe in its README): `wrap_a` and
//! `wrap_b` compile to the same instructions and call `scale_a` / `scale_b`, so
//! their full hashes share one bucket with two names; `bump` is an 11-byte stub
//! with no callee. `lib.fid` was built by `kuna fid build` over `lib.o`, so it
//! records each wrapper's callee.
//!
//! - `fidcallees off`: the two wrappers stay `sub_` (a two-name bucket is a tie)
//!   and `bump` is renamed from its few bytes alone.
//! - `fidcallees on` (default): the first round names `scale_a` / `scale_b`, the
//!   second settles each wrapper by the name at its call target, and `bump` is
//!   withheld because no callee confirms it.

use std::path::PathBuf;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};

const WRAP_A: u64 = 0x401040;
const WRAP_B: u64 = 0x401060;
const BUMP: u64 = 0x401080;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/fid/callees")
        .canonicalize()
        .unwrap()
}

fn name_at(prog: &ConsoleProgram, vma: u64) -> String {
    let space = prog.arch().manage().get_default_code_space().unwrap().clone();
    let addr = Address::new(Rc::clone(&space), vma);
    match prog.arch().symboltab.find_function_across_scopes(&addr) {
        Some((sid, _)) => prog.arch().symboltab.symbol(sid).get_name().to_string(),
        None => prog.arch().name_function(&addr),
    }
}

fn names(fidcallees: &str) -> [String; 3] {
    let dir = fixture_dir();
    let specs = dir.join("../../../../specs");
    let spec_roots = vec![specs.canonicalize().unwrap().to_str().unwrap().to_string()];
    std::env::set_var("kuna_fid_db", dir.join("lib.fid"));
    let bin = dir.join("prog");
    let mut prog = bootstrap_from_object(bin.to_str().unwrap(), "", &spec_roots)
        .expect("bootstrap fixture with built processor specs");
    for (k, v) in [("listing", "on"), ("fid", "on"), ("fidcallees", fidcallees)] {
        prog.arch_mut().set_kuna_option(k, v).expect("option flips");
    }
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    [WRAP_A, WRAP_B, BUMP].map(|a| name_at(&prog, a))
}

#[test]
fn callee_names_settle_a_shared_hash_and_withhold_a_bare_stub() {
    let [a, b, bump] = names("off");
    assert!(a.starts_with("sub_") && b.starts_with("sub_"), "off: wrappers tie, got {a} {b}");
    assert_eq!(bump, "bump", "off: the stub is renamed from its bytes alone");

    let [a, b, bump] = names("on");
    assert_eq!((a.as_str(), b.as_str()), ("wrap_a", "wrap_b"), "on: callees settle the wrappers");
    assert!(bump.starts_with("sub_"), "on: a stub with no confirming callee keeps its placeholder, got {bump}");
}
