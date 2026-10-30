//! (kuna) `x87depth` — the x87 register-stack depth at each return.
//!
//! SLEIGH models ST0..ST7 as eight fixed registers and every push or pop as a
//! copy shift, so the p-code has no stack top. A function that calls a
//! float-returning helper and discards the result (`call noisy; fstp st(0)`)
//! therefore reaches its `ret` with ST0 holding whatever the shifts moved in,
//! and return recovery reads that as a `long double` result built from an
//! undefined value.
//!
//! This pass recovers the depth the way IDA's x87 solver does, without an LP.
//! Before SSA, each block's raw ops are scanned in order: the `ST7 = ST6` copy
//! that opens every push adds one, the `ST6 = ST7` copy that closes every pop
//! removes one, a pop or any other read of `ST(i)` requires a depth above `i`
//! (the shift copies themselves and the `tmp = ST7` of the `fdec` rotation that
//! `fld m64` uses are not reads).
//! The i386 System V convention fixes the rest: the stack is empty at entry and
//! at every call, and a call leaves 0 or 1 values (`δ_c`) on it. The depth
//! after a call is `δ_c` plus the pushes and pops since; reads bound `δ_c` from
//! below, the next call and every join pin it, and joins of two calls' results
//! relate their `δ`s (a union-find with offsets over the per-call unknowns).
//!
//! A return whose depth comes out exactly 0 is recorded with the returns
//! `x87emptyreturn` proves empty, so the ST0 return trial is retired when every
//! return agrees. Any partial (MMX) access to the register bank, a write to
//! the tag word, a depth below zero, or a conflict at a join ends the analysis
//! with no answer, and a return whose depth depends on a call nothing
//! constrains is left alone.

use crate::funcdata::Funcdata;
use kuna_base::address::Address;
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;

use super::kuna_x87emptyreturn::Storage;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Depth {
    Known(i32),
    AfterCall(usize, i32),
}

/// The per-call unknowns `δ_c`, each in `[0, 1]`, related by equalities.
struct Calls {
    parent: Vec<usize>,
    offset: Vec<i32>,
    lo: Vec<i32>,
    hi: Vec<i32>,
}

impl Calls {
    fn new() -> Self {
        Calls { parent: Vec::new(), offset: Vec::new(), lo: Vec::new(), hi: Vec::new() }
    }

    fn add(&mut self) -> usize {
        let v = self.parent.len();
        self.parent.push(v);
        self.offset.push(0);
        self.lo.push(0);
        self.hi.push(1);
        v
    }

    /// The class root of `v` and the offset with `δ_v = δ_root + offset`.
    fn find(&self, mut v: usize) -> (usize, i32) {
        let mut off = 0;
        while self.parent[v] != v {
            off += self.offset[v];
            v = self.parent[v];
        }
        (v, off)
    }

    fn at_least(&mut self, v: usize, m: i32) -> Option<()> {
        let (r, off) = self.find(v);
        self.lo[r] = self.lo[r].max(m - off);
        (self.lo[r] <= self.hi[r]).then_some(())
    }

    fn equal(&mut self, v: usize, m: i32) -> Option<()> {
        let (r, off) = self.find(v);
        self.lo[r] = self.lo[r].max(m - off);
        self.hi[r] = self.hi[r].min(m - off);
        (self.lo[r] <= self.hi[r]).then_some(())
    }

    /// Record `δ_a + ka == δ_b + kb`.
    fn link(&mut self, a: usize, ka: i32, b: usize, kb: i32) -> Option<()> {
        let (ra, oa) = self.find(a);
        let (rb, ob) = self.find(b);
        let w = kb + ob - ka - oa;
        if ra == rb {
            return (w == 0).then_some(());
        }
        self.parent[ra] = rb;
        self.offset[ra] = w;
        self.lo[rb] = self.lo[rb].max(self.lo[ra] + w);
        self.hi[rb] = self.hi[rb].min(self.hi[ra] + w);
        (self.lo[rb] <= self.hi[rb]).then_some(())
    }

    fn value(&self, v: usize) -> Option<i32> {
        let (r, off) = self.find(v);
        (self.lo[r] == self.hi[r]).then_some(self.lo[r] + off)
    }

    fn need(&mut self, d: Depth, m: i32) -> Option<()> {
        match d {
            Depth::Known(k) => (k >= m).then_some(()),
            Depth::AfterCall(c, k) => self.at_least(c, m - k),
        }
    }

    fn pin(&mut self, d: Depth, m: i32) -> Option<()> {
        match d {
            Depth::Known(k) => (k == m).then_some(()),
            Depth::AfterCall(c, k) => self.equal(c, m - k),
        }
    }

    fn join(&mut self, a: Depth, b: Depth) -> Option<()> {
        match (a, b) {
            (Depth::Known(x), Depth::Known(y)) => (x == y).then_some(()),
            (Depth::Known(x), d) | (d, Depth::Known(x)) => self.pin(d, x),
            (Depth::AfterCall(ca, ka), Depth::AfterCall(cb, kb)) => self.link(ca, ka, cb, kb),
        }
    }
}

fn shift(d: Depth, by: i32) -> Depth {
    match d {
        Depth::Known(k) => Depth::Known(k + by),
        Depth::AfterCall(c, k) => Depth::AfterCall(c, k + by),
    }
}

/// A register reference as `(space index, offset, size)`.
type Reg = (kuna_base::types::int4, u64, u64);

fn reg_of_varnode(data: &Funcdata, id: crate::context::VarnodeId) -> Option<Reg> {
    let v = data.vbank().get(id)?;
    Some((v.get_addr().get_space()?.get_index(), v.get_offset(), v.get_size() as u64))
}

fn reg_of_data(v: &VarnodeData) -> Option<Reg> {
    Some((v.space.as_ref()?.get_index(), v.offset, u64::from(v.size)))
}

fn overlaps(r: Reg, reg: &VarnodeData) -> bool {
    reg.space.as_ref().is_some_and(|s| s.get_index() == r.0)
        && r.1 < reg.offset + u64::from(reg.size)
        && reg.offset < r.1 + r.2
}

/// Which bank register `r` is exactly, or `Err` on a partial (MMX) access.
fn bank_index(r: Option<Reg>, storage: &Storage) -> Result<Option<usize>, ()> {
    let Some(r) = r else { return Ok(None) };
    for (i, reg) in storage.bank.iter().enumerate() {
        if overlaps(r, reg) {
            return if r.1 == reg.offset && r.2 == u64::from(reg.size) { Ok(Some(i)) } else { Err(()) };
        }
    }
    Ok(None)
}

/// What one p-code op does to the depth.
enum Step {
    Call,
    Return,
    Push,
    Pop,
    Reads(Vec<usize>),
}

fn classify(
    code: OpCode,
    out: Option<Reg>,
    ins: &[Option<Reg>],
    free_userop: bool,
    storage: &Storage,
) -> Option<Step> {
    match code {
        OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => return Some(Step::Call),
        OpCode::CPUI_RETURN => return Some(Step::Return),
        _ => {}
    }
    if out.is_some_and(|o| overlaps(o, &storage.tags)) {
        return None;
    }
    let o = bank_index(out, storage).ok()?;
    let i0 = bank_index(ins.first().copied().flatten(), storage).ok()?;
    if code == OpCode::CPUI_COPY {
        match (o, i0) {
            (Some(7), Some(6)) => return Some(Step::Push),
            (Some(6), Some(7)) => return Some(Step::Pop),
            (Some(a), Some(b)) if a.abs_diff(b) == 1 => return Some(Step::Reads(Vec::new())),
            (_, Some(7)) => return Some(Step::Reads(Vec::new())),
            _ => {}
        }
    }
    if free_userop {
        return Some(Step::Reads(Vec::new()));
    }
    let mut reads = Vec::new();
    for r in ins {
        if let Some(i) = bank_index(*r, storage).ok()? {
            reads.push(i);
        }
    }
    Some(Step::Reads(reads))
}

/// Apply one op; `None` ends the analysis.
fn apply(step: Step, d: Depth, calls: &mut Calls) -> Option<Depth> {
    Some(match step {
        Step::Call => {
            calls.pin(d, 0)?;
            Depth::AfterCall(calls.add(), 0)
        }
        Step::Return => d,
        Step::Push => shift(d, 1),
        Step::Pop => {
            calls.need(d, 1)?;
            shift(d, -1)
        }
        Step::Reads(regs) => {
            for i in regs {
                calls.need(d, i as i32 + 1)?;
            }
            d
        }
    })
}

/// Walk one block from `start`, returning its exit depth.
fn walk_block(
    data: &Funcdata,
    block: crate::context::BlockId,
    start: Depth,
    storage: &Storage,
    calls: &mut Calls,
    returns: &mut Vec<(Address, Depth)>,
) -> Option<Depth> {
    let mut d = start;
    for id in data.bb_ops(block) {
        let op = data.obank().get(id)?;
        let out = op.get_out().and_then(|o| reg_of_varnode(data, o));
        let ins: Vec<_> = (0..op.num_input()).map(|i| op.get_in(i).and_then(|v| reg_of_varnode(data, v))).collect();
        let free = op.code() == OpCode::CPUI_CALLOTHER
            && op.get_in(0).and_then(|v| data.vbank().get(v)).is_some_and(|v| v.is_constant() && v.get_offset() == storage.free);
        let step = classify(op.code(), out, &ins, free, storage)?;
        if matches!(step, Step::Return) && op.get_halt_type() == 0 {
            returns.push((op.get_addr().clone(), d));
        }
        d = apply(step, d, calls)?;
    }
    Some(d)
}

#[derive(Default)]
struct OpsEmit {
    ops: Vec<(OpCode, Option<VarnodeData>, Vec<VarnodeData>)>,
}

impl kuna_sleigh::translate::PcodeEmit for OpsEmit {
    fn dump(&mut self, _addr: &Address, opc: OpCode, outvar: Option<&VarnodeData>, vars: &[VarnodeData]) {
        self.ops.push((opc, outvar.cloned(), vars.to_vec()));
    }
}

const MAX_SITE_INSTRUCTIONS: usize = 256;

/// How many values a call left on the x87 stack, read from the caller's code
/// at the call's return address `back`: 0 or 1 when the instructions up to the
/// next call pin it, `None` when they do not.
pub fn call_leaves<T: kuna_sleigh::translate::Translate + ?Sized>(
    tr: &T,
    back: &Address,
    storage: &Storage,
    free_userop: u64,
) -> Option<i32> {
    let mut calls = Calls::new();
    let delta = calls.add();
    let mut seen = std::collections::HashMap::new();
    let mut todo = vec![(back.clone(), Depth::AfterCall(delta, 0))];
    let mut budget = MAX_SITE_INSTRUCTIONS;
    while let Some((at, mut d)) = todo.pop() {
        let key = (at.get_space()?.get_index(), at.get_offset());
        if let Some(&prev) = seen.get(&key) {
            calls.join(prev, d)?;
            continue;
        }
        seen.insert(key, d);
        budget = budget.checked_sub(1)?;
        let mut emit = OpsEmit::default();
        let len = tr.one_instruction(&mut emit, &at).ok().filter(|&n| n > 0)?;
        let mut ends = false;
        for (code, out, ins) in emit.ops {
            let ins_regs: Vec<_> = ins.iter().map(reg_of_data).collect();
            let free = code == OpCode::CPUI_CALLOTHER
                && ins.first().is_some_and(|v| v.space.as_ref().is_some_and(|s| s.get_type() == kuna_base::space::spacetype::IPTR_CONSTANT) && v.offset == free_userop);
            let step = classify(code, out.as_ref().and_then(reg_of_data), &ins_regs, free, storage)?;
            match step {
                Step::Call => {
                    calls.pin(d, 0)?;
                    ends = true;
                    break;
                }
                Step::Return => {
                    ends = true;
                    break;
                }
                _ => d = apply(step, d, &mut calls)?,
            }
            match code {
                OpCode::CPUI_BRANCHIND => return calls.value(delta),
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if let Some(sp) = ins.first().and_then(|v| v.space.as_ref()) {
                        if sp.get_type() != kuna_base::space::spacetype::IPTR_CONSTANT {
                            todo.push((Address::new(std::rc::Rc::clone(sp), ins[0].offset), d));
                            if code == OpCode::CPUI_BRANCH {
                                ends = true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if !ends {
            todo.push((&at + len as i64, d));
        }
    }
    calls.value(delta)
}

/// The returns whose x87 depth is proven to be 0, or nothing when the function
/// is not analyzable under the System V assumptions.
pub fn empty_returns(data: &Funcdata, storage: &Storage) -> Vec<Address> {
    solve(data, storage).unwrap_or_default()
}

fn solve(data: &Funcdata, storage: &Storage) -> Option<Vec<Address>> {
    let n = data.bblocks_get_size() as usize;
    if n == 0 {
        return None;
    }
    let blocks: Vec<_> = (0..n).map(|i| data.bblocks_get_block(i as kuna_base::types::int4)).collect();
    let index: std::collections::HashMap<_, _> = blocks.iter().enumerate().map(|(i, &b)| (b, i)).collect();
    let mut calls = Calls::new();
    let mut returns = Vec::new();
    let mut entry: Vec<Option<Depth>> = vec![None; n];
    entry[0] = Some(Depth::Known(0));
    let mut pending = vec![0usize];
    while let Some(i) = pending.pop() {
        let exit = walk_block(data, blocks[i], entry[i]?, storage, &mut calls, &mut returns)?;
        let b = data.bblocks_ref().block(blocks[i]);
        for s in 0..b.size_out() {
            let j = *index.get(&b.get_out(s))?;
            match entry[j] {
                None => {
                    entry[j] = Some(exit);
                    pending.push(j);
                }
                Some(prev) => calls.join(prev, exit)?,
            }
        }
    }
    let mut out = Vec::new();
    for (addr, d) in returns {
        let depth = match d {
            Depth::Known(k) => k,
            Depth::AfterCall(c, k) => match calls.value(c) {
                Some(v) => v + k,
                None => continue,
            },
        };
        if depth == 0 {
            out.push(addr);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_discarded_call_result_pins_the_call() {
        let mut c = Calls::new();
        let v = c.add();
        c.need(Depth::AfterCall(v, 0), 1).unwrap();
        assert_eq!(c.value(v), Some(1));
        let w = c.add();
        c.need(Depth::AfterCall(w, 0), 0).unwrap();
        assert_eq!(c.value(w), None);
        c.join(Depth::AfterCall(w, 0), Depth::AfterCall(v, 0)).unwrap();
        assert_eq!(c.value(w), Some(1));
        assert!(c.pin(Depth::AfterCall(w, 0), 0).is_none());
    }
}
