//! (kuna `repstring`) An x86 `rep movs` or `rep stos` becomes `memcpy` or
//! `memset`.
//!
//! A compiler that inlines a copy or fill of a run-time length (gcc and clang at
//! `-Os`, MSVC's `/Oi` intrinsics, gcc's `-minline-all-stringops`) emits
//!
//! ```text
//!     mov  rcx, n          ; count, in elements
//!     rep  movsq           ; *rdi++ = *rsi++, rcx times    (memcpy)
//!     rep  stosq           ; *rdi++ = rax, rcx times       (memset)
//! ```
//!
//! and SLEIGH lifts the repeat prefix as a loop inside the one instruction, so
//! the C shows `while (n) { *p = *q; n -= 1; p = p + 1; q = q + 1; }`.
//!
//! # What is proved
//!
//! On SSA, after the main loop has settled, the pass looks for the two blocks
//! the instruction lifts to: a head `H` and a body `B` whose ops all sit at one
//! instruction address, where `H` is entered from one block outside and from
//! `B`, `B` is entered only from `H` and leaves only to `H`, and `H`'s other
//! successor `E` starts at another address. It declines unless:
//!
//! * `H` holds, besides its branch, only the phis of the count, the destination
//!   and, for a copy, the source;
//! * `H` leaves to `E` exactly when the count is zero;
//! * `B` steps the count down by one and each pointer up by the element width
//!   `w` (1, 2, 4 or 8; a set direction flag steps them down and is declined),
//!   stores one element through the destination, and computes nothing else:
//!   a copy loads the element through the source, a fill stores a value
//!   defined before the loop. A fill becomes `memset` only when every byte of
//!   the value is the same, which is always true of `stosb` and true of a
//!   constant such as `0` or `0x2020202020202020`;
//! * nothing outside the loop reads a value the body computes.
//!
//! A destination in the function's own frame (the stack pointer plus a
//! constant) is declined: the builtin is placed after heritage, so the frame
//! locations it writes would have no definition at it, and the merge could fold
//! a value stored into the buffer after the copy into one held before it. A
//! frame location heritage already guards the element store with (an INDIRECT on
//! the store and a phi in the head, for an address-taken local the destination
//! might alias) is given an INDIRECT on the builtin instead, so a read of it
//! after the loop still sees the write.
//!
//! # The rewrite
//!
//! `memcpy(dst, src, n * w)` or `memset(dst, c, n * w)` is placed in `H` before
//! its branch, where `dst`, `src` and `n` are the values entering the loop. The
//! builtin keeps the call flag `CALLOTHER` carries, so it stays ordered like a
//! call against the loads, stores and calls around it.
//! Every read after the loop of the count becomes `0`, and of a pointer, the
//! pointer plus `n * w`. The edge into `B` is then removed, so `H` runs once and
//! `B`, now unreachable, is deleted with the rest of the dead code.
//!
//! `rep movs` is defined for a destination that overlaps its source ahead of
//! it (an LZ77 decoder's match copy replicates a pattern that way), and
//! `memcpy` is not; the rewrite cannot tell the two apart, which is what the
//! option is for.

use kuna_base::error::{KunaError, KunaResult};
use kuna_base::types::uintb;
use kuna_num::opcodes::OpCode::*;

use crate::action::{Action, ActionBase, ActionContext, ActionGroupList, ApplyResult};
use crate::context::{BlockId, OpId, VarnodeId};
use crate::funcdata::Funcdata;
use crate::op::PcodeOp;
use crate::userop::{BUILTIN_MEMCPY, BUILTIN_MEMSET};

/// (kuna) `ActionRepString` — collapse an x86 `rep movs`/`rep stos` loop into
/// `memcpy`/`memset` (option `repstring`).
pub struct ActionRepString {
    base: ActionBase,
}

impl ActionRepString {
    pub fn new(g: impl Into<String>) -> Self {
        Self { base: ActionBase::new(0, "repstring", g) }
    }
}

impl Action for ActionRepString {
    fn base(&self) -> &ActionBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut ActionBase {
        &mut self.base
    }
    fn clone_filtered(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        grouplist.contains(self.get_group()).then(|| Box::new(Self { base: self.base.clone() }) as Box<dyn Action>)
    }
    fn apply(&mut self, data: &mut Funcdata, _ctx: &mut ActionContext) -> ApplyResult {
        if !data.get_arch().rep_string {
            return 0;
        }
        let heads: Vec<BlockId> = (0..data.bblocks_get_size()).map(|i| data.bblocks_get_block(i)).collect();
        let mut changed = 0;
        for head in heads {
            let Some(rep) = match_rep(data, head) else { continue };
            if rewrite(data, &rep).is_err() {
                break;
            }
            changed += 1;
        }
        self.base.count += changed;
        (changed != 0) as ApplyResult
    }
}

/// What the element store writes: a copied element (the source pointer's phi
/// output and its entering value), or a fill byte, constant or not.
enum Element {
    Copy { src_out: VarnodeId, src_in: VarnodeId },
    FillConst(u64),
    FillByte(VarnodeId),
}

/// One matched repeat loop: the head, the edge into the body, the values
/// entering the loop and the element width.
struct Rep {
    head: BlockId,
    body: BlockId,
    to_body: i32,
    width: i32,
    count_out: VarnodeId,
    count_in: VarnodeId,
    dst_out: VarnodeId,
    dst_in: VarnodeId,
    element: Element,
    /// The head phis of the frame locations the element store may write, which
    /// heritage carries through the body with an INDIRECT on the store.
    memory: Vec<VarnodeId>,
}

fn op(data: &Funcdata, id: OpId) -> Option<&PcodeOp> {
    data.obank().get(id)
}

fn size(data: &Funcdata, v: VarnodeId) -> Option<i32> {
    data.vbank().get(v).map(|n| n.get_size())
}

fn constant(data: &Funcdata, v: VarnodeId) -> Option<u64> {
    let n = data.vbank().get(v)?;
    n.is_constant().then(|| n.get_offset())
}

fn mask(width: i32) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * width)) - 1
    }
}

fn def_block(data: &Funcdata, v: VarnodeId) -> Option<BlockId> {
    op(data, data.vbank().get(v)?.get_def()?)?.get_parent()
}

/// `v` through the COPYs that define it.
fn copied(data: &Funcdata, mut v: VarnodeId) -> VarnodeId {
    for _ in 0..4 {
        let Some(d) = data.vbank().get(v).and_then(|n| n.get_def()).and_then(|d| op(data, d)) else { break };
        if d.code() != CPUI_COPY {
            break;
        }
        let Some(input) = d.get_in(0) else { break };
        v = input;
    }
    v
}

/// The constant `inc` adds to `v` (INT_ADD either way round, INT_SUB, or a
/// PTRADD of a constant index), or `None`.
fn step(data: &Funcdata, inc: &PcodeOp, v: VarnodeId) -> Option<u64> {
    let width = size(data, v)?;
    let (a, b) = (inc.get_in(0)?, inc.get_in(1)?);
    let k = match inc.code() {
        CPUI_INT_ADD if a == v => constant(data, b)?,
        CPUI_INT_ADD if b == v => constant(data, a)?,
        CPUI_INT_SUB if a == v => constant(data, b)?.wrapping_neg(),
        CPUI_PTRADD if a == v => constant(data, b)?.wrapping_mul(constant(data, inc.get_in(2)?)?),
        _ => return None,
    };
    Some(k & mask(width))
}

/// The successor the CBRANCH ending `b` takes when its condition is true, and
/// the other one.
fn taken(data: &Funcdata, b: BlockId) -> Option<(BlockId, BlockId)> {
    let fb = data.bblocks_ref().block(b);
    let tail = op(data, data.bb_op_tail(b)?)?;
    if fb.size_out() != 2 || tail.code() != CPUI_CBRANCH {
        return None;
    }
    let (t, f) = (fb.get_true_out(), fb.get_false_out());
    Some(if tail.is_boolean_flip() { (f, t) } else { (t, f) })
}

/// The counter `cond` compares with zero, and whether `cond` holds when it is
/// zero (`n == 0`) or when it is not (`n != 0`).
fn zero_test(data: &Funcdata, cond: VarnodeId) -> Option<(VarnodeId, bool)> {
    let c = op(data, data.vbank().get(cond)?.get_def()?)?;
    let (a, b) = (c.get_in(0)?, c.get_in(1)?);
    let n = match (constant(data, a), constant(data, b)) {
        (None, Some(0)) => a,
        (Some(0), None) => b,
        _ => return None,
    };
    match c.code() {
        CPUI_INT_EQUAL => Some((n, true)),
        CPUI_INT_NOTEQUAL => Some((n, false)),
        _ => None,
    }
}

fn match_rep(data: &Funcdata, head: BlockId) -> Option<Rep> {
    let hb = data.bblocks_ref().block(head);
    if hb.size_in() != 2 || hb.size_out() != 2 {
        return None;
    }
    let cond = op(data, data.bb_op_tail(head)?)?.get_in(1)?;
    let (counter, when_zero) = zero_test(data, cond)?;
    let (on_true, on_false) = taken(data, head)?;
    let (exit, body) = if when_zero { (on_true, on_false) } else { (on_false, on_true) };
    let bb = data.bblocks_ref().block(body);
    if body == head || body == exit || bb.size_in() != 1 || bb.size_out() != 1 || bb.get_out(0) != head {
        return None;
    }
    let back = hb.get_in_index(body);
    let to_body = hb.get_out_index(body);
    if back < 0 || to_body < 0 {
        return None;
    }
    let (head_ops, body_ops) = (data.bb_ops(head), data.bb_ops(body));
    let at = op(data, *head_ops.first()?)?.get_addr().clone();
    if !head_ops.iter().chain(body_ops.iter()).all(|&o| op(data, o).is_some_and(|p| *p.get_addr() == at)) {
        return None;
    }
    if data.bb_ops(exit).first().and_then(|&o| op(data, o)).is_none_or(|p| *p.get_addr() == at) {
        return None;
    }
    // The head: phis (out, entering value, value from the body), then the branch.
    let mut phis: Vec<(VarnodeId, VarnodeId, VarnodeId)> = Vec::new();
    for &o in &head_ops {
        let p = op(data, o)?;
        match p.code() {
            CPUI_MULTIEQUAL => phis.push((p.get_out()?, p.get_in(1 - back)?, p.get_in(back)?)),
            CPUI_CBRANCH => {}
            _ if p.get_out() == Some(cond) => {}
            _ => return None,
        }
    }
    let defined_in = |v: VarnodeId, b: BlockId| def_block(data, v) == Some(b);
    // The body's steps, by the phi they step.
    let mut count = None;
    let mut ptrs: Vec<(VarnodeId, VarnodeId, u64)> = Vec::new();
    let mut memory: Vec<VarnodeId> = Vec::new();
    let mut indirects: Vec<OpId> = Vec::new();
    for &(out, enter, next) in &phis {
        if defined_in(enter, head) || defined_in(enter, body) || !defined_in(next, body) {
            return None;
        }
        let def = data.vbank().get(copied(data, next))?.get_def()?;
        let inc = op(data, def)?;
        if inc.code() == CPUI_INDIRECT && inc.get_in(0) == Some(out) {
            memory.push(out);
            indirects.push(def);
            continue;
        }
        let k = step(data, inc, out)?;
        if out == counter && k == mask(size(data, out)?) {
            count = Some((out, enter));
        } else {
            ptrs.push((out, enter, k));
        }
    }
    let (count_out, count_in) = count?;
    // The element store, and for a copy the element load.
    let (mut store, mut load) = (None, None);
    for &o in &body_ops {
        let p = op(data, o)?;
        match p.code() {
            CPUI_STORE if store.is_none() => store = Some(o),
            CPUI_LOAD if load.is_none() => load = Some(o),
            CPUI_COPY | CPUI_INT_ADD | CPUI_INT_SUB | CPUI_PTRADD | CPUI_BRANCH => {}
            CPUI_INDIRECT if indirects.contains(&o) => {}
            _ => return None,
        }
    }
    let store = store?;
    let on_store = |o: OpId| {
        op(data, o)
            .and_then(|p| p.get_in(1))
            .and_then(|v| data.vbank().get(v))
            .is_some_and(|v| crate::funcdata_varnode::op_iop_decode(v.get_offset()) == store)
    };
    if !indirects.iter().all(|&o| on_store(o)) {
        return None;
    }
    let st = op(data, store)?;
    let st_ptr = copied(data, st.get_in(1)?);
    let stored = st.get_in(2)?;
    let width = size(data, stored)?;
    let dst = ptrs.iter().find(|(out, _, _)| *out == st_ptr)?;
    if in_frame(data, dst.1) {
        return None;
    }
    if dst.2 != width as u64 {
        return None;
    }
    let element = match load {
        Some(l) => {
            let ld = op(data, l)?;
            if ptrs.len() != 2 || copied(data, stored) != ld.get_out()? {
                return None;
            }
            let ld_ptr = copied(data, ld.get_in(1)?);
            let src = ptrs.iter().find(|(out, _, _)| *out == ld_ptr)?;
            if src.2 != width as u64 || src.0 == dst.0 {
                return None;
            }
            Element::Copy { src_out: src.0, src_in: src.1 }
        }
        None => {
            if ptrs.len() != 1 || def_block(data, stored).is_some_and(|b| b == head || b == body) {
                return None;
            }
            match constant(data, stored) {
                Some(k) if (0..width).all(|i| (k >> (8 * i)) & 0xff == k & 0xff) => Element::FillConst(k & 0xff),
                Some(_) => return None,
                None if width == 1 => Element::FillByte(stored),
                None => return None,
            }
        }
    };
    // Nothing outside the loop reads what the body computes.
    for &o in &body_ops {
        let Some(out) = op(data, o)?.get_out() else { continue };
        for u in data.vbank().get(out)?.descend_iter() {
            if !op(data, u)?.get_parent().is_some_and(|b| b == head || b == body) {
                return None;
            }
        }
    }
    Some(Rep { head, body, to_body, width, count_out, count_in, dst_out: dst.0, dst_in: dst.1, element, memory })
}

/// Is `v` an address in the function's own frame: the stack pointer plus a
/// constant, through copies?
fn in_frame(data: &Funcdata, mut v: VarnodeId) -> bool {
    for _ in 0..8 {
        let Some(n) = data.vbank().get(v) else { return false };
        if n.is_spacebase() {
            return true;
        }
        let Some(d) = n.get_def().and_then(|d| op(data, d)) else { return false };
        let next = match d.code() {
            CPUI_COPY | CPUI_CAST => d.get_in(0),
            CPUI_INT_ADD | CPUI_PTRSUB | CPUI_PTRADD | CPUI_INT_SUB => d.get_in(0),
            _ => None,
        };
        match next {
            Some(n) => v = n,
            None => return false,
        }
    }
    false
}

/// A new op of `code` over `inputs`, placed before `before`, with a fresh
/// output of `size` bytes when `size` is positive.
fn insert(
    data: &mut Funcdata,
    code: kuna_num::opcodes::OpCode,
    inputs: &[VarnodeId],
    size: i32,
    before: OpId,
) -> KunaResult<(OpId, Option<VarnodeId>)> {
    let at = op(data, before).map(|p| p.get_addr().clone()).ok_or_else(|| KunaError::lowlevel("repstring: stale op"))?;
    let new = data.new_op(inputs.len() as i32, at);
    data.op_set_opcode_code(new, code);
    for (slot, &v) in inputs.iter().enumerate() {
        data.op_set_input(new, v, slot as i32)?;
    }
    let out = if size > 0 { Some(data.new_unique_out(size, new)?) } else { None };
    data.op_insert_before(new, before);
    Ok((new, out))
}

/// Point every read of `from` outside the loop at `to`, or at a new zero of
/// `from`'s width when `to` is `None`.
fn redirect(data: &mut Funcdata, from: VarnodeId, to: Option<VarnodeId>, rep: &Rep) -> KunaResult<()> {
    let width = size(data, from).unwrap_or(8);
    let readers: Vec<OpId> = data.vbank().get(from).map(|v| v.descend_iter().collect()).unwrap_or_default();
    for reader in readers {
        let Some(p) = op(data, reader) else { continue };
        if p.get_parent().is_some_and(|b| b == rep.head || b == rep.body) {
            continue;
        }
        let slots: Vec<i32> = (0..p.num_input()).filter(|&i| p.get_in(i) == Some(from)).collect();
        for slot in slots {
            let value = match to {
                Some(v) => v,
                None => data.new_constant(width, 0),
            };
            data.op_set_input(reader, value, slot)?;
        }
    }
    Ok(())
}

fn rewrite(data: &mut Funcdata, rep: &Rep) -> KunaResult<()> {
    let tail = data.bb_op_tail(rep.head).ok_or_else(|| KunaError::lowlevel("repstring: empty head"))?;
    let ptr_size = size(data, rep.dst_out).unwrap_or(8);
    let count_size = size(data, rep.count_in).unwrap_or(ptr_size);
    let bytes = if rep.width == 1 {
        rep.count_in
    } else {
        let w = data.new_constant(count_size, rep.width as uintb);
        insert(data, CPUI_INT_MULT, &[rep.count_in, w], count_size, tail)?
            .1
            .ok_or_else(|| KunaError::lowlevel("repstring: no size"))?
    };
    let (id, second, src) = match rep.element {
        Element::Copy { src_out, src_in } => (BUILTIN_MEMCPY, src_in, Some(src_out)),
        Element::FillConst(byte) => (BUILTIN_MEMSET, data.new_constant(4, byte as uintb), None),
        Element::FillByte(byte) => (BUILTIN_MEMSET, byte, None),
    };
    let id = data.new_constant(4, id as uintb);
    let (call, _) = insert(data, CPUI_CALLOTHER, &[id, rep.dst_in, second, bytes], 0, tail)?;
    for &location in &rep.memory {
        let (addr, width) = match data.vbank().get(location) {
            Some(v) => (v.get_addr().clone(), v.get_size()),
            None => continue,
        };
        let at = op(data, call).map(|p| p.get_addr().clone()).ok_or_else(|| KunaError::lowlevel("repstring: stale call"))?;
        let ind = data.new_op(2, at);
        data.op_set_opcode_code(ind, CPUI_INDIRECT);
        data.op_set_input(ind, location, 0)?;
        let iop = data.new_varnode_iop(call);
        data.op_set_input(ind, iop, 1)?;
        let after = data.new_varnode_out(width, &addr, ind)?;
        data.op_insert_before(ind, call);
        redirect(data, location, Some(after), rep)?;
    }
    let (_, dst_end) = insert(data, CPUI_INT_ADD, &[rep.dst_out, bytes], ptr_size, tail)?;
    redirect(data, rep.dst_out, dst_end, rep)?;
    if let Some(src_out) = src {
        let (_, src_end) = insert(data, CPUI_INT_ADD, &[src_out, bytes], ptr_size, tail)?;
        redirect(data, src_out, src_end, rep)?;
    }
    redirect(data, rep.count_out, None, rep)?;
    data.remove_branch(rep.head, rep.to_body)
}
